"""Authentication and authorisation.

* Passwords: Argon2id (``argon2-cffi`` defaults, RFC 9106 low-memory profile).
  Hashes are upgraded transparently at login when parameters change.
* Access tokens: HS256 JWTs, short-lived, carrying user id, role and a ``jti``.
* Refresh tokens: JWTs whose ``jti`` is stored server-side, so they can be revoked.
  Each use rotates the token; presenting an already-rotated token is treated as
  theft and revokes every refresh token for that user.
* Lockout: an account locks for ``lockout_seconds`` after ``lockout_threshold``
  consecutive failures, independent of per-IP throttling done at the API edge.
* WebSocket tickets: single-use, 30-second, random tokens, so a long-lived access
  token never appears in a URL (where proxies and browser history record it).

Every authentication failure returns the same message whether the username exists
or not, and verification runs against a dummy hash for unknown users so response
time does not reveal which usernames are valid.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from sentinelx.common.enums import UserRole
from sentinelx.common.errors import SentinelXError
from sentinelx.config.settings import ApiSettings
from sentinelx.storage.database import Database
from sentinelx.storage.models import User
from sentinelx.storage.redis_state import SharedState
from sentinelx.storage.repositories import UserRepository
from sentinelx.telemetry.logging import get_logger

__all__ = [
    "AuthError",
    "AuthService",
    "Principal",
    "TokenPair",
    "validate_password",
]

log = get_logger(__name__)

_hasher = PasswordHasher()
#: Verified against when the username does not exist, so timing is uniform.
_DUMMY_HASH = _hasher.hash("sentinelx-timing-equaliser")

_COMMON_PASSWORDS = frozenset(
    {"password", "password123", "123456789012", "qwertyuiopas", "administrator", "sentinelx", "letmein12345",
     "changeme1234", "adminadmin12", "welcome12345", "passw0rd1234"}
)
_GENERIC_FAILURE = "invalid username or password"


class AuthError(SentinelXError):
    """Authentication or authorisation failed. ``status`` maps onto HTTP."""

    def __init__(self, message: str, status: int = 401, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller."""

    user_id: int
    username: str
    role: UserRole
    token_id: str = ""
    must_change_password: bool = False

    def can(self, required: UserRole) -> bool:
        return self.role.can_act_as(required)


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime
    principal: Principal


def validate_password(password: str, *, username: str, min_length: int) -> list[str]:
    """Return every reason a password is unacceptable (empty when acceptable).

    Length over composition rules, per NIST SP 800-63B: a long passphrase is
    stronger than a short string with a mandated symbol.
    """
    problems = []
    if len(password) < min_length:
        problems.append(f"must be at least {min_length} characters")
    if len(password) > 256:
        problems.append("must be at most 256 characters")
    if password.lower() == username.lower() or username.lower() in password.lower():
        problems.append("must not contain the username")
    if password.lower() in _COMMON_PASSWORDS:
        problems.append("is too common")
    if len(set(password)) < 5:
        problems.append("must use more than a handful of distinct characters")
    return problems


class AuthService:
    def __init__(self, settings: ApiSettings, database: Database, state: SharedState) -> None:
        if len(settings.jwt_secret) < 32:
            raise SentinelXError("JWT secret must be at least 32 characters")
        self.settings = settings
        self.database = database
        self.state = state

    # --------------------------------------------------------------- passwords

    @staticmethod
    def hash_password(password: str) -> str:
        return _hasher.hash(password)

    def check_password_policy(self, password: str, username: str) -> None:
        problems = validate_password(password, username=username, min_length=self.settings.password_min_length)
        if problems:
            raise AuthError("password " + "; ".join(problems), status=422)

    # ------------------------------------------------------------------ users

    async def ensure_bootstrap_admin(self) -> str | None:
        """Create the first administrator when no users exist.

        Returns:
            The generated password when one had to be generated, so the caller can
            show it to the operator exactly once. It is never logged.
        """
        async with self.database.session() as session:
            users = UserRepository(session)
            if await users.count() > 0:
                return None
            generated: str | None = None
            password = self.settings.bootstrap_admin_password
            if not password:
                generated = password = secrets.token_urlsafe(18)
            else:
                self.check_password_policy(password, self.settings.bootstrap_admin_username)
            await users.add(
                User(
                    username=self.settings.bootstrap_admin_username,
                    password_hash=self.hash_password(password),
                    role=UserRole.ADMIN.value,
                    # A generated password was shown on a terminal; make the first
                    # login replace it.
                    must_change_password=generated is not None,
                )
            )
        log.warning("bootstrap_admin_created", username=self.settings.bootstrap_admin_username, generated_password=generated is not None)
        return generated

    async def create_user(self, username: str, password: str, role: UserRole) -> User:
        username = username.strip()
        if not 3 <= len(username) <= 64 or not all(ch.isalnum() or ch in "._-" for ch in username):
            raise AuthError("username must be 3-64 characters of letters, digits, '.', '_' or '-'", status=422)
        self.check_password_policy(password, username)
        async with self.database.session() as session:
            users = UserRepository(session)
            if await users.by_username(username) is not None:
                raise AuthError(f"user {username!r} already exists", status=409)
            return await users.add(User(username=username, password_hash=self.hash_password(password), role=role.value))

    async def change_password(self, principal: Principal, current: str, new: str) -> None:
        async with self.database.session() as session:
            users = UserRepository(session)
            user = await users.get(principal.user_id)
            if user is None or not self._verify(user.password_hash, current):
                raise AuthError("current password is incorrect", status=403)
            if self._verify(user.password_hash, new):
                raise AuthError("new password must differ from the current one", status=422)
            self.check_password_policy(new, user.username)
            user.password_hash = self.hash_password(new)
            user.must_change_password = False
            await users.revoke_tokens(user.id)  # sign out every other session

    async def set_password(self, user_id: int, new: str) -> None:
        """Administrative reset. Forces a change at next login and revokes sessions."""
        async with self.database.session() as session:
            users = UserRepository(session)
            user = await users.get(user_id)
            if user is None:
                raise AuthError("user not found", status=404)
            self.check_password_policy(new, user.username)
            user.password_hash = self.hash_password(new)
            user.must_change_password = True
            user.failed_logins = 0
            user.locked_until = None
            await users.revoke_tokens(user.id)

    # ------------------------------------------------------------------ login

    @staticmethod
    def _verify(password_hash: str, password: str) -> bool:
        try:
            return _hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    async def login(self, username: str, password: str, *, client_ip: str) -> TokenPair:
        """Verify credentials and issue tokens.

        Raises:
            AuthError: 429 when the client IP is throttled, 423 when the account is
                locked, 401 for any credential failure (uniform message).
        """
        allowed, _, retry_after = await self.state.hit(
            "login", client_ip,
            limit=self.settings.login_rate_limit_attempts,
            window_seconds=self.settings.login_rate_limit_window_seconds,
        )
        if not allowed:
            raise AuthError("too many login attempts; try again later", status=429, retry_after=retry_after)

        now = datetime.now(UTC)
        async with self.database.session() as session:
            users = UserRepository(session)
            user = await users.by_username(username.strip()[:64])
            if user is None:
                self._verify(_DUMMY_HASH, password)  # equalise timing
                log.info("login_failed", username=username[:64], reason="unknown_user", client_ip=client_ip)
                raise AuthError(_GENERIC_FAILURE)

            locked_until = user.locked_until
            if locked_until is not None and locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=UTC)
            if locked_until is not None and locked_until > now:
                self._verify(_DUMMY_HASH, password)
                raise AuthError("account temporarily locked after repeated failures", status=423,
                                retry_after=(locked_until - now).total_seconds())

            if not user.is_active or not self._verify(user.password_hash, password):
                user.failed_logins += 1
                if user.failed_logins >= self.settings.lockout_threshold:
                    user.locked_until = now + timedelta(seconds=self.settings.lockout_seconds)
                    user.failed_logins = 0
                    log.warning("account_locked", username=user.username, client_ip=client_ip)
                log.info("login_failed", username=user.username, reason="bad_credentials", client_ip=client_ip)
                raise AuthError(_GENERIC_FAILURE)

            if _hasher.check_needs_rehash(user.password_hash):
                user.password_hash = self.hash_password(password)
            user.failed_logins = 0
            user.locked_until = None
            user.last_login_at = now
            principal = Principal(user.id, user.username, UserRole(user.role), must_change_password=user.must_change_password)
            pair = await self._issue(users, principal)
        await self.state.reset("login", client_ip)
        log.info("login_succeeded", username=principal.username, role=principal.role.value, client_ip=client_ip)
        return pair

    async def _issue(self, users: UserRepository, principal: Principal) -> TokenPair:
        now = datetime.now(UTC)
        access_jti, refresh_jti = secrets.token_hex(16), secrets.token_hex(16)
        access_expires = now + timedelta(seconds=self.settings.access_token_ttl_seconds)
        refresh_expires = now + timedelta(seconds=self.settings.refresh_token_ttl_seconds)
        common = {"sub": str(principal.user_id), "iss": self.settings.jwt_issuer, "iat": now}
        access = jwt.encode(
            {**common, "type": "access", "jti": access_jti, "exp": access_expires,
             "username": principal.username, "role": principal.role.value, "pwd_change": principal.must_change_password},
            self.settings.jwt_secret, algorithm=self.settings.jwt_algorithm,
        )
        refresh = jwt.encode(
            {**common, "type": "refresh", "jti": refresh_jti, "exp": refresh_expires},
            self.settings.jwt_secret, algorithm=self.settings.jwt_algorithm,
        )
        await users.store_refresh_token(refresh_jti, principal.user_id, refresh_expires)
        return TokenPair(access, refresh, access_expires, refresh_expires, principal)

    def _decode(self, token: str, expected_type: str) -> dict[str, Any]:
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                self.settings.jwt_secret,
                # Pinning the algorithm list is what prevents "alg: none" and
                # HS/RS confusion attacks.
                algorithms=[self.settings.jwt_algorithm],
                issuer=self.settings.jwt_issuer,
                options={"require": ["exp", "iat", "sub", "jti", "type"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("token expired") from exc
        except jwt.PyJWTError as exc:
            raise AuthError("invalid token") from exc
        if claims.get("type") != expected_type:
            raise AuthError("invalid token")
        return claims

    async def authenticate(self, access_token: str) -> Principal:
        """Validate an access token and confirm the account is still usable.

        The database check means a deactivated user or a demoted admin loses access
        on their next request, not when their token eventually expires.
        """
        claims = self._decode(access_token, "access")
        async with self.database.session() as session:
            user = await UserRepository(session).get(int(claims["sub"]))
        if user is None or not user.is_active:
            raise AuthError("account disabled")
        return Principal(user.id, user.username, UserRole(user.role), str(claims["jti"]), user.must_change_password)

    async def refresh(self, refresh_token: str) -> TokenPair:
        claims = self._decode(refresh_token, "refresh")
        async with self.database.session() as session:
            users = UserRepository(session)
            stored = await users.refresh_token(str(claims["jti"]))
            user = await users.get(int(claims["sub"]))
            if stored is None or user is None or not user.is_active:
                raise AuthError("invalid token")
            if stored.revoked_at is not None:
                # A rotated token came back: someone else holds a copy. Burn them all.
                await users.revoke_tokens(user.id)
                log.warning("refresh_token_reuse_detected", username=user.username)
                raise AuthError("invalid token")
            stored.revoked_at = datetime.now(UTC)
            principal = Principal(user.id, user.username, UserRole(user.role), must_change_password=user.must_change_password)
            return await self._issue(users, principal)

    async def logout(self, principal: Principal) -> None:
        async with self.database.session() as session:
            await UserRepository(session).revoke_tokens(principal.user_id)

    # ------------------------------------------------------------ websockets

    async def issue_ws_ticket(self, principal: Principal) -> str:
        ticket = secrets.token_urlsafe(32)
        await self.state.cache_set(f"wsticket:{ticket}", {"user_id": principal.user_id}, ttl_seconds=30)
        return ticket

    async def redeem_ws_ticket(self, ticket: str) -> Principal:
        if not ticket or len(ticket) > 128:
            raise AuthError("invalid ticket")
        key = f"wsticket:{ticket}"
        data = await self.state.cache_get(key)
        if not isinstance(data, dict):
            raise AuthError("invalid or expired ticket")
        await self.state.cache_set(key, "used", ttl_seconds=1)  # single use
        async with self.database.session() as session:
            user = await UserRepository(session).get(int(data["user_id"]))
        if user is None or not user.is_active:
            raise AuthError("account disabled")
        return Principal(user.id, user.username, UserRole(user.role))
