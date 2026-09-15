"""Authentication and authorisation.

* Passwords: Argon2id (``argon2-cffi`` defaults, RFC 9106 low-memory profile).
  Hashes are upgraded transparently at login when parameters change.
* Access tokens: HS256 JWTs, short-lived, carrying user id, role and a ``jti``.
* Refresh tokens: JWTs whose ``jti`` is stored server-side, so they can be revoked.
  Each use rotates the token; presenting an already-rotated token is treated as
  theft and revokes every refresh token for that user.
* Lockout: ``lockout_threshold`` failures for one account from one address lock that
  pair for ``lockout_seconds``; failures from many addresses lock the account itself at
  ``ACCOUNT_LOCK_MULTIPLIER`` times the threshold. Per-IP throttling applies as well.
* WebSocket tickets: single-use, 30-second, random tokens, so a long-lived access
  token never appears in a URL (where proxies and browser history record it).

Every authentication failure returns the same message whether the username exists
or not, and verification runs against a dummy hash for unknown users so response
time does not reveal which usernames are valid.
"""

from __future__ import annotations

import asyncio
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
    {
        "password",
        "password123",
        "123456789012",
        "qwertyuiopas",
        "administrator",
        "sentinelx",
        "letmein12345",
        "changeme1234",
        "adminadmin12",
        "welcome12345",
        "passw0rd1234",
    }
)
_GENERIC_FAILURE = "invalid username or password"
#: Failures from any addresses, as a multiple of ``lockout_threshold``, that lock an
#: account outright. Per-address lockout engages at the threshold itself.
ACCOUNT_LOCK_MULTIPLIER = 4
#: Concurrent Argon2 operations. Each uses ~64 MiB with the library defaults.
HASH_CONCURRENCY = 4


class AuthError(SentinelXError):
    """Authentication or authorisation failed. ``status`` maps onto HTTP."""

    def __init__(
        self, message: str, status: int = 401, *, retry_after: float | None = None
    ) -> None:
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
        self._hash_slots = asyncio.Semaphore(HASH_CONCURRENCY)

    # --------------------------------------------------------------- passwords

    @staticmethod
    def hash_password(password: str) -> str:
        return _hasher.hash(password)

    def check_password_policy(self, password: str, username: str) -> None:
        problems = validate_password(
            password, username=username, min_length=self.settings.password_min_length
        )
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
                    password_hash=await self._hash_async(password),
                    role=UserRole.ADMIN.value,
                    # A generated password was shown on a terminal; make the first
                    # login replace it.
                    must_change_password=generated is not None,
                )
            )
        log.warning(
            "bootstrap_admin_created",
            username=self.settings.bootstrap_admin_username,
            generated_password=generated is not None,
        )
        return generated

    async def create_user(self, username: str, password: str, role: UserRole) -> User:
        username = username.strip()
        if not 3 <= len(username) <= 64 or not all(ch.isalnum() or ch in "._-" for ch in username):
            raise AuthError(
                "username must be 3-64 characters of letters, digits, '.', '_' or '-'", status=422
            )
        self.check_password_policy(password, username)
        password_hash = await self._hash_async(password)
        async with self.database.session() as session:
            users = UserRepository(session)
            if await users.by_username(username) is not None:
                raise AuthError(f"user {username!r} already exists", status=409)
            return await users.add(
                User(username=username, password_hash=password_hash, role=role.value)
            )

    async def change_password(self, principal: Principal, current: str, new: str) -> TokenPair:
        """Change the caller's password, sign out every session, and start a new one.

        Returns:
            Fresh tokens for the caller, so changing a password does not end the
            session it was changed from.
        """
        async with self.database.session() as session:
            user = await UserRepository(session).get(principal.user_id)
            password_hash = user.password_hash if user is not None else _DUMMY_HASH
        if user is None or not await self._verify_async(password_hash, current):
            raise AuthError("current password is incorrect", status=403)
        if await self._verify_async(password_hash, new):
            raise AuthError("new password must differ from the current one", status=422)
        self.check_password_policy(new, user.username)
        new_hash = await self._hash_async(new)
        async with self.database.session() as session:
            users = UserRepository(session)
            stored = await users.get(principal.user_id)
            if stored is None:
                raise AuthError("account disabled")
            stored.password_hash = new_hash
            stored.must_change_password = False
            await users.end_sessions(stored.id)  # every other session ends
            await self._end_access_tokens(stored.id)
            pair = await self._issue(
                users, Principal(stored.id, stored.username, UserRole(stored.role))
            )
        if principal.token_id:
            await self._revoke_access_token(principal.token_id)
        return pair

    async def set_password(self, user_id: int, new: str) -> None:
        """Administrative reset. Forces a change at next login and revokes sessions."""
        async with self.database.session() as session:
            user = await UserRepository(session).get(user_id)
            if user is None:
                raise AuthError("user not found", status=404)
            username = user.username
        self.check_password_policy(new, username)
        new_hash = await self._hash_async(new)
        async with self.database.session() as session:
            users = UserRepository(session)
            user = await users.get(user_id)
            if user is None:
                raise AuthError("user not found", status=404)
            user.password_hash = new_hash
            user.must_change_password = True
            user.failed_logins = 0
            user.locked_until = None
            await users.end_sessions(user.id)
        await self._end_access_tokens(user_id)

    # ------------------------------------------------------------------ login

    @staticmethod
    def _verify(password_hash: str, password: str) -> bool:
        try:
            return _hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    async def _hash_async(self, password: str) -> str:
        """Argon2 hashing on a worker thread, sharing the verification limit."""
        async with self._hash_slots:
            return await asyncio.to_thread(self.hash_password, password)

    async def _verify_async(self, password_hash: str, password: str) -> bool:
        """Argon2 verification on a worker thread, a few at a time.

        Each verification deliberately costs tens of milliseconds of CPU and memory; on
        the event loop that would stall every request and the packet pipeline, and
        without a bound a login flood would exhaust memory.
        """
        async with self._hash_slots:
            return await asyncio.to_thread(self._verify, password_hash, password)

    async def login(self, username: str, password: str, *, client_ip: str) -> TokenPair:
        """Verify credentials and issue tokens.

        Lockout has two levels. Repeated failures for one account *from one address*
        lock that pair for ``lockout_seconds``, which stops guessing without letting
        anyone lock another person out from elsewhere. Failures for an account from
        any addresses lock the account itself only at ``ACCOUNT_LOCK_MULTIPLIER`` times
        the threshold, against guessing distributed across many addresses.

        Raises:
            AuthError: 429 when the client IP is throttled, 423 when locked, 401 for any
                credential failure (the same message whether or not the user exists).
        """
        allowed, _, retry_after = await self.state.hit(
            "login",
            client_ip,
            limit=self.settings.login_rate_limit_attempts,
            window_seconds=self.settings.login_rate_limit_window_seconds,
        )
        if not allowed:
            raise AuthError(
                "too many login attempts; try again later", status=429, retry_after=retry_after
            )

        name = username.strip()[:64]
        pair_key = f"{name.lower()}|{client_ip}"
        now = datetime.now(UTC)
        async with self.database.session() as session:
            user = await UserRepository(session).by_username(name)
            snapshot = (
                (user.id, user.password_hash, user.is_active, user.locked_until)
                if user is not None
                else None
            )

        pair_failures, pair_retry = await self.state.count(
            "login-fail", pair_key, window_seconds=self.settings.lockout_seconds
        )
        locked_until = snapshot[3] if snapshot else None
        if locked_until is not None and locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=UTC)
        if pair_failures >= self.settings.lockout_threshold or (
            locked_until is not None and locked_until > now
        ):
            await self._verify_async(_DUMMY_HASH, password)  # equalise timing
            wait = pair_retry
            if locked_until is not None and locked_until > now:
                wait = max(wait, (locked_until - now).total_seconds())
            raise AuthError(
                "account temporarily locked after repeated failures",
                status=423,
                retry_after=wait,
            )

        if snapshot is None:
            await self._verify_async(_DUMMY_HASH, password)
            log.info("login_failed", username=name, reason="unknown_user", client_ip=client_ip)
            await self.state.hit(
                "login-fail",
                pair_key,
                limit=self.settings.lockout_threshold,
                window_seconds=self.settings.lockout_seconds,
            )
            raise AuthError(_GENERIC_FAILURE)

        user_id, password_hash, is_active, _ = snapshot
        verified = is_active and await self._verify_async(password_hash, password)
        if not verified:
            await self.state.hit(
                "login-fail",
                pair_key,
                limit=self.settings.lockout_threshold,
                window_seconds=self.settings.lockout_seconds,
            )
            async with self.database.session() as session:
                users = UserRepository(session)
                failures = await users.record_failed_login(user_id)
                if failures >= self.settings.lockout_threshold * ACCOUNT_LOCK_MULTIPLIER:
                    stored = await users.get(user_id)
                    if stored is not None:
                        stored.locked_until = now + timedelta(seconds=self.settings.lockout_seconds)
                        stored.failed_logins = 0
                    log.warning("account_locked", username=name, client_ip=client_ip)
            log.info("login_failed", username=name, reason="bad_credentials", client_ip=client_ip)
            raise AuthError(_GENERIC_FAILURE)

        rehash = (
            await self._hash_async(password)
            if _hasher.check_needs_rehash(password_hash)
            else None
        )
        async with self.database.session() as session:
            users = UserRepository(session)
            stored = await users.get(user_id)
            if stored is None or not stored.is_active:
                raise AuthError(_GENERIC_FAILURE)
            if rehash is not None:
                stored.password_hash = rehash
            stored.failed_logins = 0
            stored.locked_until = None
            stored.last_login_at = now
            principal = Principal(
                stored.id,
                stored.username,
                UserRole(stored.role),
                must_change_password=stored.must_change_password,
            )
            pair = await self._issue(users, principal)
        await self.state.reset("login", client_ip)
        await self.state.reset("login-fail", pair_key)
        log.info(
            "login_succeeded",
            username=principal.username,
            role=principal.role.value,
            client_ip=client_ip,
        )
        return pair

    async def _issue(self, users: UserRepository, principal: Principal) -> TokenPair:
        now = datetime.now(UTC)
        access_jti, refresh_jti = secrets.token_hex(16), secrets.token_hex(16)
        access_expires = now + timedelta(seconds=self.settings.access_token_ttl_seconds)
        refresh_expires = now + timedelta(seconds=self.settings.refresh_token_ttl_seconds)
        common = {"sub": str(principal.user_id), "iss": self.settings.jwt_issuer, "iat": now}
        access = jwt.encode(
            {
                **common,
                "type": "access",
                "jti": access_jti,
                "exp": access_expires,
                "username": principal.username,
                "role": principal.role.value,
                "pwd_change": principal.must_change_password,
            },
            self.settings.jwt_secret,
            algorithm=self.settings.jwt_algorithm,
        )
        refresh = jwt.encode(
            {**common, "type": "refresh", "jti": refresh_jti, "exp": refresh_expires},
            self.settings.jwt_secret,
            algorithm=self.settings.jwt_algorithm,
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
        on their next request, not when their token eventually expires; the revocation
        check means a signed-out token stops working immediately.
        """
        claims = self._decode(access_token, "access")
        token_id = str(claims["jti"])
        if await self.state.cache_get(f"revoked-access:{token_id}") is not None:
            raise AuthError("token revoked")
        ended = await self.state.cache_get(f"sessions-ended:{claims['sub']}")
        if isinstance(ended, int) and int(claims["iat"]) < ended:
            raise AuthError("session ended")
        async with self.database.session() as session:
            user = await UserRepository(session).get(int(claims["sub"]))
        if user is None or not user.is_active:
            raise AuthError("account disabled")
        return Principal(
            user.id,
            user.username,
            UserRole(user.role),
            token_id,
            user.must_change_password,
        )

    async def refresh(self, refresh_token: str) -> TokenPair:
        claims = self._decode(refresh_token, "refresh")
        reuse_detected = False
        async with self.database.session() as session:
            users = UserRepository(session)
            stored = await users.refresh_token(str(claims["jti"]))
            user = await users.get(int(claims["sub"]))
            if stored is None or user is None or not user.is_active:
                raise AuthError("invalid token")  # nothing to persist; rollback is harmless
            if not await users.claim_refresh_token(stored.jti):
                # Already used: someone else holds a copy (or raced us with it). Revoke
                # the whole family; the revocation must commit, so raise after the block.
                await users.revoke_tokens(user.id)
                log.warning("refresh_token_reuse_detected", username=user.username)
                reuse_detected = True
            else:
                principal = Principal(
                    user.id,
                    user.username,
                    UserRole(user.role),
                    must_change_password=user.must_change_password,
                )
                pair = await self._issue(users, principal)
        if reuse_detected:
            raise AuthError("invalid token")
        return pair

    async def logout(self, principal: Principal) -> None:
        """Sign the user out everywhere: refresh and access tokens stop working now."""
        async with self.database.session() as session:
            await UserRepository(session).end_sessions(principal.user_id)
        await self._end_access_tokens(principal.user_id)
        if principal.token_id:
            await self._revoke_access_token(principal.token_id)

    async def _end_access_tokens(self, user_id: int) -> None:
        """Deny every access token issued to the user before now.

        Access tokens are self-contained, so without this, sessions signed out by a
        logout or password change would keep working until their tokens expired.
        Tokens issued in the same second (the caller's fresh pair) stay valid.
        """
        await self.state.cache_set(
            f"sessions-ended:{user_id}",
            int(datetime.now(UTC).timestamp()),
            ttl_seconds=self.settings.access_token_ttl_seconds,
        )

    async def _revoke_access_token(self, token_id: str) -> None:
        """Deny an access token until it would have expired anyway."""
        await self.state.cache_set(
            f"revoked-access:{token_id}", True, ttl_seconds=self.settings.access_token_ttl_seconds
        )

    # ------------------------------------------------------------ websockets

    async def issue_ws_ticket(self, principal: Principal) -> str:
        ticket = secrets.token_urlsafe(32)
        await self.state.cache_set(
            f"wsticket:{ticket}", {"user_id": principal.user_id}, ttl_seconds=30
        )
        return ticket

    async def redeem_ws_ticket(self, ticket: str) -> Principal:
        if not ticket or len(ticket) > 128:
            raise AuthError("invalid ticket")
        # Read-and-delete in one atomic step: two connections presenting the same
        # ticket cannot both succeed.
        data = await self.state.cache_pop(f"wsticket:{ticket}")
        if not isinstance(data, dict):
            raise AuthError("invalid or expired ticket")
        async with self.database.session() as session:
            user = await UserRepository(session).get(int(data["user_id"]))
        if user is None or not user.is_active:
            raise AuthError("account disabled")
        return Principal(user.id, user.username, UserRole(user.role))
