"""Authentication and user management."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi import Path as FastApiPath
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.api.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    PasswordResetRequest,
    TokenResponse,
    UserCreateRequest,
    UserResponse,
    UserUpdateRequest,
)
from sentinelx.api.security import (
    REFRESH_COOKIE,
    Admin,
    PlatformDep,
    clear_auth_cookies,
    client_ip,
    current_principal,
    set_auth_cookies,
)
from sentinelx.common.enums import UserRole
from sentinelx.services.auth import AuthError, Principal, TokenPair
from sentinelx.storage.models import User
from sentinelx.storage.repositories import UserRepository

router = APIRouter(tags=["auth"])
Authenticated = Annotated[Principal, Depends(current_principal)]
UserId = Annotated[int, FastApiPath(ge=1, le=2**31 - 1)]


def _user(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        username=user.username,
        role=UserRole(user.role),
        is_active=user.is_active,
        must_change_password=user.must_change_password,
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
        created_at=user.created_at.isoformat() if user.created_at else None,
    )


def _token_response(
    request: Request, response: Response, pair: TokenPair, platform: PlatformDep
) -> TokenResponse:
    principal = pair.principal
    browser = request.headers.get("x-sentinelx-client") == "dashboard"
    csrf = (
        set_auth_cookies(response, pair, secure=platform.settings.api.cookie_secure)
        if browser
        else None
    )
    return TokenResponse(
        access_token=pair.access_token,
        # A browser gets the refresh token only as an httpOnly cookie; returning it
        # in the body would make it readable by any script on the page.
        refresh_token=None if browser else pair.refresh_token,
        expires_at=pair.access_expires_at.isoformat(),
        user=UserResponse(
            id=principal.user_id,
            username=principal.username,
            role=principal.role,
            must_change_password=principal.must_change_password,
        ),
        csrf_token=csrf,
    )


@router.post("/auth/login", response_model=TokenResponse, summary="Exchange credentials for tokens")
async def login(
    body: LoginRequest, request: Request, response: Response, platform: PlatformDep
) -> TokenResponse:
    ip = client_ip(request)
    try:
        pair = await platform.auth.login(body.username, body.password, client_ip=ip)
    except AuthError as exc:
        await platform.audit.record(
            # Client-supplied text: keep it printable so it cannot forge log lines.
            actor="".join(ch for ch in body.username[:64] if ch.isprintable()) or "(empty)",
            action="LOGIN_FAILED",
            source="api",
            outcome="failure",
            client_ip=ip,
            reason=str(exc),
        )
        raise
    await platform.audit.record(
        actor=pair.principal.username, action="LOGIN", source="api", client_ip=ip
    )
    return _token_response(request, response, pair, platform)


@router.post("/auth/refresh", response_model=TokenResponse, summary="Rotate a refresh token")
async def refresh(request: Request, response: Response, platform: PlatformDep) -> TokenResponse:
    """Rotate the refresh token from the JSON body (API clients) or the session cookie.

    The cookie is honoured only with ``X-SentinelX-Client: dashboard``, the header the
    dashboard sends on every call. A page on another site cannot add that header to a
    cross-site request without a CORS preflight, so the cookie alone never rotates a
    session (SameSite=Strict already keeps the cookie off such requests).
    """
    cookie = request.cookies.get(REFRESH_COOKIE)
    token: object = None
    if cookie and request.headers.get("x-sentinelx-client") == "dashboard":
        token = cookie
    else:
        body: dict[str, Any] = {}
        if request.headers.get("content-type", "").startswith("application/json"):
            try:
                body = await request.json()
            except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError
                raise HTTPException(
                    status_code=422, detail="request body is not valid JSON"
                ) from exc
        token = body.get("refresh_token") if isinstance(body, dict) else None
        if not token and cookie:
            raise HTTPException(
                status_code=403,
                detail="refreshing from the session cookie requires the dashboard client header",
            )
    if not token or not isinstance(token, str):
        raise HTTPException(status_code=401, detail="refresh token required")
    try:
        pair = await platform.auth.refresh(token)
    except AuthError:
        clear_auth_cookies(response)
        raise
    return _token_response(request, response, pair, platform)


@router.post(
    "/auth/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke all refresh tokens for the user",
)
async def logout(
    principal: Authenticated, request: Request, response: Response, platform: PlatformDep
) -> Response:
    await platform.auth.logout(principal)
    await platform.audit.record(
        actor=principal.username, action="LOGOUT", source="api", client_ip=client_ip(request)
    )
    clear_auth_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/auth/me", response_model=UserResponse)
async def me(principal: Authenticated, platform: PlatformDep) -> UserResponse:
    async with platform.database.session() as session:
        user = await UserRepository(session).get(principal.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    return _user(user)


@router.post(
    "/auth/change-password",
    response_model=TokenResponse,
    summary="Change your password; every other session is signed out",
)
async def change_password(
    body: ChangePasswordRequest,
    principal: Authenticated,
    request: Request,
    response: Response,
    platform: PlatformDep,
) -> TokenResponse:
    pair = await platform.auth.change_password(principal, body.current_password, body.new_password)
    await platform.audit.record(
        actor=principal.username,
        action="CHANGE_PASSWORD",
        target=principal.username,
        source="api",
        client_ip=client_ip(request),
    )
    # The caller keeps working with a fresh session; all earlier tokens are revoked.
    return _token_response(request, response, pair, platform)


@router.post("/auth/ws-ticket", summary="Issue a single-use 30 second WebSocket ticket")
async def ws_ticket(principal: Authenticated, platform: PlatformDep) -> dict[str, Any]:
    return {"ticket": await platform.auth.issue_ws_ticket(principal), "expires_in": 30}


# ------------------------------------------------------------------- users


@router.get("/users", response_model=list[UserResponse], tags=["users"])
async def list_users(principal: Admin, platform: PlatformDep) -> list[UserResponse]:
    async with platform.database.session() as session:
        return [_user(u) for u in await UserRepository(session).all()]


@router.post("/users", response_model=UserResponse, status_code=201, tags=["users"])
async def create_user(
    body: UserCreateRequest, principal: Admin, request: Request, platform: PlatformDep
) -> UserResponse:
    user = await platform.auth.create_user(body.username, body.password, body.role)
    await platform.audit.record(
        actor=principal.username,
        action="CREATE_USER",
        target=user.username,
        source="api",
        client_ip=client_ip(request),
        details={"role": body.role.value},
    )
    return _user(user)


@router.patch("/users/{user_id}", response_model=UserResponse, tags=["users"])
async def update_user(
    user_id: UserId,
    body: UserUpdateRequest,
    principal: Admin,
    request: Request,
    platform: PlatformDep,
) -> UserResponse:
    if user_id == principal.user_id and (
        body.role not in (None, UserRole.ADMIN) or body.is_active is False
    ):
        raise HTTPException(
            status_code=422, detail="you cannot demote or deactivate your own account"
        )
    async with platform.database.session() as session:
        users = UserRepository(session)
        await _active_admin_ids(session)  # serialises concurrent administrator changes
        user = await users.get(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="user not found")
        changes: dict[str, Any] = {}
        if body.role is not None and body.role.value != user.role:
            if user.role == UserRole.ADMIN.value and await _admin_count(users) <= 1:
                raise HTTPException(status_code=422, detail="cannot demote the last administrator")
            changes["role"] = {"from": user.role, "to": body.role.value}
            user.role = body.role.value
        if body.is_active is not None and body.is_active != user.is_active:
            changes["is_active"] = {"from": user.is_active, "to": body.is_active}
            user.is_active = body.is_active
            if not body.is_active:
                await users.revoke_tokens(user.id)
        if changes:
            await _require_an_active_admin(session)
        result = _user(user)
    await platform.audit.record(
        actor=principal.username,
        action="UPDATE_USER",
        target=result.username,
        source="api",
        client_ip=client_ip(request),
        details=changes,
    )
    return result


async def _admin_count(users: UserRepository) -> int:
    return sum(1 for u in await users.all() if u.role == UserRole.ADMIN.value and u.is_active)


async def _active_admin_ids(session: AsyncSession) -> list[int]:
    """Ids of the active administrators, row-locked until the transaction ends.

    On PostgreSQL ``FOR UPDATE`` makes a second administrator change wait for the
    first to commit, so both cannot pass a count taken before either change. SQLite
    ignores the clause; there the write lock serialises the changes and
    :func:`_require_an_active_admin` re-counts after this transaction's own write.
    """
    rows = await session.execute(
        select(User.id)
        .where(User.role == UserRole.ADMIN.value, User.is_active.is_(True))
        .order_by(User.id)
        .with_for_update()
    )
    return list(rows.scalars())


async def _require_an_active_admin(session: AsyncSession) -> None:
    """Refuse (and so roll back) a change that leaves no active administrator."""
    await session.flush()
    if not await _active_admin_ids(session):
        raise HTTPException(status_code=422, detail="at least one active administrator must remain")


@router.post("/users/{user_id}/reset-password", status_code=204, tags=["users"])
async def reset_password(
    user_id: UserId,
    body: PasswordResetRequest,
    principal: Admin,
    request: Request,
    platform: PlatformDep,
) -> Response:
    await platform.auth.set_password(user_id, body.new_password)
    await platform.audit.record(
        actor=principal.username,
        action="RESET_PASSWORD",
        target=str(user_id),
        source="api",
        client_ip=client_ip(request),
    )
    return Response(status_code=204)


@router.delete("/users/{user_id}", status_code=204, tags=["users"])
async def delete_user(
    user_id: UserId, principal: Admin, request: Request, platform: PlatformDep
) -> Response:
    if user_id == principal.user_id:
        raise HTTPException(status_code=422, detail="you cannot delete your own account")
    async with platform.database.session() as session:
        users = UserRepository(session)
        await _active_admin_ids(session)  # serialises concurrent administrator changes
        user = await users.get(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="user not found")
        if user.role == UserRole.ADMIN.value and await _admin_count(users) <= 1:
            raise HTTPException(status_code=422, detail="cannot delete the last administrator")
        username = user.username
        await users.delete(user)
        await _require_an_active_admin(session)
    await platform.audit.record(
        actor=principal.username,
        action="DELETE_USER",
        target=username,
        source="api",
        client_ip=client_ip(request),
    )
    return Response(status_code=204)
