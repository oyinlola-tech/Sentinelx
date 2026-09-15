"""The generated first-administrator password reaches the operator only through a
private file, never through console output (which docker logs and journald keep).

Regression for CodeQL py/clear-text-logging-sensitive-data: the password was printed to
standard error at start-up.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import httpx
import pytest

from sentinelx.api.app import create_app
from sentinelx.firewall import MemoryFirewall
from sentinelx.services import bootstrap
from sentinelx.services.bootstrap import (
    BootstrapSecretError,
    remove_password_file,
    write_password_file,
)
from sentinelx.services.platform import Platform
from tests.api.conftest import make_settings

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes and ownership")


class TestPasswordFile:
    @posix_only
    def test_file_is_private_to_this_account(self, tmp_path: Path) -> None:
        path = write_password_file(tmp_path / "private" / "pw", "s3cret-value")
        assert path.read_text(encoding="utf-8") == "s3cret-value\n"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700

    def test_an_existing_file_is_replaced(self, tmp_path: Path) -> None:
        path = tmp_path / "private" / "pw"
        write_password_file(path, "first")
        write_password_file(path, "second")
        assert path.read_text(encoding="utf-8") == "second\n"

    @posix_only
    def test_a_planted_symlink_is_replaced_not_followed(self, tmp_path: Path) -> None:
        directory = tmp_path / "private"
        directory.mkdir(mode=0o700)
        victim = tmp_path / "victim.txt"
        victim.write_text("untouched", encoding="utf-8")
        (directory / "pw").symlink_to(victim)
        path = write_password_file(directory / "pw", "s3cret-value")
        assert not path.is_symlink()
        assert victim.read_text(encoding="utf-8") == "untouched"

    @posix_only
    def test_a_directory_others_can_open_is_refused(self, tmp_path: Path) -> None:
        shared = tmp_path / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        with pytest.raises(BootstrapSecretError, match="accessible to other accounts"):
            write_password_file(shared / "pw", "s3cret-value")
        assert not (shared / "pw").exists()

    @posix_only
    def test_a_symlinked_directory_is_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        (tmp_path / "link").symlink_to(real, target_is_directory=True)
        with pytest.raises(BootstrapSecretError, match="not a plain directory"):
            write_password_file(tmp_path / "link" / "pw", "s3cret-value")

    def test_default_location_is_per_account(self) -> None:
        path = bootstrap.default_password_file()
        assert path.name == "initial-admin-password"
        owner = str(os.geteuid()) if hasattr(os, "geteuid") else None
        if owner is not None:
            assert path.parent.name == f"sentinelx-{owner}"

    def test_removing_a_missing_file_is_not_an_error(self, tmp_path: Path) -> None:
        assert remove_password_file(tmp_path / "absent") is False


async def _start(tmp_path: Path, **api: object) -> Platform:
    settings = make_settings(tmp_path, bootstrap_admin_password="", **api)
    platform = Platform(settings, firewall=MemoryFirewall())
    await platform.start()
    return platform


async def test_start_up_output_never_contains_the_password(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    password_file = tmp_path / "secrets" / "initial-admin-password"
    settings = make_settings(
        tmp_path, bootstrap_admin_password="", bootstrap_password_file=password_file
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        platform: Platform = app.state.platform
        assert platform.bootstrap_password_file == password_file
        password = password_file.read_text(encoding="utf-8").strip()
        assert len(password) >= 20
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as http:
            login = await http.post("/auth/login", json={"username": "admin", "password": password})
            assert login.status_code == 200
            assert login.json()["user"]["must_change_password"] is True
    captured = capfd.readouterr()
    console = captured.out + captured.err
    assert password not in console
    assert str(password_file) in console


async def test_the_file_is_deleted_once_the_admin_chooses_a_password(tmp_path: Path) -> None:
    password_file = tmp_path / "secrets" / "pw"
    platform = await _start(tmp_path, bootstrap_password_file=password_file)
    try:
        password = password_file.read_text(encoding="utf-8").strip()
        app = create_app(platform.settings, platform=platform)
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as http:
            token = (
                await http.post("/auth/login", json={"username": "admin", "password": password})
            ).json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            # Until the password is changed, this account may do nothing else.
            assert (await http.get("/system/status", headers=headers)).status_code == 403
            assert platform.bootstrap_password_file == password_file
            changed = await http.post(
                "/auth/change-password",
                headers=headers,
                json={"current_password": password, "new_password": "Chosen-By-Me-2026"},
            )
            assert changed.status_code == 200
            assert not password_file.exists()
            fresh = {"Authorization": f"Bearer {changed.json()['access_token']}"}
            status = await http.get("/system/status", headers=fresh)
            assert status.json()["bootstrap_admin_pending"] is False
    finally:
        await platform.stop()


@posix_only
async def test_an_unsafe_location_prints_no_password_and_says_how_to_recover(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    settings = make_settings(
        tmp_path, bootstrap_admin_password="", bootstrap_password_file=shared / "pw"
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        platform: Platform = app.state.platform
        assert platform.bootstrap_password_file is None
        assert platform.bootstrap_password_undelivered is True
    console = "".join(capfd.readouterr())
    assert not (shared / "pw").exists()
    assert "sentinelx users reset-password admin" in console
    assert "password is in" not in console


async def test_a_configured_password_writes_no_file(tmp_path: Path) -> None:
    password_file = tmp_path / "secrets" / "pw"
    settings = make_settings(tmp_path, bootstrap_password_file=password_file)
    platform = Platform(settings, firewall=MemoryFirewall())
    await platform.start()
    try:
        assert platform.bootstrap_password_file is None
        assert not password_file.exists()
    finally:
        await platform.stop()
