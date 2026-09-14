"""CLI entry point. Installed as the ``sentinelx`` command; this file allows
``python apps/cli/main.py`` from a source checkout."""

from sentinelx.cli.main import app

if __name__ == "__main__":
    app()
