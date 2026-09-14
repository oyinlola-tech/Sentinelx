#!/usr/bin/env python3
"""Export the API's OpenAPI document for the dashboard's typed client.

    python scripts/export_openapi.py            # writes apps/dashboard/src/lib/openapi.json
    cd apps/dashboard && npm run generate:api   # regenerates api-schema.d.ts

CI runs both and fails if the committed files differ, so the frontend contract can
never silently drift from the backend.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sentinelx.api.app import create_app
from sentinelx.config.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET = ROOT / "apps" / "dashboard" / "src" / "lib" / "openapi.json"


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_TARGET
    settings = Settings(api={"jwt_secret": "x" * 48, "docs_enabled": True})
    schema = create_app(settings).openapi()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {target.relative_to(ROOT)} ({len(schema['paths'])} paths)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
