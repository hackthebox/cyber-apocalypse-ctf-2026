#!/usr/bin/env python3
"""htb/solve.py delegates to src/scripts/verify_lab.py."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

TARGET = Path(__file__).resolve().parent.parent / "src" / "scripts" / "verify_lab.py"

if __name__ == "__main__":
    if not TARGET.is_file():
        raise SystemExit(f"Missing challenge verify script: {TARGET}")
    sys.argv[0] = str(TARGET)
    runpy.run_path(str(TARGET), run_name="__main__")
