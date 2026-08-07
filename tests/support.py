from __future__ import annotations

import sys
from pathlib import Path


def add_src_to_path() -> None:
    source = Path(__file__).resolve().parents[1] / "src"
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
