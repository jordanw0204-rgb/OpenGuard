from __future__ import annotations

import argparse

from openguard.service import run_service


def main() -> int:
    parser = argparse.ArgumentParser(prog="OpenGuardService")
    parser.add_argument("--service", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--data-dir", default=None, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if not arguments.service:
        parser.error("This binary is launched by the Windows Service Control Manager")
    run_service(arguments.data_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
