"""Provisioning script helper for a revision check and an atomic JSON transfer."""

import argparse
import json
import sys
from pathlib import Path

from .config import ClusterConfig, config_revision, replace_config_file

MAX_CONFIG_TRANSFER_BYTES = 2 * 1024 * 1024


def _reject_non_finite(token: str) -> None:
    raise ValueError(f"Invalid non-finite JSON constant: {token}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--expect", help="Replace this revision with JSON from stdin")
    args = parser.parse_args()
    try:
        if args.expect is None:
            print(config_revision(args.config))
        else:
            raw = sys.stdin.buffer.read(MAX_CONFIG_TRANSFER_BYTES + 1)
            if len(raw) > MAX_CONFIG_TRANSFER_BYTES:
                raise ValueError(f"Config payload exceeds {MAX_CONFIG_TRANSFER_BYTES} byte limit")
            parsed = json.loads(raw.decode("utf-8"), parse_constant=_reject_non_finite)
            ClusterConfig.from_dict(parsed)
            replace_config_file(args.config, raw, args.expect)
    except (OSError, ValueError, RecursionError) as exc:
        print(f"Config transfer failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
