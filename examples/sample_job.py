#!/usr/bin/env python3
"""Example parallel workload shipped automatically by `phonecluster map --script`.

Try running across all phones from your Master phone:
  python3 phonecluster_cli.py map --script examples/sample_job.py --args-file examples/sample_args.txt
  # or:
  python3 phonecluster_cli.py map --script examples/sample_job.py --repeat 12
"""

from __future__ import annotations

import math
import os
import socket
import sys
import time


def count_primes(limit: int) -> int:
    if limit < 2:
        return 0
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for p in range(2, int(math.isqrt(limit)) + 1):
        if sieve[p]:
            sieve[p * p : limit + 1 : p] = b"\x00" * ((limit - p * p) // p + 1)
    return sum(sieve)


def main() -> None:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 250_000
    t0 = time.monotonic()
    found = count_primes(limit)
    dt = time.monotonic() - t0
    node = os.environ.get("PHONECLUSTER_NODE_ID", socket.gethostname())
    idx = os.environ.get("PHONECLUSTER_TASK_INDEX", "0")
    print(f"task={idx} node={node} limit={limit} primes={found} elapsed={dt:.3f}s")


if __name__ == "__main__":
    main()
