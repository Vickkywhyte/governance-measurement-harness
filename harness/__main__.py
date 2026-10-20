"""Entry point: python -m harness [--keys-dir DIR] [--db PATH]

Deletes the chain DB (fresh run), executes all vectors through the
compliance runtime, prints a formatted report, and exits non-zero if any
vector failed.

Examples:
    python -m harness
    python -m harness --keys-dir ./test_keys --db ./test_chain.db
"""

from __future__ import annotations

import argparse
import contextlib
import sys
import tempfile
from pathlib import Path

from compliance_runtime.config.keys import set_keys_dir

from harness.runner import _CHAIN_DB, run
from harness.stats import format_report, summarise


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m harness",
        description="Governance measurement harness runner",
    )
    parser.add_argument(
        "--keys-dir",
        metavar="DIR",
        default=None,
        help=(
            "Directory to store the Ed25519 key pair. "
            "When supplied the keys persist after the run so you can verify "
            "the chain with: python -m verifier --db <db> --pubkey <dir>/verification_key.pem. "
            "When omitted an ephemeral temp dir is used and the keys are discarded."
        ),
    )
    parser.add_argument(
        "--db",
        metavar="PATH",
        default=str(_CHAIN_DB),
        help=f"Path to the SQLite chain DB (default: {_CHAIN_DB})",
    )
    args = parser.parse_args()

    chain_db = Path(args.db)

    # Delete the chain DB so every run starts from genesis.
    if chain_db.exists():
        chain_db.unlink()

    if args.keys_dir:
        keys_dir = Path(args.keys_dir)
        keys_dir.mkdir(parents=True, exist_ok=True)
        ctx = contextlib.nullcontext(str(keys_dir))
    else:
        ctx = tempfile.TemporaryDirectory()

    with ctx as keys_path:
        pub_key_path = Path(keys_path) / "verification_key.pem"
        set_keys_dir(keys_path)
        try:
            receipts = run(chain_db=chain_db)
        finally:
            set_keys_dir(None)

        summary = summarise(receipts)
        print(format_report(summary))

        if pub_key_path.exists():
            print(f"\n  Public key for this run's chain:")
            print(f"    {pub_key_path}")
            print(f"\n  Verify with:")
            print(
                f"    python -m verifier --db {chain_db} --pubkey {pub_key_path}"
            )
        elif args.keys_dir:
            print(
                f"\n  WARNING: key not found at {pub_key_path} — "
                "verification_key.pem may not have been written."
            )

    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
