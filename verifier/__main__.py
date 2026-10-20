"""Entry point: python -m verifier --db <path> --pubkey <path> [--tamper]

Reads the raw action-records chain from a SQLite DB, loads the Ed25519
public key, and verifies the chain's hash links and signatures.

Pass --tamper to flip one byte in the DB before verifying, proving that
the chain detects any modification.

Isolation contract: this module (and verifier/verify.py) may only import
from the Python standard library and the `cryptography` package.  It must
never import `harness` or `compliance_runtime`.
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from verifier.verify import verify_chain


def _read_chain_raw(db_path: Path) -> list[dict]:
    """Read action_records in insertion order without deserializing."""
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM action_records ORDER BY rowid ASC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _tamper_db(source: Path) -> Path:
    """Copy the DB to a temp file and flip one byte at the binary level,
    simulating a post-write tampering attempt that bypasses SQL triggers.

    Reads the first record's disposition from SQLite (to know what to find),
    then locates that UTF-8 string in the raw file bytes and flips one
    character — exactly how a real attacker would modify a SQLite file
    after the triggers were set.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    tampered = Path(tmp.name)
    shutil.copy2(source, tampered)

    # Read the first record's current_hash — a 64-char lowercase hex string,
    # unique and unlikely to appear in SQLite metadata pages.
    conn = sqlite3.connect(str(tampered))
    try:
        row = conn.execute(
            "SELECT rowid, current_hash, action "
            "FROM action_records ORDER BY rowid LIMIT 1"
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise RuntimeError("No records found in DB — nothing to tamper")
    rowid, current_hash, action = row

    # Flip the first hex character of the current_hash at the binary level.
    # 'a'→'b', anything else → 'a'.  This changes the stored hash without
    # touching signatures or previous_hash pointers, so:
    #   - record[0] hash recomputation will not match the stored (flipped) hash
    #   - record[0] signature check will fail (signature was over the original)
    #   - record[1] previous_hash will not match the flipped current_hash
    original_byte = current_hash[0].encode("ascii")
    replacement_byte = b"b" if original_byte != b"b" else b"c"

    target = current_hash.encode("ascii")
    replacement = replacement_byte + target[1:]

    raw = tampered.read_bytes()
    # Replace ALL occurrences — SQLite stores values in both the B-tree
    # leaf pages and any covering indexes, so a single-occurrence replace
    # leaves SQLite reading from an untouched copy.
    count = raw.count(target)
    if count == 0:
        raise RuntimeError(
            "Could not locate current_hash in raw DB bytes — cannot tamper"
        )
    patched = raw.replace(target, replacement)
    tampered.write_bytes(patched)

    flipped_hash = replacement.decode("ascii")
    print(
        f"\n  [TAMPER] Binary edit on action={action!r}, rowid={rowid}:\n"
        f"           Replaced {count} occurrence(s) of current_hash in raw bytes.\n"
        f"           current_hash[0]: {original_byte.decode()!r} → "
        f"{replacement_byte.decode()!r}\n"
        f"           stored hash now: {flipped_hash[:16]}…  "
        f"(was: {current_hash[:16]}…)"
    )

    return tampered


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verifier",
        description="Offline Ed25519 + SHA-256 chain verifier",
    )
    parser.add_argument("--db", required=True, help="Path to the SQLite chain DB")
    parser.add_argument(
        "--pubkey", required=True, help="Path to the PEM-encoded Ed25519 public key"
    )
    parser.add_argument(
        "--tamper",
        action="store_true",
        help=(
            "Demo mode: copy the DB, flip one byte, then verify — "
            "proves the chain detects tampering. The original DB is NOT modified."
        ),
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    pubkey_path = Path(args.pubkey)

    if not db_path.exists():
        print(f"ERROR: DB not found: {db_path}", file=sys.stderr)
        return 2
    if not pubkey_path.exists():
        print(f"ERROR: Public key not found: {pubkey_path}", file=sys.stderr)
        return 2

    tampered_path: Path | None = None
    verify_path = db_path
    if args.tamper:
        print("  [TAMPER MODE] Copying DB and flipping one byte...")
        tampered_path = _tamper_db(db_path)
        verify_path = tampered_path

    try:
        chain = _read_chain_raw(verify_path)
        public_key_pem = pubkey_path.read_bytes()

        result = verify_chain(chain, public_key_pem)
    finally:
        if tampered_path and tampered_path.exists():
            tampered_path.unlink()

    print("=" * 56)
    if args.tamper:
        print("  Chain Verifier  [TAMPER DEMO]")
    else:
        print("  Chain Verifier")
    print("=" * 56)
    print(f"  DB            : {db_path}")
    print(f"  Records       : {result['checked']}")
    chain_status = "PASS" if result["chain_ok"] else "FAIL"
    sig_status   = "PASS" if result["sigs_ok"]  else "FAIL"
    print(f"  Chain Integrity   : {chain_status}")
    print(f"  Signature Validity: {sig_status}")
    if result["errors"]:
        print("  Errors:")
        for err in result["errors"]:
            print(f"    ✗  {err}")

    stats = result.get("stats", {})
    receipts = result.get("receipts", [])
    if receipts:
        print("")
        print(f"  Measurement receipts : {stats['total']}")
        accuracy = stats.get("accuracy")
        fo_rate  = stats.get("firing_offense_rate")
        fr_rate  = stats.get("friction_rate")
        print(f"  Accuracy             : {accuracy*100:.1f}%  ({stats.get('correct','?')}/{stats['total']})")
        print(f"  Firing-offense rate  : {fo_rate*100:.1f}%  (should be 0.0%)")
        print(f"  Friction rate        : {fr_rate*100:.1f}%  (should be 0.0%)")
        print("")
        print("  By expected disposition:")
        for bucket, counts in sorted(stats.get("by_bucket", {}).items()):
            mark = "✓" if counts["correct"] == counts["total"] else "✗"
            print(f"    {mark}  {bucket:<22}  {counts['correct']}/{counts['total']}")

    print("=" * 56)
    overall = "VALID" if result["valid"] else "INVALID"
    print(f"  Overall: {overall}")

    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
