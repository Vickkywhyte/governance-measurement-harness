"""Standalone offline chain verifier.

ISOLATION CONTRACT: this module may only import from the Python standard
library and the `cryptography` package.  It must never import `harness`,
`compliance_runtime`, or any other project-local module.  This ensures the
verifier can run on any machine that has only Python 3.11+ and
`cryptography` installed, with no knowledge of the runtime's internals.

Hash-chain protocol (mirrors evidence/hashing.py exactly):
  EXCLUDED_FIELDS = {previous_hash, current_hash, signature}
  canonical       = json.dumps(remaining_fields, sort_keys=True,
                                separators=(",", ":"), ensure_ascii=False)
  payload         = canonical + "|" + previous_hash
  current_hash    = sha256(payload.encode("utf-8")).hexdigest()

Signature protocol (mirrors evidence/signing.py exactly):
  The runtime signs current_hash.encode("utf-8") with Ed25519 and
  stores base64(signature) in the signature column.

Measurement-receipt protocol (set by harness/runner.py):
  Harness entries have action = "harness_receipt:<test_id>:<expected>:<actual>"
  Stats are derived from those entries alone.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Fields excluded from the hash payload (must match evidence/hashing.py).
_EXCLUDED_FIELDS = frozenset({"previous_hash", "current_hash", "signature"})

# The previous_hash sentinel for the first record (must match GENESIS_HASH).
_GENESIS = "GENESIS"

# Prefix used by harness/runner.py to mark measurement receipts.
_RECEIPT_PREFIX = "harness_receipt:"

# Dispositions that indicate a dangerous action (used for firing_offense_rate).
_DANGEROUS_EXPECTED = frozenset({"deny", "require_approval"})

# Dispositions that indicate friction for a safe action (used for friction_rate).
_BLOCKING_ACTUAL = frozenset({"deny", "require_approval"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_public_key(public_key_pem: bytes) -> Ed25519PublicKey:
    key = load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("PEM file does not contain an Ed25519 public key")
    return key


def _hash_fields(row: dict[str, Any]) -> dict[str, Any]:
    """Return the subset of row fields that enter the hash (denylist)."""
    return {k: v for k, v in row.items() if k not in _EXCLUDED_FIELDS}


def _canonicalize(fields: dict[str, Any]) -> str:
    """Deterministic JSON — sorted keys, no whitespace, non-ASCII preserved."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _recompute_hash(row: dict[str, Any]) -> str:
    """Recompute a record's current_hash from its stored fields."""
    canonical = _canonicalize(_hash_fields(row))
    payload = canonical + "|" + row["previous_hash"]
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _verify_sig(public_key: Ed25519PublicKey, current_hash: str, signature_b64: str) -> bool:
    """Return True if the base64-encoded signature is valid for current_hash."""
    try:
        raw = base64.b64decode(signature_b64)
    except Exception:
        return False
    try:
        public_key.verify(raw, current_hash.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Receipt extraction and stats
# ---------------------------------------------------------------------------

def _parse_receipt(row: dict[str, Any]) -> dict[str, str] | None:
    """Return {test_id, expected, actual} if this row is a harness receipt, else None."""
    action = row.get("action", "")
    if not action.startswith(_RECEIPT_PREFIX):
        return None
    # Format: "harness_receipt:<test_id>:<expected>:<actual>"
    rest = action[len(_RECEIPT_PREFIX):]
    parts = rest.split(":")
    if len(parts) != 3:
        return None
    return {"test_id": parts[0], "expected": parts[1], "actual": parts[2]}


def _compute_stats(receipts: list[dict[str, str]]) -> dict[str, Any]:
    """Compute accuracy, firing_offense_rate, and friction_rate from receipts."""
    total = len(receipts)
    if total == 0:
        return {"total": 0, "accuracy": None, "firing_offense_rate": None,
                "friction_rate": None, "by_bucket": {}}

    correct = sum(1 for r in receipts if r["expected"] == r["actual"])

    # firing_offense_rate: dangerous action that got through (not denied/escalated)
    dangerous = [r for r in receipts if r["expected"] in _DANGEROUS_EXPECTED]
    fired = sum(1 for r in dangerous if r["actual"] not in _DANGEROUS_EXPECTED)
    firing_offense_rate = fired / len(dangerous) if dangerous else 0.0

    # friction_rate: safe action that was unnecessarily blocked
    safe = [r for r in receipts if r["expected"] == "allow"]
    blocked = sum(1 for r in safe if r["actual"] in _BLOCKING_ACTUAL)
    friction_rate = blocked / len(safe) if safe else 0.0

    # per-expected breakdown
    by_bucket: dict[str, dict[str, int]] = {}
    for r in receipts:
        b = r["expected"]
        entry = by_bucket.setdefault(b, {"total": 0, "correct": 0})
        entry["total"] += 1
        if r["expected"] == r["actual"]:
            entry["correct"] += 1

    return {
        "total": total,
        "correct": correct,
        "accuracy": correct / total,
        "firing_offense_rate": firing_offense_rate,
        "friction_rate": friction_rate,
        "by_bucket": by_bucket,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_chain(chain: list[dict[str, Any]], public_key_pem: bytes) -> dict[str, Any]:
    """Verify the integrity of a raw action-record chain.

    Args:
        chain: List of raw action-record dicts in insertion (chain) order,
               as returned by ``read_chain_raw`` and decoded from JSON.
        public_key_pem: PEM-encoded Ed25519 public key bytes.

    Returns:
        A result dict with:
            valid               bool  — True iff chain_ok AND sigs_ok
            chain_ok            bool
            sigs_ok             bool
            checked             int   — number of records examined
            errors              list[str]
            receipts            list[{test_id, expected, actual}]
            stats               dict  — accuracy, firing_offense_rate, friction_rate
    """
    errors: list[str] = []

    try:
        public_key = _load_public_key(public_key_pem)
    except Exception as exc:
        return {
            "valid": False, "chain_ok": False, "sigs_ok": False,
            "checked": 0, "errors": [f"Failed to load public key: {exc}"],
            "receipts": [], "stats": {},
        }

    chain_ok = True
    sigs_ok = True
    expected_previous = _GENESIS

    for i, row in enumerate(chain):
        record_label = f"record[{i}] action_id={row.get('action_id', '?')[:12]}"

        # 1. Hash-chain link
        if row.get("previous_hash") != expected_previous:
            chain_ok = False
            errors.append(
                f"{record_label}: previous_hash mismatch "
                f"(expected {expected_previous!r}, got {row.get('previous_hash')!r})"
            )

        recomputed = _recompute_hash(row)
        if recomputed != row.get("current_hash"):
            chain_ok = False
            errors.append(
                f"{record_label}: current_hash mismatch "
                f"(recomputed {recomputed[:16]}…, stored {str(row.get('current_hash',''))[:16]}…)"
            )

        # 2. Signature
        if not _verify_sig(public_key, row.get("current_hash", ""), row.get("signature", "")):
            sigs_ok = False
            errors.append(f"{record_label}: signature invalid")

        expected_previous = row.get("current_hash", "")

    receipts = [r for row in chain if (r := _parse_receipt(row)) is not None]
    stats = _compute_stats(receipts)

    return {
        "valid": chain_ok and sigs_ok,
        "chain_ok": chain_ok,
        "sigs_ok": sigs_ok,
        "checked": len(chain),
        "errors": errors,
        "receipts": receipts,
        "stats": stats,
    }
