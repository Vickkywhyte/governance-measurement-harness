"""Measurement harness runner.

Loads test vectors, evaluates each through the compliance runtime, records
a signed measurement receipt on the evidence chain, and returns the full
receipt list for statistical analysis.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import compliance_runtime

_VECTORS_DIR = Path(__file__).parent / "vectors"
_CHAIN_DB = Path("test_chain.db")

# Resolve the policy directory from the installed compliance_runtime package.
# compliance_runtime.__file__ → .../src/compliance_runtime/__init__.py
# Walking up three levels reaches the repo root where configs/policies lives.
_RUNTIME_ROOT = Path(compliance_runtime.__file__).parent.parent.parent
_DEFAULT_POLICY_DIR = _RUNTIME_ROOT / "configs" / "policies"


def run(
    vectors_dir: Path = _VECTORS_DIR,
    chain_db: Path = _CHAIN_DB,
    policy_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Run all vectors and return the list of measurement receipts.

    For each vector the runner:
    1. Calls ``evaluate_action`` with the vector's action and optional context.
    2. Compares the actual disposition to the vector's ``expected`` field.
    3. Appends a signed receipt entry to the evidence chain via
       ``append_measurement``.
    4. Collects and returns all receipts.

    Args:
        vectors_dir: Directory containing ``*.json`` test vector files.
        chain_db: Path to the SQLite chain DB.  The caller is responsible
                  for deleting it before each run to start a fresh chain.
        policy_dir: Path to the YAML policy directory.  Defaults to the
                    ``configs/policies`` directory inside the installed
                    compliance-runtime package tree.
    """
    resolved_policy_dir: Path = policy_dir or _DEFAULT_POLICY_DIR
    vectors = _load_vectors(vectors_dir)
    receipts: list[dict[str, Any]] = []

    for vector in vectors:
        action_block: dict[str, Any] = vector["action"]
        context: dict[str, Any] | None = vector.get("context")

        actual: str = compliance_runtime.evaluate_action(
            action=action_block["tool"],
            parameters=action_block["parameters"],
            context=context,
            policy_dir=resolved_policy_dir,
        )

        expected: str = vector["expected"]
        match: bool = actual == expected

        receipt: dict[str, Any] = {
            "test_id": vector["id"],
            "bucket": vector["bucket"],
            "expected": expected,
            "actual": actual,
            "match": match,
            "rationale": vector.get("rationale", ""),
        }

        # Encode test_id, expected, and actual into the action string so the
        # standalone verifier can reconstruct stats without importing this package.
        # Format: "harness_receipt:<test_id>:<expected>:<actual>"
        compliance_runtime.append_measurement(
            db_path=chain_db,
            entry={
                "action": f"harness_receipt:{vector['id']}:{expected}:{actual}",
                "disposition": actual,
            },
        )

        receipts.append(receipt)

    return receipts


def _load_vectors(vectors_dir: Path) -> list[dict[str, Any]]:
    """Load and sort all ``*.json`` files in *vectors_dir* by filename."""
    paths = sorted(vectors_dir.glob("*.json"))
    if not paths:
        raise FileNotFoundError(f"No .json vectors found in {vectors_dir}")
    return [json.loads(p.read_text(encoding="utf-8")) for p in paths]
