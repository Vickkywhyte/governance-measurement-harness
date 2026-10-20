"""Statistical aggregation over harness run results."""

from __future__ import annotations

from typing import Any


def summarise(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate measurement receipts into a summary report.

    Returns a dict with:
        total       — number of vectors run
        passed      — vectors where actual == expected
        failed      — vectors where actual != expected
        pass_rate   — passed / total (0.0–1.0)
        by_bucket   — per-bucket breakdown {bucket: {total, passed, failed}}
        failures    — list of {test_id, bucket, expected, actual, rationale}
                      for every non-matching vector
    """
    total = len(receipts)
    passed = sum(1 for r in receipts if r["match"])
    failed = total - passed

    by_bucket: dict[str, dict[str, int]] = {}
    for r in receipts:
        bucket = r["bucket"]
        entry = by_bucket.setdefault(bucket, {"total": 0, "passed": 0, "failed": 0})
        entry["total"] += 1
        if r["match"]:
            entry["passed"] += 1
        else:
            entry["failed"] += 1

    failures = [
        {
            "test_id": r["test_id"],
            "bucket": r["bucket"],
            "expected": r["expected"],
            "actual": r["actual"],
            "rationale": r.get("rationale", ""),
        }
        for r in receipts
        if not r["match"]
    ]

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": passed / total if total else 0.0,
        "by_bucket": by_bucket,
        "failures": failures,
    }


def format_report(summary: dict[str, Any]) -> str:
    """Render a summary dict as a human-readable console report."""
    lines: list[str] = []
    pct = summary["pass_rate"] * 100
    lines.append("=" * 56)
    lines.append("  Governance Measurement Harness — Run Report")
    lines.append("=" * 56)
    lines.append(
        f"  Result : {summary['passed']}/{summary['total']} passed  ({pct:.1f}%)"
    )
    lines.append("")
    lines.append("  By bucket:")
    for bucket, counts in sorted(summary["by_bucket"].items()):
        mark = "✓" if counts["failed"] == 0 else "✗"
        lines.append(
            f"    {mark}  {bucket:<22}  "
            f"{counts['passed']}/{counts['total']} passed"
        )
    if summary["failures"]:
        lines.append("")
        lines.append("  Failures:")
        for f in summary["failures"]:
            lines.append(f"    ✗  {f['test_id']}")
            lines.append(f"       expected : {f['expected']}")
            lines.append(f"       actual   : {f['actual']}")
            lines.append(f"       rationale: {f['rationale']}")
    lines.append("=" * 56)
    return "\n".join(lines)
