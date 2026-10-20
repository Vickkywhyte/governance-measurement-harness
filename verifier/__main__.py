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
import datetime
import html
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

    html_path = Path("index.html")
    html_path.write_text(
        _build_html(result, db_path=db_path, tamper_mode=args.tamper),
        encoding="utf-8",
    )
    print(f"\n  Dashboard written to: {html_path.resolve()}")
    print(f"  Open with: open {html_path.resolve()}")

    return 0 if result["valid"] else 1


# ---------------------------------------------------------------------------
# HTML dashboard generator (stdlib only — no external deps)
# ---------------------------------------------------------------------------

_BUCKET_LABELS: dict[str, str] = {
    "deny":             "should_refuse",
    "allow":            "should_act",
    "require_approval": "should_escalate",
    "allow_with_flag":  "should_flag",
}

_BUCKET_COLORS: dict[str, str] = {
    "should_refuse":   "#ef4444",   # red
    "should_act":      "#22c55e",   # green
    "should_escalate": "#f59e0b",   # amber
    "should_flag":     "#6366f1",   # indigo
}

_DISP_LABELS: dict[str, str] = {
    "deny":             "deny",
    "allow":            "allow",
    "require_approval": "require_approval",
    "allow_with_flag":  "allow_with_flag",
}


def _pct(v: float | None) -> str:
    return f"{v * 100:.1f}%" if v is not None else "—"


def _status_badge(ok: bool, label_pass: str = "PASS", label_fail: str = "FAIL") -> str:
    cls = "badge-pass" if ok else "badge-fail"
    text = label_pass if ok else label_fail
    return f'<span class="{cls}">{text}</span>'


def _build_receipt_rows(receipts: list[dict]) -> str:
    rows = []
    for r in receipts:
        bucket = _BUCKET_LABELS.get(r["expected"], r["expected"])
        color  = _BUCKET_COLORS.get(bucket, "#888")
        ok     = r["expected"] == r["actual"]
        mark   = "✓" if ok else "✗"
        row_cls = "row-pass" if ok else "row-fail"
        rows.append(
            f'<tr class="{row_cls}">'
            f'<td class="mono">{html.escape(r["test_id"])}</td>'
            f'<td><span class="bucket-tag" style="background:{color}20;'
            f'color:{color};border:1px solid {color}40">{html.escape(bucket)}</span></td>'
            f'<td class="mono disp">{html.escape(r["expected"])}</td>'
            f'<td class="mono disp">{html.escape(r["actual"])}</td>'
            f'<td class="mark {"mark-pass" if ok else "mark-fail"}">{mark}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


def _build_bucket_bars(stats: dict) -> str:
    by_bucket = stats.get("by_bucket", {})
    bars = []
    order = ["deny", "allow", "require_approval", "allow_with_flag"]
    for exp in order:
        if exp not in by_bucket:
            continue
        bucket = _BUCKET_LABELS.get(exp, exp)
        color  = _BUCKET_COLORS.get(bucket, "#888")
        counts = by_bucket[exp]
        total  = counts["total"]
        correct = counts["correct"]
        pct_w  = int(correct / total * 100) if total else 0
        bars.append(
            f'<div class="bar-row">'
            f'  <div class="bar-label">{html.escape(bucket)}</div>'
            f'  <div class="bar-track">'
            f'    <div class="bar-fill" style="width:{pct_w}%;background:{color}"></div>'
            f'  </div>'
            f'  <div class="bar-count">{correct}/{total}</div>'
            f'</div>'
        )
    return "\n".join(bars)


def _build_html(result: dict, *, db_path: Path, tamper_mode: bool) -> str:
    valid    = result["valid"]
    chain_ok = result["chain_ok"]
    sigs_ok  = result["sigs_ok"]
    checked  = result["checked"]
    errors   = result.get("errors", [])
    receipts = result.get("receipts", [])
    stats    = result.get("stats", {})

    overall_color = "#16a34a" if valid else "#dc2626"
    overall_text  = "VALID" if valid else "INVALID"
    tamper_banner = (
        '<div class="tamper-banner">⚠ TAMPER DEMO MODE — chain was modified before verification</div>'
        if tamper_mode else ""
    )
    error_rows = "".join(
        f'<li class="error-item"><code>{html.escape(e)}</code></li>' for e in errors
    )
    error_section = (
        f'<div class="card errors-card"><h2>Chain errors</h2><ul>{error_rows}</ul></div>'
        if errors else ""
    )

    accuracy  = stats.get("accuracy")
    fo_rate   = stats.get("firing_offense_rate")
    fr_rate   = stats.get("friction_rate")
    acc_color = "#16a34a" if accuracy == 1.0 else "#dc2626"
    fo_color  = "#16a34a" if fo_rate == 0.0  else "#dc2626"
    fr_color  = "#16a34a" if fr_rate == 0.0  else "#dc2626"

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Chain Verifier</title>
<style>
  :root {{
    --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0;
    --text: #0f172a; --muted: #64748b; --mono: #1e293b;
    --pass: #16a34a; --fail: #dc2626;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      --bg:#0f172a;--card:#1e293b;--border:#334155;
      --text:#f1f5f9;--muted:#94a3b8;--mono:#e2e8f0;
    }}
  }}
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: system-ui, sans-serif; background: var(--bg); color: var(--text);
          line-height: 1.6; padding: 16px; }}
  .page {{ max-width: 860px; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; font-weight: 700; margin-bottom: 4px; }}
  h2 {{ font-size: 1rem; font-weight: 600; margin-bottom: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
  .meta {{ font-size: .85rem; color: var(--muted); margin-bottom: 24px; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px;
           padding: 20px 24px; margin-bottom: 16px; }}
  .overall-card {{ border-left: 5px solid {overall_color}; }}
  .overall-status {{ font-size: 2rem; font-weight: 800; color: {overall_color}; }}
  .badge-pass {{ display:inline-block;padding:2px 10px;border-radius:999px;font-size:.8rem;
                 font-weight:700;background:#dcfce7;color:#15803d;border:1px solid #bbf7d0; }}
  .badge-fail {{ display:inline-block;padding:2px 10px;border-radius:999px;font-size:.8rem;
                 font-weight:700;background:#fee2e2;color:#b91c1c;border:1px solid #fecaca; }}
  .integrity-grid {{ display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px; }}
  .integrity-item {{ background:var(--bg);border:1px solid var(--border);border-radius:8px;
                     padding:12px 16px; }}
  .integrity-item .label {{ font-size:.8rem;color:var(--muted);margin-bottom:4px; }}
  .stats-grid {{ display:grid;grid-template-columns:repeat(3,1fr);gap:12px; }}
  @media(max-width:540px){{ .stats-grid,.integrity-grid{{grid-template-columns:1fr;}} }}
  .stat-card {{ background:var(--bg);border:1px solid var(--border);border-radius:8px;
                padding:16px;text-align:center; }}
  .stat-value {{ font-size:1.8rem;font-weight:800;line-height:1; }}
  .stat-label {{ font-size:.78rem;color:var(--muted);margin-top:4px; }}
  .bar-row {{ display:flex;align-items:center;gap:10px;margin-bottom:10px; }}
  .bar-label {{ width:160px;font-size:.82rem;color:var(--muted);flex-shrink:0; }}
  .bar-track {{ flex:1;height:16px;background:var(--border);border-radius:999px;overflow:hidden; }}
  .bar-fill {{ height:100%;border-radius:999px;transition:width .4s; }}
  .bar-count {{ width:40px;text-align:right;font-size:.82rem;font-weight:600;color:var(--muted); }}
  table {{ width:100%;border-collapse:collapse;font-size:.88rem; }}
  th {{ text-align:left;padding:8px 10px;border-bottom:2px solid var(--border);
        font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted); }}
  td {{ padding:8px 10px;border-bottom:1px solid var(--border); }}
  tr:last-child td {{ border-bottom:none; }}
  .row-pass td {{ background:transparent; }}
  .row-fail td {{ background:#fff1f2; }}
  @media (prefers-color-scheme:dark) {{
    :root:not([data-theme="light"]) .row-fail td {{ background:#2d1515; }}
  }}
  .mono {{ font-family: ui-monospace, monospace; }}
  .disp {{ font-size:.82rem; }}
  .mark {{ font-size:1rem;font-weight:700;text-align:center; }}
  .mark-pass {{ color:var(--pass); }}
  .mark-fail {{ color:var(--fail); }}
  .bucket-tag {{ padding:2px 8px;border-radius:999px;font-size:.75rem;font-weight:600; }}
  .errors-card {{ border-left:4px solid var(--fail); }}
  .errors-card h2 {{ color:var(--fail); }}
  .error-item {{ margin:4px 0 4px 16px;font-size:.82rem; }}
  .tamper-banner {{ background:#fef3c7;border:1px solid #fde68a;color:#92400e;
                    padding:10px 16px;border-radius:8px;margin-bottom:16px;font-weight:600; }}
  @media (prefers-color-scheme:dark) {{
    :root:not([data-theme="light"]) .tamper-banner {{
      background:#2d1f00;border-color:#78350f;color:#fde68a;
    }}
  }}
  .records-note {{ font-size:.8rem;color:var(--muted);margin-top:6px; }}
</style>
</head>
<body>
<div class="page">

  {tamper_banner}

  <div class="card overall-card">
    <h1>Chain Verifier</h1>
    <p class="meta">Generated {timestamp} &nbsp;·&nbsp; DB: <code>{html.escape(str(db_path))}</code>
       &nbsp;·&nbsp; {checked} records</p>
    <div class="overall-status">{overall_text}</div>
    <div class="integrity-grid" style="margin-top:16px">
      <div class="integrity-item">
        <div class="label">Chain Integrity</div>
        {_status_badge(chain_ok)}
      </div>
      <div class="integrity-item">
        <div class="label">Signature Validity</div>
        {_status_badge(sigs_ok)}
      </div>
    </div>
  </div>

  {error_section}

  <div class="card">
    <h2>Measurement stats</h2>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value" style="color:{acc_color}">{_pct(accuracy)}</div>
        <div class="stat-label">Accuracy<br>({stats.get("correct","—")}/{stats.get("total","—")} correct)</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:{fo_color}">{_pct(fo_rate)}</div>
        <div class="stat-label">Firing-offense rate<br>(target: 0.0%)</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:{fr_color}">{_pct(fr_rate)}</div>
        <div class="stat-label">Friction rate<br>(target: 0.0%)</div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Results by bucket</h2>
    {_build_bucket_bars(stats)}
  </div>

  <div class="card">
    <h2>Test cases ({len(receipts)})</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th><th>Bucket</th><th>Expected</th><th>Actual</th><th>Result</th>
        </tr>
      </thead>
      <tbody>
        {_build_receipt_rows(receipts)}
      </tbody>
    </table>
    <p class="records-note">Chain contains {checked} total records
      ({checked - len(receipts)} non-harness runtime records).</p>
  </div>

</div>
</body>
</html>"""


if __name__ == "__main__":
    sys.exit(main())
