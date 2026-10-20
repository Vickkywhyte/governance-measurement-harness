# Governance Measurement Harness

> Governance vendors give you controls. This gives you a way to check if the controls work — with receipts an auditor can verify without trusting you.

Most AI governance tools are black boxes. They promise to enforce policy, but when an auditor asks *"how do I know it actually worked?"*, the honest answer is usually: *"trust us."*

This harness changes that. It:

1. **Runs a labeled test suite** against a live compliance runtime, recording what the policy engine actually decided for each action.
2. **Commits every result to a signed, hash-chained evidence log** — the same cryptographic chain the runtime uses for production decisions.
3. **Ships a standalone verifier** that an auditor can run on any machine with Python and `cryptography`. No access to your codebase. No trust required.

---

## How it works

```
┌─────────────────────────────────────────────────────┐
│  python -m harness                                   │
│                                                      │
│  Load 12 test vectors (harness/vectors/*.json)       │
│         │                                            │
│         ▼                                            │
│  compliance_runtime.evaluate_action()                │
│  (live policy engine — no mock)                      │
│         │                                            │
│         ▼                                            │
│  Compare actual disposition to expected              │
│         │                                            │
│         ▼                                            │
│  compliance_runtime.append_measurement()             │
│  → SHA-256 hash-chained, Ed25519-signed receipt      │
│    written to chain.db                               │
│         │                                            │
│         ▼                                            │
│  Print report (accuracy, firing-offense rate,        │
│  friction rate, per-bucket results)                  │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  python -m verifier --db chain.db --pubkey key.pem  │
│                                                      │
│  (stdlib + cryptography ONLY — zero runtime imports) │
│                                                      │
│  Recompute every SHA-256 hash from raw DB rows       │
│  Verify every Ed25519 signature                      │
│  Extract measurement receipts from action field      │
│  Recalculate accuracy / firing-offense / friction    │
│  Print independent verification report               │
└─────────────────────────────────────────────────────┘
```

The verifier is **completely independent**. It imports nothing from `harness` or `compliance_runtime`. An auditor can copy `verifier/` to a fresh machine, `pip install cryptography`, and run it against the DB and public key you hand them — and they will arrive at the same numbers you reported.

---

## Test vectors

12 labeled vectors across four buckets:

| Bucket | Count | Expected disposition | Example |
|---|---|---|---|
| `should_refuse` | 3 | `deny` | mass record deletion, bulk PII export to external FTP, unscoped account suspension |
| `should_act` | 3 | `allow` | single-record support lookup, balance query, bounded transaction history |
| `should_escalate` | 3 | `require_approval` | salary update, large funds transfer (>€10k), credit limit increase |
| `should_flag` | 3 | `allow_with_flag` | off-hours read, repeated exports, PII access with no linked ticket |

Vectors are plain JSON files in `harness/vectors/`. Adding a new vector is one file.

---

## Quick start

```bash
# Install (with compliance-runtime available in your environment)
pip install -e .

# Run the harness — produces chain.db and keys/
python -m harness --keys-dir ./keys --db ./chain.db

# Verify independently — no harness or runtime imports used
python -m verifier --db ./chain.db --pubkey ./keys/verification_key.pem
```

### Expected output

**Harness:**
```
========================================================
  Governance Measurement Harness — Run Report
========================================================
  Result : 12/12 passed  (100.0%)

  By bucket:
    ✓  should_act              3/3 passed
    ✓  should_escalate         3/3 passed
    ✓  should_flag             3/3 passed
    ✓  should_refuse           3/3 passed
========================================================
```

**Verifier:**
```
========================================================
  Chain Verifier
========================================================
  DB            : chain.db
  Records       : 12
  Chain Integrity   : PASS
  Signature Validity: PASS

  Measurement receipts : 12
  Accuracy             : 100.0%  (12/12)
  Firing-offense rate  : 0.0%  (should be 0.0%)
  Friction rate        : 0.0%  (should be 0.0%)

  By expected disposition:
    ✓  allow                   3/3
    ✓  allow_with_flag         3/3
    ✓  deny                    3/3
    ✓  require_approval        3/3
========================================================
  Overall: VALID
```

---

## Tamper demo

Pass `--tamper` to prove the chain catches any modification. The verifier copies the DB, flips one byte in the first record's `disposition` field, and runs verification — the hash-chain and signature checks both fail.

```bash
python -m verifier \
  --db ./chain.db \
  --pubkey ./keys/verification_key.pem \
  --tamper
```

Expected output (abbreviated):
```
  [TAMPER MODE] Copying DB and flipping one byte...
  [TAMPER] Binary edit on action='harness_receipt:safety-001:deny:deny', rowid=1:
           Replaced 4 occurrence(s) of current_hash in raw bytes.
           current_hash[0]: '7' → 'b'
           stored hash now: b4be3be974231d05…  (was: 74be3be974231d05…)

  Chain Integrity   : FAIL
  Signature Validity: FAIL
  Errors:
    ✗  record[0] ...: current_hash mismatch (recomputed 74be3b…, stored b4be3b…)
    ✗  record[0] ...: signature invalid
    ✗  record[1] ...: current_hash mismatch (recomputed 3c50cd…, stored 20e253…)
    ...
  Overall: INVALID
```

Note that modifying record[0]'s hash cascades: record[1]'s `previous_hash` now doesn't match the (tampered) `current_hash` of record[0], which breaks record[1]'s own recomputed hash too. **One flipped byte invalidates the entire tail of the chain.**

The tamper operates at the raw binary file level (replacing all B-tree and index copies of the hash), proving that the chain survives even a sophisticated file-level edit. The original `chain.db` is untouched — `--tamper` operates on a temporary copy.

---

## Architecture

```
governance-measurement-harness/
├── harness/
│   ├── vectors/          # 12 labeled JSON test cases
│   ├── runner.py         # load vectors → evaluate → append to chain
│   ├── stats.py          # accuracy / firing-offense / friction aggregation
│   └── __main__.py       # CLI: python -m harness [--keys-dir] [--db]
└── verifier/
    ├── verify.py         # pure stdlib + cryptography — zero project imports
    └── __main__.py       # CLI: python -m verifier --db --pubkey [--tamper]
```

**Key design decision:** `verifier/` has zero imports from `harness` or `compliance_runtime`. This is not a style choice — it is the entire point. An independent verifier that shares code with the system it verifies isn't independent. The isolation is enforced by a comment at the top of each file and verified by the fact that it runs on a clean install with `pip install cryptography` alone.

---

## Stats definitions

| Metric | Definition |
|---|---|
| **Accuracy** | Correct dispositions ÷ total vectors |
| **Firing-offense rate** | Actions that *should* have been `deny`/`require_approval` but were not ÷ total dangerous vectors. A non-zero rate means the policy let through something it should have stopped — a compliance incident waiting to happen. |
| **Friction rate** | Actions that *should* have been `allow` but were blocked ÷ total safe vectors. Non-zero means the policy is generating unnecessary friction for legitimate operations. |

---

## Requirements

- Python ≥ 3.11
- `compliance-runtime` (for the harness runner)
- `cryptography ≥ 42.0` (for the verifier — and transitively for the harness)

The verifier itself only needs `cryptography` and Python stdlib.

---

## License

MIT
