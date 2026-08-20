# Silent Payments V2 — PSBT Interop Report

Repo: `notTanveer/embit` · Branch under test: `feat/silent-payments-V2` @ `839c5ab`
Tool: [psbt-interop-lab](https://github.com/GautamBytes/psbt-interop-lab) `0.10.1`
Date: 2026-08-20

## Summary

| | |
|---|---:|
| embit unit tests (BIP-352/375/PSBTv2 suites) | 183 passed, 0 failed |
| Differential fuzz cases run | 2,560 |
| Agreement with reference parser | 2,557 / 2,560 (99.9%) |
| Crashes / hangs | 0 |
| Real parser bug found | 1 |
| Known BIP-375 gap | 1 |

## What was actually run

This environment has no Docker daemon, so psbt-interop-lab's containerized
`matrix` / `quickstart` commands — and every scenario that depends on
Bitcoin Core regtest or another library's container (BIP-375 sender / BIP-376
receiver-spend through `rust-psbt-v2`, MuSig2, cross-library signing) —
could not run. See [Not covered](#not-covered) below.

What the lab *can* run without Docker still gave a real, adversarial signal:
its parser-conformance checker, its local roundtrip matrix, and its seeded
differential mutation fuzzer. To reach those, a small Python adapter was
written speaking the lab's `psbt-lab.adapter/0.2` protocol, calling embit's
own `PSBT.from_base64` / `to_base64` directly — no reimplementation, no
mocks. (The adapter is throwaway test scaffolding built for this report; it
is not part of the embit repository.)

| Check | Needs Docker | Run |
|---|---|---|
| Adapter protocol conformance (`adapter check`) | No | ✅ ran |
| Local roundtrip matrix, PSBTv0 + PSBTv2 (`parse-matrix`) | No | ✅ ran |
| Differential mutation fuzzing (`fuzz --runtime local`) | No | ✅ ran — 2,560 cases |
| embit's own BIP-352/375 vectors, cross-checked against the lab's pinned corpus | No | ✅ ran |
| BIP-375 sender / BIP-376 receiver-spend via `rust-psbt-v2` | Yes | ⬜ unavailable here |
| Cross-library signing, MuSig2, HWI simulator | Yes | ⬜ unavailable here |

## Parser conformance

The adapter was run through the lab's full baseline profile plus its local
roundtrip matrix, against `src/embit/psbt.py` on the branch:

| Check | Result |
|---|---|
| Protocol handshake & self-reported identity | PASS |
| Native parse — accepts a valid PSBT | PASS |
| Native parse — rejects malformed bytes | PASS |
| Roundtrip preserves every field, byte-identical | PASS |
| BIP-174 minimal PSBTv0 fixture, byte-identical roundtrip | PASS |
| BIP-370 PSBTv2 fixture, byte-identical roundtrip | PASS |

Every other adapter in this run (`rust-bitcoin`, `btcsuite-go`, `bdkpython`,
`rust-psbt-v2`, `bdk-wallet-current`) reported `unsupported` — their native
bundles aren't published for this platform without Docker. The only
implementations actually exercised side-by-side were embit and the lab's
bundled reference JS parser, plus the differential fuzzer below.

## Differential fuzzing

2 fixtures (PSBTv0 and PSBTv2) × 5 seeds × 256 bounded mutation cases each —
byte flips, field truncation, duplicate keys, out-of-range values — fed to
embit and to the lab's reference parser in parallel: 2,560 cases total,
2,557 agreed, 0 uncaught exceptions in embit. 3 divergences, all explained:

### Bug: truncated global transaction is silently accepted

Mutating `PSBT_GLOBAL_UNSIGNED_TX` to cut its last few bytes should make the
locktime field unreadable. The reference parser rejects it
(`"unsigned transaction locktime: truncated data"`); embit parses it anyway,
treating the short read as `locktime = 0` and re-padding it on serialize.

Root cause: `src/embit/transaction.py:164` and `:183` call `stream.read(4)`
and pass the result straight to `int.from_bytes` without checking the read
actually returned 4 bytes. A short read degrades silently instead of raising.

### By design: negative `PSBT_OUT_AMOUNT` — embit is stricter, not wrong

2 cases set a PSBTv2 output's signed 64-bit amount to a negative value.
embit rejects it at parse time (`src/embit/psbt.py:803`,
`"PSBT_OUT_AMOUNT must be non-negative"`); the lab's reference parser
accepts it as structurally valid and defers the semantic check. Worth
knowing for interop — a peer that constructs a PSBT with a placeholder
negative amount will be turned away by embit earlier than by other
implementations — but this is embit doing eager validation, not a defect.

## BIP-375 Silent Payments vectors

embit bundles the official BIP-375 test-vector corpus at
`tests/tests/data/bip375_test_vectors.json`, driven end-to-end (parse →
`validate_sp()` → re-derive outputs) by `tests/tests/test_bip375.py`. The
lab pins the same corpus internally for its own
`bip375-official-reference-vectors` scenario.

- **Confirmed same corpus, same shape.** 19 valid + 22 invalid vectors on
  both sides; vector `valid-01`'s base64 payload is byte-identical between
  embit's bundled copy (version `1.1.1`) and the lab's pinned copy (version
  `1.1`) of the upstream BIP-375 generator output.
- **Known gap: per-input ECDH shares unparsed.** `PSBT_IN_SP_ECDH_SHARE`
  (0x1d) and `PSBT_IN_SP_DLEQ` (0x1e) aren't parsed yet (flagged in-code at
  `src/embit/silent_payments/psbt.py:98`). 5 of the 22 invalid vectors that
  specifically probe those fields are excluded from the branch's own
  rejection test rather than actually verified.

## Not covered here

Without Docker, none of the lab's containerized scenarios ran. Most
relevant to this branch, for a follow-up run with Docker available:

- `silent-payment-interop`: `bip375-sender-workflow-rust-psbt-v2`,
  `bip375-advanced-sender-workflows-rust-psbt-v2`,
  `bip376-spend-workflow-rust-psbt-v2` — the actual cross-implementation
  Silent Payments handoffs.
- Taproot key-path/script-path, MuSig2 (BIP-373), and HWI-simulator signing
  scenarios.
- Any scenario needing Bitcoin Core policy verification on regtest.

## Recommendations

1. **Fix the short-read bug.** Validate the length returned by
   `stream.read(n)` before `int.from_bytes` in `transaction.py` (at least
   lines 164 and 183) so truncated transactions raise instead of silently
   zero-filling.
2. **Close the per-input ECDH gap.** Parsing `PSBT_IN_SP_ECDH_SHARE` /
   `PSBT_IN_SP_DLEQ` would let the 5 currently-excluded BIP-375 vectors run
   for real, and matches what the lab's own validator already checks for.
3. **Contribute an embit adapter upstream.** embit has no adapter in
   psbt-interop-lab today — it's invisible to the project's cross-language
   matrix even though rust-psbt-v2, libwally, and others are represented.
   The proof-of-concept adapter built for this report (parser role only,
   PSBTv0 + PSBTv2) is a reasonable seed for a real one with a signer role
   added.
4. **Re-run with Docker.** The BIP-375/376 scenarios above are the ones
   that actually test Silent Payments PSBT interop against another
   implementation; everything in this report is embit tested against
   itself and against a bundled reference parser, not against
   `rust-psbt-v2` or `libwally` directly.
