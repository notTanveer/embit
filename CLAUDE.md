# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Cheap-Worker Delegation Tools (Token Saving)

Three CLI tools delegate bulk I/O to a cheap worker model. Use them to save tokens.

### ask-kimi — bulk reading
For reading files >400 lines, or when you'd otherwise read 3+ files:

```bash
ask-kimi --paths <file1> <file2>... --question "<specific question>"
```

Returns a structured summary. Use that instead of reading files yourself.
Only read files directly when you need to make edits to specific lines.

### kimi-write — boilerplate generation
For generating tests, config files, docstrings, or repetitive code patterns:

```bash
kimi-write --spec "<what to write>" --context <existing-similar-file> --target <output-path>
```

Then review the output and edit only what needs fixing.

### extract-chat — chat transcript extraction
Extracts human-readable text from Claude Code JSONL transcripts:

```bash
extract-chat <session.jsonl> -o /tmp/chat.txt
```

### Documentation workflow (MANDATORY)
**NEVER write documentation directly. Always delegate:**

1. Extract chat: `extract-chat <latest-session.jsonl> -o /tmp/chat.txt`
2. Ask worker to read chat + existing docs and suggest updates:
   `ask-kimi --paths /tmp/chat.txt <doc-files> --question "read chat, give exact changes for docs"`
3. Apply the worker's changes via Edit tool

### When NOT to delegate
- Tasks under ~2000 tokens of work (delegation overhead isn't worth it)
- Architectural decisions, debugging, safety-critical code
- Anything requiring careful reasoning
- When exact line numbers are needed for editing

## Commands

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run a single test file
pytest tests/tests/test_psbt.py

# Run a single test method
pytest tests/tests/test_psbt.py::TestClass::test_method_name

# Run tests on MicroPython
cd tests && micropython ./run_tests.py

# Lint/format
black .
ruff check .
mypy src/embit
```

## Architecture

**embit** is a minimal Bitcoin library targeting both Python 3.10+ and MicroPython (embedded systems). All cryptographic operations have pure-Python fallbacks — the optional system `libsecp256k1` is used when available via ctypes (`src/embit/util/secp256k1.py`).

Source lives under `src/embit/`. Key layers:

**Cryptography & Keys**
- `ec.py` — secp256k1 signatures (`Signature`, `SchnorrSig`), bound to secp256k1 lib
- `bip32.py` — HD key derivation (`HDKey`)
- `bip39.py` — mnemonic seed phrases
- `dleq.py` — discrete log equality proofs (BIP-374)

**Transactions & Scripts**
- `script.py` — script construction and address types (p2pkh, p2wpkh, p2tr, etc.)
- `transaction.py` — raw transaction serialization/parsing
- `psbt.py` — PSBT v1/v2 (BIP-174/BIP-370); `psbtview.py` for read-only analysis; `finalizer.py` for finalization
- `bip375_validator.py` — BIP-375 PSBT validation

**Higher-level Protocols**
- `descriptor/` — output descriptors and miniscript (`descriptor.py`, `miniscript.py`, `taptree.py`)
- `silent_payments/` + `bip352.py` — Silent Payments protocol
- `slip39.py` — SLIP-39 Shamir secret sharing
- `liquid/` — Liquid Network support (PSET, blech32, blip32); mirrors the main Bitcoin module structure

**Encoding**
- `base58.py`, `bech32.py`, `hashes.py`, `compact.py`

**Base classes** (`base.py`): `EmbitBase` defines the `serialize`/`parse` contract used throughout. All domain objects inherit from it.

## Testing Notes

Tests are in `tests/tests/` and use a custom `unittest.py` runner (`tests/unittest.py`) that is compatible with both CPython and MicroPython. Standard `pytest` works on CPython; use `micropython run_tests.py` for embedded target testing.

Test vectors for BIP standards (BIP-374, BIP-375, BIP-370) are in `tests/tests/vectors/`.
