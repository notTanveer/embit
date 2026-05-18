# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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
