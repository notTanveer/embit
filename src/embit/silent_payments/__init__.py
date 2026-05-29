"""
Silent Payments support for embit.

- bip352: BIP-352 protocol (address generation/decoding, output derivation)
- dleq:   BIP-374 Discrete Log Equality proofs
- fields: BIP-375 PSBT field data classes and exceptions
- ecdh:   ECDH share / DLEQ proof computation and input eligibility
- validator: BIP-375 PSBT 4-stage validation pipeline
- psbt: SP-aware scopes, PSBT subclass with the sign_with() SP hook, and
        the BIP-376 finalize_sp_spends finalizer
"""

from . import bip352
from . import dleq
from .fields import (
    SPFieldError,
    SPValidationError,
    SilentPaymentData,
)
from .ecdh import (
    compute_ecdh_share,
    compute_global_ecdh_share,
    compute_dleq_proof,
    compute_global_dleq_proof,
    get_eligible_inputs,
)
from .bip352 import derive_silent_payment_outputs
from .validator import BIP375Validator, validate_bip375_psbt
from .psbt import (
    SPInputScope,
    SPOutputScope,
    SilentPaymentsPSBT,
    finalize_sp_spends,
)

__all__ = [
    "bip352",
    "dleq",
    "SPFieldError",
    "SPValidationError",
    "SilentPaymentData",
    "compute_ecdh_share",
    "compute_global_ecdh_share",
    "compute_dleq_proof",
    "compute_global_dleq_proof",
    "get_eligible_inputs",
    "derive_silent_payment_outputs",
    "BIP375Validator",
    "validate_bip375_psbt",
    "SPInputScope",
    "SPOutputScope",
    "SilentPaymentsPSBT",
    "finalize_sp_spends",
]
