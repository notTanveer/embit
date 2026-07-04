"""Silent Payments (BIP-352/374/375/376): addresses, ECDH shares, DLEQ proofs, and PSBT support."""

from . import bip352
from . import dleq
from .fields import (
    SPFieldError,
    SPValidationError,
    SilentPaymentData,
)
from .bip352 import (
    compute_ecdh_share,
    compute_global_ecdh_share,
    derive_outputs_for_keys,
    normalize_xonly_keys,
)
from .ecdh import (
    compute_dleq_proof,
    compute_global_dleq_proof,
    get_eligible_inputs,
)
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
    "derive_outputs_for_keys",
    "normalize_xonly_keys",
    "BIP375Validator",
    "validate_bip375_psbt",
    "SPInputScope",
    "SPOutputScope",
    "SilentPaymentsPSBT",
    "finalize_sp_spends",
]
