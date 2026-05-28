"""
Silent Payments support for embit.

- bip352: BIP-352 protocol (address generation/decoding, output derivation)
- dleq:   BIP-374 Discrete Log Equality proofs
- fields: BIP-375 PSBT field data classes and exceptions
- ecdh:   ECDH share / DLEQ proof computation and input eligibility
- outputs: BIP-375 output derivation helper
- validator: BIP-375 PSBT 4-stage validation pipeline
- psbt: SP-aware scopes and PSBT subclass with the sign_with() SP hook
"""

from . import bip352
from . import dleq
from .fields import (
    SPFieldError,
    SPValidationError,
    SilentPaymentData,
    ECDHShare,
    DLEQProof,
)
from .ecdh import (
    compute_ecdh_share,
    compute_global_ecdh_share,
    compute_dleq_proof,
    compute_global_dleq_proof,
    get_eligible_inputs,
)
from .outputs import derive_silent_payment_outputs
from .validator import BIP375Validator, validate_bip375_psbt
from .psbt import SPInputScope, SPOutputScope, SilentPaymentsPSBT
from .finalizer import finalize_sp_spends
