"""
Silent Payments support for embit.

- bip352: BIP-352 protocol (address generation/decoding, output derivation)
- dleq:   BIP-374 Discrete Log Equality proofs
- fields: BIP-375 PSBT field data classes and exceptions
- ecdh:   ECDH share / DLEQ proof computation and input eligibility
- outputs: BIP-375 PSBT population and output derivation helpers
- validator: BIP-375 PSBT 4-stage validation pipeline
- psbt: SP-aware scopes, PSBT subclass, and signing orchestrator
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
from .outputs import (
    derive_silent_payment_outputs,
    populate_silent_payment_send_data,
    populate_silent_payment_send_data_from_keys,
    sign_sp_psbt,
)
from .validator import BIP375Validator, validate_bip375_psbt
from .psbt import SPInputScope, SPOutputScope, SilentPaymentsPSBT, SPSigner
from .finalizer import finalize_sp_spends
