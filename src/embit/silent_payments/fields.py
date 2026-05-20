"""
BIP-375 Silent Payment PSBT field definitions and exceptions.

Holds the data classes and error types used by the rest of the
silent_payments subpackage and by the PSBT signer integration.
"""

from typing import Optional

from .. import ec
from . import dleq


class SPFieldError(Exception):
    """Raised when SP field validation fails."""

    pass


class SPValidationError(Exception):
    """Raised when SP validation fails."""

    pass


class SilentPaymentData:
    """Represents PSBT_OUT_SP_V0_INFO field (scan key + spend key)."""

    def __init__(self, scan_key: ec.PublicKey, spend_key: ec.PublicKey):
        self.scan_key = scan_key
        self.spend_key = spend_key

    def serialize(self) -> bytes:
        """Serialize as 33-byte scan key + 33-byte spend key."""
        return self.scan_key.sec() + self.spend_key.sec()

    @classmethod
    def parse(cls, data: bytes) -> "SilentPaymentData":
        """Parse from 66 bytes (33-byte scan key + 33-byte spend key)."""
        if len(data) != 66:
            raise SPFieldError(f"PSBT_OUT_SP_V0_INFO must be 66 bytes, got {len(data)}")
        try:
            scan_key = ec.PublicKey.parse(data[:33])
            spend_key = ec.PublicKey.parse(data[33:66])
            return cls(scan_key, spend_key)
        except Exception as e:
            raise SPFieldError(f"Invalid SP data: {e}")


class ECDHShare:
    """Represents PSBT_IN_SP_ECDH_SHARE or PSBT_GLOBAL_SP_ECDH_SHARE field."""

    def __init__(self, scan_key: ec.PublicKey, share: bytes):
        """
        Args:
            scan_key: The scan key this share is for
            share: 33 bytes - the ECDH shared secret point C = a·B_scan
        """
        if len(share) != 33:
            raise SPFieldError(f"ECDH share must be 33 bytes, got {len(share)}")
        self.scan_key = scan_key
        self.share = share

    @property
    def share_pubkey(self) -> ec.PublicKey:
        """Get the ECDH share as a PublicKey."""
        return ec.PublicKey.parse(self.share)

    def serialize(self) -> bytes:
        """Serialize for use in PSBT field value."""
        return self.share


class DLEQProof:
    """Represents PSBT_IN_SP_DLEQ or PSBT_GLOBAL_SP_DLEQ field."""

    def __init__(self, scan_key: ec.PublicKey, proof: bytes):
        """
        Args:
            scan_key: The scan key this proof is for
            proof: 64 bytes - BIP-374 DLEQ proof
        """
        if len(proof) != 64:
            raise SPFieldError(f"DLEQ proof must be 64 bytes, got {len(proof)}")
        self.scan_key = scan_key
        self.proof = proof

    def serialize(self) -> bytes:
        """Serialize for use in PSBT field value."""
        return self.proof

    def verify(
        self,
        A: ec.PublicKey,
        B: ec.PublicKey,
        C: ec.PublicKey,
        m: Optional[bytes] = None,
    ) -> bool:
        """
        Verify this DLEQ proof.

        Args:
            A: Public key of the input (a·G)
            B: The scan key (B_scan)
            C: The ECDH share (a·B_scan)
            m: Optional message bound to the proof

        Returns:
            True if proof is valid, False otherwise
        """
        return dleq.verify_dleq_proof(A.sec(), B.sec(), C.sec(), self.proof, m=m)
