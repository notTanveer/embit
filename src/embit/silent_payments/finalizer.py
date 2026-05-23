from collections import OrderedDict

from ..script import Witness


def finalize_sp_spends(psbt) -> int:
    """
    BIP-376 Finalizer: for each signed SP spend input, construct the final
    scriptwitness from taproot_key_sig and clear SP-specific fields.

    Returns number of inputs finalized.
    """
    count = 0
    for inp in psbt.inputs:
        if getattr(inp, "sp_tweak", None) is None:
            continue
        if inp.taproot_key_sig is None:
            continue
        inp.final_scriptwitness = Witness([inp.taproot_key_sig])
        inp.taproot_key_sig = None
        inp.sp_tweak = None
        inp.sp_spend_bip32_derivations = OrderedDict()
        count += 1
    return count
