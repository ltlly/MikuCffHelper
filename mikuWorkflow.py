from binaryninja import *

from .passes.spiltIfPass import pass_spilt_if_block
from .utils import log_error, log_info


def workflow_patch_llil(analysis_context: AnalysisContext):
    function = analysis_context.function
    llil = function.llil
    if llil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    pass_spilt_if_block(llil)
    log_info("spilt if block")
    llil.finalize()
    llil.generate_ssa_form()
    return True
