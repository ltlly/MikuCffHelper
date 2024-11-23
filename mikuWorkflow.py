from binaryninja import *


from .utils import log_error, log_info


def workflow_patch_llil(analysis_context: AnalysisContext):
    from .passes.spiltIfPass import pass_spilt_if_block
    from .passes.copyCommonBlockPass import pass_copy_common_block
    function = analysis_context.function
    llil = function.llil
    if llil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    pass_spilt_if_block(llil)
    log_info("spilt if block")
    pass_copy_common_block(llil)
    log_info("copy common block")

    return True


def workflow_patch_mlil(analysis_context: AnalysisContext):
    from .passes.reverseIfPass import pass_reverse_if
    from .passes.deflatHardPass import pass_deflat_hard
    function = analysis_context.function
    mlil = function.mlil
    if mlil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    pass_reverse_if(analysis_context)
    pass_deflat_hard(analysis_context)