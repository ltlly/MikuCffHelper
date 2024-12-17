from binaryninja import *

from .utils import log_error, log_info


def workflow_patch_llil(analysis_context: AnalysisContext):
    from .passes.low.spiltIfPass import pass_spilt_if_block
    from .passes.low.copyCommonBlockPass import pass_copy_common_block
    from .passes.low.inlineIfCondPass import pass_inline_if_cond
    function = analysis_context.function
    llil = function.llil
    if llil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    pass_inline_if_cond(analysis_context)
    log_info("inline if cond")
    pass_spilt_if_block(analysis_context)
    log_info("spilt if block")
    pass_copy_common_block(analysis_context)
    log_info("copy common block")

    return True


def workflow_patch_mlil(analysis_context: AnalysisContext):
    from .passes.mid.reverseIfPass import pass_reverse_if
    from .passes.mid.deflatHardPass import pass_deflate_hard
    function = analysis_context.function
    mlil = function.mlil
    if mlil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    pass_reverse_if(analysis_context)
    pass_deflate_hard(analysis_context)
