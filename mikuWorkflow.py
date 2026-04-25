from binaryninja import AnalysisContext

from .passes.low.spiltIfPass import pass_spilt_if_block
from .passes.low.copyCommonBlockPass import pass_copy_common_block
from .passes.low.inlineIfCondPass import pass_inline_if_cond
from .passes.mid.deflatHardPass import pass_deflate_hard
from .passes.mid.clearPass import pass_clear
from .passes.mid.movStateDefine import pass_mov_state_define


def workflow_patch_llil(analysis_context: AnalysisContext):
    if analysis_context.function.llil is None:
        return
    # 块复制让公共后继成为各前驱独占的块，便于上层符号执行；
    # 标志位内联消除 LLIL 标志中转，让条件直接出现在 if 中；
    # if 单独成块是后续 MLIL/HLIL 形状的常见前置。
    pass_copy_common_block(analysis_context)
    pass_inline_if_cond(analysis_context)
    pass_spilt_if_block(analysis_context)


def workflow_patch_mlil(analysis_context: AnalysisContext):
    if analysis_context.function.mlil is None:
        return
    # 1) clear: 折叠常量 if、连续 goto，规整图结构
    # 2) mov_state_define: 把状态常量赋值移到块尾，方便前向模拟
    # 3) deflate_hard: 前向符号执行，把状态机分发短路成直接 goto
    # 第一遍 deflate 之后再 clear+mov+deflate 一次：第一遍会把外层
    # 状态机短路掉，结构变化后内层状态机的 define 位置 / 形态变化，
    # 第二遍能够吃到剩余的转移。
    pass_clear(analysis_context)
    pass_mov_state_define(analysis_context)
    pass_deflate_hard(analysis_context)
    pass_clear(analysis_context)
    pass_mov_state_define(analysis_context)
    pass_deflate_hard(analysis_context)
    pass_clear(analysis_context)


def workflow_patch_hlil(analysis_context: AnalysisContext):
    from .utils import suggest_stateVar

    suggest_stateVar(analysis_context.view, analysis_context.function)
