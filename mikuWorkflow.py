from binaryninja import AnalysisContext

from .passes.low.spiltIfPass import pass_spilt_if_block
from .passes.low.copyCommonBlockPass import pass_copy_common_block
from .passes.low.inlineIfCondPass import pass_inline_if_cond
from .passes.mid.deflatHardPass import pass_deflate_hard
from .passes.mid.clearPass import pass_clear
from .passes.mid.movStateDefine import pass_mov_state_define
from .passes.mid.synthesizeSwitchPass import pass_synthesize_switch


def workflow_patch_llil(analysis_context: AnalysisContext):
    if analysis_context.function.llil is None:
        return
    # pass_copy_common_block 内部已加 LLIL 层 CFF 嗅探 (_llil_function_likely_cff)
    # + 单块大小阈值 + 总块数额度上限三重保险，正常函数通常不会被它影响
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


def workflow_patch_mlil_switch(analysis_context: AnalysisContext):
    """互斥的 deflate 替代路径：把 dispatcher 重构为 MLIL JUMP_TO，让 BN
    HLIL restructurer 显示成 switch-case 结构。

    与 workflow_patch_mlil 互斥：用户只应启用其中一个 (UI 里的 eligibility
    切换)。
    """
    if analysis_context.function.mlil is None:
        return
    pass_clear(analysis_context)
    pass_mov_state_define(analysis_context)
    pass_synthesize_switch(analysis_context)
    pass_clear(analysis_context)


def workflow_patch_hlil(analysis_context: AnalysisContext):
    from .utils import suggest_stateVar

    suggest_stateVar(analysis_context.view, analysis_context.function)
