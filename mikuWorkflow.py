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


def workflow_patch_mlil_auto(analysis_context: AnalysisContext):
    """统一的"先 B 后 A"自动 fallback 路径。

    工程考量：
      - 用户当前必须手动选 path A 或 path B，每个函数适用范围又不一样
        (B 适合干净的 OLLVM 标准 CFF；A 在 B 拒绝时仍能短路真实块)
      - 自动模式：先跑 B (synthesize_switch)，B 没改动则 fallback 到 A
        (deflate_hard)
      - B 改动过的函数不再跑 A —— 此时原 cmp-tree 已被 P1 替换或被 P2
        重定向，再跑 A 会以 guard block 为 dispatcher 错配

    对外暴露为单一开关，UI 默认启用这个，老的 workflow_patch_mlil /
    workflow_patch_mlil_switch 留作进阶用户手动单独启用。
    """
    if analysis_context.function.mlil is None:
        return

    # 共用 prelude
    pass_clear(analysis_context)
    pass_mov_state_define(analysis_context)

    # 优先 B
    transformed = pass_synthesize_switch(analysis_context)

    if not transformed:
        # B 没动函数 —— 通常意味着函数不符合 B 的合成守卫 (无完整 case_values
        # 或 forward_resolve 解析率太低)。试 A 兜底，A 的 deflate_hard 即使
        # 在 B 拒绝时也常能短路 state SetVar 链
        pass_deflate_hard(analysis_context)
        pass_clear(analysis_context)
        pass_mov_state_define(analysis_context)
        pass_deflate_hard(analysis_context)

    pass_clear(analysis_context)


def workflow_patch_hlil(analysis_context: AnalysisContext):
    from .utils import suggest_stateVar

    suggest_stateVar(analysis_context.view, analysis_context.function)
