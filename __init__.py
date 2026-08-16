import json
from binaryninja import PluginCommand, Workflow, Activity
from .mikuWorkflow import (
    workflow_patch_llil,
    workflow_patch_mlil,
    workflow_patch_hlil,
    workflow_patch_mlil_switch,
    workflow_patch_mlil_auto,
    workflow_patch_mlil_general,
)
from .utils import log_info
from .fix_binaryninja_api import lowlevelil  # noqa: F401
from .fix_binaryninja_api import mediumlevelil  # noqa: F401


def register_workflow():
    """
    Register the workflow for the plugin.
    """
    cff_workflow = Workflow("core.function.metaAnalysis").clone(
        "MikuCffHelper_workflow"
    )

    configuration_llil = json.dumps(
        {
            "name": "analysis.plugins.workflow_patch_llil",
            "description": "内部 LLIL 预处理：公共块复制 / flag 条件内联 / if 分块（勿手动关闭）",
            "eligibility": {"auto": {"default": True}},
        }
    )
    cff_workflow.register_activity(
        Activity(configuration_llil, action=workflow_patch_llil)
    )

    # 推荐入口：先尝试 synthesize_switch (path B)，失败时 fallback 到
    # deflate_hard (path A)。对每个函数自动选最适合的路径
    configuration_mlil_auto = json.dumps(
        {
            "name": "analysis.plugins.workflow_patch_mlil_auto",
            "description": "自动模式（推荐）：先 模式2 Switch合成，失败自动 模式1 Deflate硬解；<50块通常<10s，>300块可能30-60s+",
            "eligibility": {"auto": {"default": False}},
        }
    )
    cff_workflow.register_activity(
        Activity(configuration_mlil_auto, action=workflow_patch_mlil_auto)
    )

    # 进阶：单独跑 deflate_hard (path A)。用户已知函数适合用 A 时启用
    configuration_mlil = json.dumps(
        {
            "name": "analysis.plugins.workflow_patch_mlil",
            "description": "模式1 Deflate硬解：SCC+副作用筛选识别dispatcher → 前向整型模拟 → state=const 直连真实块；输出 goto/if/while，块数最少，大函数最慢",
            "eligibility": {"auto": {"default": False}},
        }
    )
    cff_workflow.register_activity(
        Activity(configuration_mlil, action=workflow_patch_mlil)
    )

    # 进阶：单独跑 synthesize_switch (path B)。用户已知函数适合用 B 时启用
    configuration_mlil_switch = json.dumps(
        {
            "name": "analysis.plugins.workflow_patch_mlil_switch",
            "description": "模式2 Switch合成：支配树检测 → 状态变量识别 → 前向模拟 → MLIL_JUMP_TO；HLIL 显示 switch-case，适合标准 OLLVM",
            "eligibility": {"auto": {"default": False}},
        }
    )
    cff_workflow.register_activity(
        Activity(configuration_mlil_switch, action=workflow_patch_mlil_switch)
    )

    # 实验性：新框架通用路径使用独立 workflow，避免主 workflow 的 LLIL
    # copy/split 预处理把 general 的输入块数撑大（实测 sub_407368 31→90）。
    # general workflow 只注册 MLIL activity，不插入 workflow_patch_llil。
    configuration_hlil = json.dumps(
        {
            "name": "analysis.plugins.workflow_patch_hlil",
            "description": "A activity to patch hlil",
            "eligibility": {"auto": {"default": True}},
        }
    )
    cff_workflow.register_activity(
        Activity(configuration_hlil, action=workflow_patch_hlil)
    )

    configuration_mlil_general = json.dumps(
        {
            "name": "analysis.plugins.workflow_patch_mlil_general",
            "description": "模式3 通用框架（独立workflow）：线性检测 + alias/flag/元组 + P3 guard；适合 alias-only/无CMP_E/多状态变种；不跑LLIL复制",
            "eligibility": {"auto": {"default": True}},
        }
    )

    general_workflow = Workflow("core.function.metaAnalysis").clone(
        "MikuCffHelper_general_workflow"
    )
    general_workflow.register_activity(
        Activity(configuration_mlil_general, action=workflow_patch_mlil_general)
    )
    general_workflow.register_activity(
        Activity(configuration_hlil, action=workflow_patch_hlil)
    )
    general_workflow.insert(
        "core.function.analyzeConditionalNoReturns",
        ["analysis.plugins.workflow_patch_mlil_general"],
    )
    general_workflow.insert(
        "core.function.runCompletionCallbacks",
        ["analysis.plugins.workflow_patch_hlil"],
    )
    general_workflow.register()
    log_info(f"Registered workflow: {general_workflow.name}")

    cff_workflow.insert(
        "core.function.generateMediumLevelIL", ["analysis.plugins.workflow_patch_llil"]
    )
    cff_workflow.insert(
        "core.function.analyzeConditionalNoReturns",
        [
            "analysis.plugins.workflow_patch_mlil_auto",
            "analysis.plugins.workflow_patch_mlil",
            "analysis.plugins.workflow_patch_mlil_switch",
        ],
    )
    cff_workflow.insert(
        "core.function.runCompletionCallbacks", ["analysis.plugins.workflow_patch_hlil"]
    )
    cff_workflow.register()
    log_info(f"Registered workflow: {cff_workflow.name}")


def register_commands():
    """
    register commands
    """
    from .utils.mikuPlugin import (
        estimate_cff_time,
        set_stateVar,
        suggest_stateVar,
        isV,
    )

    PluginCommand.register_for_function("miku\\set_state_var", "", set_stateVar, isV)
    PluginCommand.register_for_function(
        "miku\\suggest_stateVar ", "", suggest_stateVar, isV
    )
    PluginCommand.register_for_function(
        "miku\\estimate_cff_time",
        "按函数大小预估 模式1/模式2/Auto/模式3 耗时",
        estimate_cff_time,
        isV,
    )


register_workflow()
register_commands()
