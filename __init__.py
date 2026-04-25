import json
from binaryninja import PluginCommand, Workflow, Activity
from .mikuWorkflow import (
    workflow_patch_llil,
    workflow_patch_mlil,
    workflow_patch_hlil,
    workflow_patch_mlil_switch,
    workflow_patch_mlil_auto,
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
            "description": "A activity to patch llil",
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
            "description": "Auto CFF: 先 synthesize_switch，失败 fallback deflate_hard",
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
            "description": "Deflate CFF: 把 dispatcher 绕过，输出最少块数的 goto 形态",
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
            "description": "Synthesize switch: 把 dispatcher 重构为 MLIL JUMP_TO，HLIL 显示 switch-case",
            "eligibility": {"auto": {"default": False}},
        }
    )
    cff_workflow.register_activity(
        Activity(configuration_mlil_switch, action=workflow_patch_mlil_switch)
    )

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
    from .utils.mikuPlugin import set_stateVar, suggest_stateVar, isV

    PluginCommand.register_for_function("miku\\set_state_var", "", set_stateVar, isV)
    PluginCommand.register_for_function(
        "miku\\suggest_stateVar ", "", suggest_stateVar, isV
    )


register_workflow()
register_commands()
