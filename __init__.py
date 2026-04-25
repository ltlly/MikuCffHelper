import json
from binaryninja import PluginCommand, Workflow, Activity
from .mikuWorkflow import (
    workflow_patch_llil,
    workflow_patch_mlil,
    workflow_patch_hlil,
    workflow_patch_mlil_switch,
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

    # 互斥的另一条路径：保留 dispatcher 但重构为 MLIL JUMP_TO，让 BN HLIL
    # restructurer 显示成 switch-case 结构。两个 mlil pass 互斥，用户只能
    # 启用一个
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
