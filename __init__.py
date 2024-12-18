import json

from binaryninja import PluginCommand, Workflow, Activity

from .mikuWorkflow import workflow_patch_llil, workflow_patch_mlil
from .utils import log_info
from .fix_binaryninja_api import lowlevelil
from .fix_binaryninja_api import mediumlevelil

def register_workflow():
    cffFixWorkFlow = Workflow("core.function.metaAnalysis").clone(
        "MikuCffHelper_workflow"
    )

    configuration_llil = json.dumps(
        {
            "name": "analysis.plugins.workflow_patch_llil",
            "description": "A activity to patch llil",
            "eligibility": {"auto": {"default": False}},
        }
    )
    cffFixWorkFlow.register_activity(
        Activity(configuration_llil, action=workflow_patch_llil)
    )

    configuration_mlil = json.dumps(
        {
            "name": "analysis.plugins.workflow_patch_mlil",
            "description": "A activity to patch mlil",
            "eligibility": {"auto": {"default": False}},
        }
    )
    cffFixWorkFlow.register_activity(
        Activity(configuration_mlil, action=workflow_patch_mlil)
    )
    cffFixWorkFlow.insert(
        "core.function.generateMediumLevelIL", ["analysis.plugins.workflow_patch_llil"]
    )
    cffFixWorkFlow.insert(
        "core.function.analyzeConditionalNoReturns", ["analysis.plugins.workflow_patch_mlil"]
    )
    cffFixWorkFlow.register()
    log_info(f"Registered workflow: {cffFixWorkFlow.name}")


def register_commands():
    from .mikuPlugin import set_stateVar, suggest_stateVar, isV

    PluginCommand.register_for_function("miku\\set_state_var", "", set_stateVar, isV)
    PluginCommand.register_for_function(
        "miku\\suggest_stateVar ", "", suggest_stateVar, isV
    )


register_workflow()
register_commands()
