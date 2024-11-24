from binaryninja import PluginCommand,Workflow,Settings,Activity
import json
from .mikuWorkflow import workflow_patch_llil, workflow_patch_mlil
from .utils import log_info


def register_workflow():
    cffFixWorkFlow = Workflow("core.function.metaAnalysis").clone("MikuCffHelper_workflow")
    Settings().register_setting(
        "analysis.plugins.MikuCffHelper_llil",
        '{"description" : "pre passes", "title" : "MikuCffHelper_llil", "default" : false, "type" : "boolean"}')

    configuration_llil = json.dumps({
        "name": "workflow_patch_llil",
        "description": "A activity to patch llil",
        "eligibility": {
            "predicates": [
                {
                    "type": "setting",
                    "identifier": "analysis.plugins.MikuCffHelper_llil",
                    "value": True
                }
            ]
        }
    })
    cffFixWorkFlow.register_activity(
        Activity(configuration_llil, action=workflow_patch_llil)
    )
    Settings().register_setting(
        "analysis.plugins.MikuCffHelper_mlil",
        '{"description" : "try to solve cff in mlil", "title" : "MikuCffHelper_mlil", "default" : false, "type" : "boolean"}')

    configuration_mlil = json.dumps({
        "name": "workflow_patch_mlil",
        "description": "A activity to patch mlil",
        "eligibility": {
            "predicates": [
                {
                    "type": "setting",
                    "identifier": "analysis.plugins.MikuCffHelper_mlil",
                    "value": True
                }
            ]
        }
    })
    cffFixWorkFlow.register_activity(
        Activity(configuration_mlil, action=workflow_patch_mlil)
    )
    cffFixWorkFlow.insert("core.function.generateMediumLevelIL", ["workflow_patch_llil"])
    cffFixWorkFlow.insert("core.function.analyzeConditionalNoReturns", ["workflow_patch_mlil"])
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
