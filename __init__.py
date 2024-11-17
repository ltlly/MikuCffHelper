from binaryninja import *

from .mikuWorkflow import workflow_patch_mlil
from .utils import log_info

# Register a new analysis setting to control whether this pass is enabled/disabled.
Settings().register_setting(
    "analysis.plugins.MikuCffHelper",
    '{"description" : "try to solve cff", "title" : "MikuCffHelper_Setting", "default" : false, "type" : "boolean"}')
configuration = json.dumps({
    "name": "workflow_patch_mlil",
    "description": "A activity to patch mlil",
    "eligibility": {
        "predicates": [
            {
                "type": "setting",
                "identifier": "analysis.plugins.MikuCffHelper",
                "value": True
            }
        ]
    }
})

cffFixWorkFlow = Workflow("core.function.metaAnalysis").clone("MikuCffHelper_workflow")
cffFixWorkFlow.register_activity(
    Activity(configuration, action=workflow_patch_mlil)
)
cffFixWorkFlow.insert("core.function.analyzeTailCalls", ["workflow_patch_mlil"])
cffFixWorkFlow.register()
log_info(f"Registered workflow: {cffFixWorkFlow.name}")
