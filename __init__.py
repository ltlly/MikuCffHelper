from binaryninja import *

from .mikuWorkflow import workflow_patch_llil
from .utils import log_info

# Register a new analysis setting to control whether this passes is enabled/disabled.
Settings().register_setting(
    "analysis.plugins.MikuCffHelper",
    '{"description" : "try to solve cff", "title" : "MikuCffHelper_Setting", "default" : false, "type" : "boolean"}')
configuration = json.dumps({
    "name": "workflow_patch_llil",
    "description": "A activity to patch llil",
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
    Activity(configuration, action=workflow_patch_llil)
)
cffFixWorkFlow.insert("core.function.generateMediumLevelIL", ["workflow_patch_llil"])
cffFixWorkFlow.register()
log_info(f"Registered workflow: {cffFixWorkFlow.name}")
