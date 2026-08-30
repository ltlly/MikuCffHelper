import json
from binaryninja import PluginCommand, Workflow, Activity
from .mikuWorkflow import (
    workflow_patch_llil,
    workflow_patch_mlil,
    workflow_patch_hlil,
    workflow_patch_mlil_switch,
    workflow_patch_mlil_auto,
)
from .utils import log_error, log_info
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
            "eligibility": {"auto": {"default": False}},
        }
    )
    llil_activity = cff_workflow.register_activity(
        Activity(configuration_llil, action=workflow_patch_llil)
    )

    # 推荐入口：独立构造并验证 switch / deflate 候选，再按当前函数可达 CFG
    # 的字典序结构成本选择；没有样本阈值或固定权重。
    configuration_mlil_auto = json.dumps(
        {
            "name": "analysis.plugins.workflow_patch_mlil_auto",
            "description": "Verified CFF auto: choose the simpler reachable CFG",
            "eligibility": {"auto": {"default": True}},
        }
    )
    auto_activity = cff_workflow.register_activity(
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
    deflate_activity = cff_workflow.register_activity(
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
    switch_activity = cff_workflow.register_activity(
        Activity(configuration_mlil_switch, action=workflow_patch_mlil_switch)
    )

    configuration_hlil = json.dumps(
        {
            "name": "analysis.plugins.workflow_patch_hlil",
            "description": "Legacy state-variable naming helper (manual)",
            "eligibility": {"auto": {"default": False}},
        }
    )
    hlil_activity = cff_workflow.register_activity(
        Activity(configuration_hlil, action=workflow_patch_hlil)
    )

    if any(
        activity is None
        for activity in (
            llil_activity,
            auto_activity,
            deflate_activity,
            switch_activity,
            hlil_activity,
        )
    ):
        log_error("MikuCffHelper: failed to register one or more Workflow activities")
        return

    # Binary Ninja 6.x exposes the in-progress IL through AnalysisContext. Follow
    # the official phase anchors and check every topology mutation instead of
    # silently inserting after a removed activity name.
    topology_ok = (
        cff_workflow.contains("core.function.generateMediumLevelIL")
        and cff_workflow.insert(
            "core.function.generateMediumLevelIL",
            ["analysis.plugins.workflow_patch_llil"],
        )
        and cff_workflow.insert_after(
            "core.function.generateMediumLevelIL",
            [
                "analysis.plugins.workflow_patch_mlil_auto",
                "analysis.plugins.workflow_patch_mlil",
                "analysis.plugins.workflow_patch_mlil_switch",
            ],
        )
        and cff_workflow.contains("core.function.generateHighLevelIL")
        and cff_workflow.insert_after(
            "core.function.generateHighLevelIL",
            ["analysis.plugins.workflow_patch_hlil"],
        )
    )
    if not topology_ok:
        log_error("MikuCffHelper: incompatible Binary Ninja Workflow topology")
        return
    if not cff_workflow.register():
        log_error("MikuCffHelper: Workflow registration failed")
        return
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
