"""Shared utilities with lazy loading for optional legacy dependencies."""

from .mikuPlugin import log_error, log_info, log_warn, suggest_stateVar

__all__ = [
    "CFGAnalyzer",
    "SimpleVisitor",
    "StateMachine",
    "InstructionAnalyzer",
    "suggest_stateVar",
    "unsigned_to_signed_32bit",
    "log_info",
    "log_warn",
    "log_error",
]


def __getattr__(name):
    if name == "CFGAnalyzer":
        from .cfg_analyzer import CFGAnalyzer

        return CFGAnalyzer
    if name == "StateMachine":
        from .state_machine import StateMachine

        return StateMachine
    if name in {"InstructionAnalyzer", "unsigned_to_signed_32bit"}:
        from .instruction_analyzer import (
            InstructionAnalyzer,
            unsigned_to_signed_32bit,
        )

        return {
            "InstructionAnalyzer": InstructionAnalyzer,
            "unsigned_to_signed_32bit": unsigned_to_signed_32bit,
        }[name]
    if name == "SimpleVisitor":
        from .instr_vistor import SimpleVisitor

        return SimpleVisitor
    raise AttributeError(name)
