from dataclasses import dataclass
import binaryninja
from binaryninja import (
    Variable,
    VariableSourceType,
    BinaryView,
    MediumLevelILIf,
)

from z3 import (
    UGT,
    ULE,
    ULT,
    UGE,
    BitVec,
    BitVecRef,
    BitVecVal,
    Bool,
    BoolVal,
    Extract,
    ZeroExt,
    simplify,
    is_true,
    is_false,
    BitVecNumRef,
    BoolRef,
)
from binaryninja.log import log_error, log_info
from typing import (
    Any,
    Union,
)


class BNILVisitor(object):
    def __init__(self, **kw):
        super(BNILVisitor, self).__init__()

    def visit(self, expression) -> Any:
        method_name = "visit_{}".format(expression.operation.name)
        if hasattr(self, method_name):
            value = getattr(self, method_name)(expression)
        else:
            log_info(f"{repr(expression.operation)} not implemented")
            raise NotImplementedError
        return value


def make_variable_z3(var: Variable) -> Union[BitVecRef, BoolRef, BitVecNumRef]:
    if var.name == "":
        if var.source_type == VariableSourceType.RegisterVariableSourceType:
            var.name = var.function.arch.get_reg_by_index(var.storage)
        else:
            var.name = f"var_{abs(var.storage):x}"
    if var.type.__str__() == "Bool":
        return Bool(var.name)
    elif var.type is None:
        log_error(f"var type is None: {var} ,make it to BitVec 64")
        return BitVec(var.name, 64)
    else:
        return BitVec(var.name, var.type.width * 8)


@dataclass
class IfResult:
    condition: BoolRef
    is_boolean: bool = False
    bool_result: bool = False
    target_index: int = -1
    true_target_index: int = -1
    false_target_index: int = -1


class SimpleVisitor(BNILVisitor):
    def __init__(self, view: BinaryView, function: binaryninja.Function):
        self.view = view
        self.func = function
        super().__init__()
        self.vars: dict[str, Any] = {}

    def visit_MLIL_GOTO(self, expr):
        pass

    def visit_MLIL_IF(self, expr: MediumLevelILIf):
        # evaluate and simplify condition
        result = self.visit(expr.condition)
        r2 = simplify(result)
        res = IfResult(condition=r2)
        res.true_target_index = expr.true
        res.false_target_index = expr.false
        # check for concrete boolean value
        if is_true(r2):
            res.bool_result = True
            res.is_boolean = True
            res.target_index = expr.true
        elif is_false(r2):
            res.bool_result = False
            res.is_boolean = True
            res.target_index = expr.false
        else:
            res.is_boolean = False
        return res

    def visit_both_sides(self, expr):
        return self.visit(expr.left), self.visit(expr.right)

    def visit_MLIL_SET_VAR(self, expr):
        var = make_variable_z3(expr.dest)
        value = simplify(self.visit(expr.src))
        size = expr.dest.type.width
        if isinstance(value, int):
            value = BitVecVal(value, size * 8)
        elif isinstance(value, BoolRef):
            pass
        else:
            value = Extract((size * 8) - 1, 0, value)
        self.vars[var.__str__()] = {
            "value": value,
            "size": expr.dest.type.width,  # size表示字节数
            "var": var,
        }

    def visit_MLIL_VAR(self, expr):
        if expr.src.name in self.vars:
            return self.vars[expr.src.name]["value"]
        else:
            newVar = make_variable_z3(expr.src)
            self.vars[expr.src.name] = {
                "value": newVar,
                "size": expr.src.type.width,
                "var": newVar,
            }
            return self.vars[expr.src.name]["value"]

    def visit_MLIL_CONST(self, expr):
        if expr.size == 0 and expr.constant in (0, 1):
            return BoolVal(True) if expr.constant else BoolVal(False)
        return BitVecVal(expr.constant, expr.size * 8)

    def visit_MLIL_CMP_E(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)
        if right.size() < left.size():
            right = ZeroExt(left.size() - right.size(), right)
        elif right.size() > left.size():
            left = ZeroExt(right.size() - left.size(), left)
        return left == right

    def visit_MLIL_CMP_NE(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)
        if right.size() < left.size():
            right = ZeroExt(left.size() - right.size(), right)
        elif right.size() > left.size():
            left = ZeroExt(right.size() - left.size(), left)
        return left != right

    def visit_MLIL_CMP_SLE(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() < left.size():
            right = ZeroExt(left.size() - right.size(), right)
        elif right.size() > left.size():
            left = ZeroExt(right.size() - left.size(), left)
        return left <= right

    def visit_MLIL_CMP_SLT(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() < left.size():
            right = ZeroExt(left.size() - right.size(), right)
        elif right.size() > left.size():
            left = ZeroExt(right.size() - left.size(), left)
        return left < right

    def visit_MLIL_CMP_SGT(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() < left.size():
            right = ZeroExt(left.size() - right.size(), right)
        elif right.size() > left.size():
            left = ZeroExt(right.size() - left.size(), left)
        return left > right

    def visit_MLIL_CMP_SGE(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() < left.size():
            right = ZeroExt(left.size() - right.size(), right)
        elif right.size() > left.size():
            left = ZeroExt(right.size() - left.size(), left)
        return left >= right

    def visit_MLIL_CMP_UGT(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() < left.size():
            right = ZeroExt(left.size() - right.size(), right)
        elif right.size() > left.size():
            left = ZeroExt(right.size() - left.size(), left)
        return UGT(left, right)

    def visit_MLIL_CMP_UGE(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() < left.size():
            right = ZeroExt(left.size() - right.size(), right)
        elif right.size() > left.size():
            left = ZeroExt(right.size() - left.size(), left)
        return UGE(left, right)

    def visit_MLIL_CMP_ULE(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() < left.size():
            right = ZeroExt(left.size() - right.size(), right)
        elif right.size() > left.size():
            left = ZeroExt(right.size() - left.size(), left)
        return ULE(left, right)

    def visit_MLIL_CMP_ULT(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() < left.size():
            right = ZeroExt(left.size() - right.size(), right)
        elif right.size() > left.size():
            left = ZeroExt(right.size() - left.size(), left)
        return ULT(left, right)
