import binaryninja
from binaryninja import (
    BinaryView,
    Variable,
    VariableSourceType,
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
        try:
            method_name = "visit_{}".format(expression.operation.name)
            if hasattr(self, method_name):
                value = getattr(self, method_name)(expression)
            else:
                log_error(f"{repr(expression.operation)} not implemented")
                raise NotImplementedError
            return value
        except Exception as e:
            # log_error(
            #     f"[{expression.instr_index}]::Error in {repr(expression.operation)} "
            # )
            # log_error(f"{e}")
            raise e


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


class SimpleVisitor(BNILVisitor):
    def __init__(self, view: BinaryView, function: binaryninja.Function):
        self.view = view
        self.func = function
        super().__init__()
        addr_size = self.view.address_size
        self.vars: dict[str, Any] = {}

    def visit_MLIL_GOTO(self, expr):
        pass

    def visit_MLIL_IF(self, expr):
        result: BoolRef = self.visit(expr.condition)
        r2: bool = simplify(result)
        if r2:
            return (True, expr.true)
        else:
            return (False, expr.false)

    def visit_both_sides(self, expr):
        return self.visit(expr.left), self.visit(expr.right)

    def visit_MLIL_SET_VAR(self, expr):
        var = make_variable_z3(expr.dest)
        value = self.visit(expr.src)
        value = simplify(value)
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
            raise Exception(f"var {expr.src.name} not found")
            # newVar = make_variable_z3(expr.src)
            # self.vars[expr.src.name] = {
            #     "value": newVar,
            #     "size": expr.src.type.width,
            #     "var": newVar,
            # }
            # log_error(f"new var: {newVar}")
            # return self.vars[expr.src.name]["value"]

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
