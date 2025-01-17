from binaryninja import MediumLevelILIf, MediumLevelILCmpNe, MediumLevelILOperation, \
    AnalysisContext, MediumLevelILLabel,MediumLevelILConst
from ...utils import ILSourceLocation

def pass_clear_const_if(analysis_context: AnalysisContext):
    """
    清除常量条件if语句的优化pass
    
    该pass用于优化MLIL将if(true) 与 if(false)语句替换为直接跳转。
    通过消除不必要的条件判断来简化控制流图。
    参数：
        analysis_context: 包含MLIL中间表示的分析上下文
    返回值：
        无
    """
    mlil = analysis_context.mlil
    for _ in range(len(mlil.basic_blocks)):
        updated = False
        for bb in mlil.basic_blocks:
            if not isinstance(bb[-1], MediumLevelILIf):
                continue
            if_instr = bb[-1]
            condition = if_instr.condition
            if not isinstance(condition, MediumLevelILConst):
                continue
            label = MediumLevelILLabel()
            if condition.constant == 1:
                label.operand = if_instr.true
            elif condition.constant == 0:
                label.operand = if_instr.false
            else:
                continue
            goto_instr = mlil.goto(label,ILSourceLocation.from_instruction(if_instr))
            mlil.replace_expr(if_instr.expr_index,goto_instr)
            updated = True
        if updated:
            mlil.finalize()
            mlil.generate_ssa_form()
        else:
            break
    mlil.finalize()
    mlil.generate_ssa_form()
        
