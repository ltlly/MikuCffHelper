from binaryninja import *


class ILSourceLocation:
    """Intermediate Language source code location information
    Used to record instruction addresses and source operand information
    """

    def __init__(self, address=None, sourceOperand=None):
        """初始化源代码位置信息
        Args:
            address: 指令地址
            sourceOperand: 源操作数
        """
        self.address = address
        self.sourceOperand = sourceOperand
        self.valid = False

    @classmethod
    def from_address_operand(cls, address, operand):
        """从地址和操作数创建ILSourceLocation实例
        Args:
            address: 指令地址
            operand: 操作数
        Returns:
            ILSourceLocation: 新的实例
        """
        instance = cls(address, operand)
        instance.valid = True
        return instance

    @classmethod
    def from_instruction(
        cls,
        instr: MediumLevelILInstruction
        | LowLevelILInstruction
        | HighLevelILInstruction,
    ) -> "ILSourceLocation":
        """从指令创建ILSourceLocation实例
        Args:
            instr: 中间语言、低级语言或高级语言指令
        Returns:
            ILSourceLocation: 新的实例
        """
        instance = cls(instr.address, instr.source_operand)
        instance.valid = True
        return instance
