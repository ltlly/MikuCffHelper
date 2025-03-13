from binaryninja import *

from ..utils import log_error


def get_basic_block_at(self, index: int) -> Optional["basicblock.BasicBlock"]:
    basic_blocks = self.basic_blocks
    bbs = sorted(list(basic_blocks), key=lambda bb: bb.start)
    low, high = 0, len(bbs) - 1
    while low <= high:
        mid = (low + high) // 2
        if bbs[mid].start <= index < bbs[mid].end:
            return bbs[mid]
        elif index < bbs[mid].start:
            high = mid - 1
        else:
            low = mid + 1
    log_error(f"can't find basic block at {index}")
    return None


LowLevelILFunction.get_basic_block_at = get_basic_block_at
