from binaryninja import basicblock, MediumLevelILFunction
from typing import Optional

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


# Binary Ninja 6.x provides a native core-backed lookup.  Keep this compatibility
# shim only for older builds instead of replacing the faster/authoritative API.
if not hasattr(MediumLevelILFunction, "get_basic_block_at"):
    MediumLevelILFunction.get_basic_block_at = get_basic_block_at
