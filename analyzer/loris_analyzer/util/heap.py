import angr
import logging

from typing import List

from loris_analyzer.util import utils
from loris_analyzer.util.logging import dlog, LOG_HEAP

log = logging.getLogger(__name__)


def init(state: angr.SimState, heap_data: List[dict]):
    dlog(LOG_HEAP, "heap_init")
    print_all_chunks(state)
    to_free_list = list()
    for chunk in heap_data:
        dlog(LOG_HEAP, f"heap_init:" f"chunk={chunk}")
        size = chunk["size"] - 8  # 8 is the heap metadata size
        ptr = state.heap.malloc(size)
        if chunk["free"]:
            to_free_list.append(ptr)
        else:
            state.memory.store(ptr, chunk["data"], endness="Iend_BE")
    for ptr in to_free_list:
        state.heap.free(ptr)
    print_all_chunks(state)


def allocate(state: angr.SimState, size: int):
    print_all_chunks(state)
    buf = state.heap.malloc(size)
    if buf == 0:
        raise ValueError(f"could not alloc memory for size {size:#x}")
    dlog(LOG_HEAP, f"Allocated simulated buffer at {buf:#010x}(size={size:#x})")
    print_all_chunks(state)
    return buf


def free(state: angr.SimState, ptr):
    print_all_chunks(state)
    ptr_str = f"{ptr:#010x}" if isinstance(ptr, int) else str(ptr)
    dlog(LOG_HEAP, f"heap_free:ptr={ptr_str}")
    ptr = utils.try_eval_one(state, ptr)
    dlog(LOG_HEAP, f"heap_free:ptr={ptr}")
    if not isinstance(ptr, int):
        log.warning(f"Attempted to free a symbolic ptr {ptr_str}")
        return 1
    if ptr < state.heap.heap_base or state.heap.heap_base + state.heap.heap_size <= ptr:
        log.warning(f"Attempted to free out of heap ptr {ptr_str}")
        return 1
    state.heap.free(ptr)
    dlog(LOG_HEAP, f"Freed simulated buffer at {ptr:#010x}")
    print_all_chunks(state)
    return 0


def log_state(state: angr.SimState):
    dlog(LOG_HEAP, "|-------------------------------------------------|")
    _print_all_chunks(state)
    dlog(LOG_HEAP, "|------------------ USED CHUNKS ------------------|")
    for ck in state.heap.allocated_chunks():
        size = utils.try_eval_one(state, ck.get_size())
        size_str = f"{size:#010x}" if isinstance(size, int) else str(size)
        dlog(LOG_HEAP, f"| {ck} (size={size_str}) |")
    dlog(LOG_HEAP, "|------------------ FREE CHUNKS -------------------|")
    for ck in state.heap.free_chunks():
        size = utils.try_eval_one(state, ck.get_size())
        size_str = f"{size:#010x}" if isinstance(size, int) else str(size)
        dlog(LOG_HEAP, f"| {ck} (size={size_str}) |")
    dlog(LOG_HEAP, "|-------------------------------------------------|")


def print_all_chunks(state: angr.SimState):
    dlog(LOG_HEAP, "|-------------------------------------------------|")
    _print_all_chunks(state)
    dlog(LOG_HEAP, "|-------------------------------------------------|")


def _print_all_chunks(state: angr.SimState):
    dlog(LOG_HEAP, "|------------------ HEAP CHUNKS ------------------|")
    for ck in state.heap.chunks():
        size = utils.try_eval_one(state, ck.get_size())
        size_str = f"{size:#010x}" if isinstance(size, int) else str(size)
        dlog(LOG_HEAP, f"| {ck} (size={size_str}) |")
