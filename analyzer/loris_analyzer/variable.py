import angr
import claripy
import copy
import intervaltree
import itertools
import logging
import random
import struct

from typing import Dict, List, Optional, Tuple, Union

from loris_analyzer.globals import *
from loris_analyzer.util import utils
from loris_analyzer.util.logging import dlog, LOG_MEM, LOG_HEAP, LOG_SOLVER

log = logging.getLogger(__name__)


class VariableStat:
    def __init__(self):
        self._n_reads: int = 0
        self._read_depth = set()
        self._n_writes: int = 0
        self._write_depth = set()
        self._states: List[angr.SimState] = list()

    @property
    def reads(self) -> int:
        return self._n_reads

    @reads.setter
    def reads(self, r):
        self._n_reads += r

    @property
    def read_depth(self) -> set:
        return self._read_depth

    @property
    def writes(self) -> int:
        return self._n_writes

    @writes.setter
    def writes(self, w):
        self._n_writes += w

    @property
    def write_depth(self) -> set:
        return self._write_depth

    @property
    def states(self) -> List[angr.SimState]:
        return self._states

    @property
    def min_states_depth(self) -> Optional[int]:
        assert len(self._states) > 0
        d = self._states[0].history.depth
        for s in self._states:
            d = min(d, s.history.depth)

        return d

    def add_state(self, _state: angr.SimState):
        if len(self._states) == 0:
            self._states.append(_state)
        elif _state.addr == self._states[0].addr:
            self._states.append(_state)
        elif _state.history.depth < self.min_states_depth:
            self._states = [_state]

    def read(self, d: Optional[tuple] = None) -> int:
        """
        Increments the number of read accesses by 1
        :param d: read depth
        :return: the number of read accesses after increment
        """
        self._n_reads += 1
        if d is not None:
            self._read_depth.add(d)
        return self._n_reads

    def written(self, d: Optional[tuple] = None) -> int:
        """
        Increments the number write accesses by 1
        :param d: write depth
        :return: the number of write accesses after increment
        """
        self._n_writes += 1
        if d is not None:
            self._write_depth.add(d)
        return self._n_writes

    def consume_update(self, other):
        """
        Updates `self` with the `other` stat
        :param other: another `VariableStat` instance
        :return:
        """
        if other is self or other.states is self._states:
            return
        self._n_reads += other.reads
        self._read_depth.update(other.read_depth)
        self._n_writes += other.writes
        self._write_depth.update(other.write_depth)
        for i in range(len(other.states) - 1, -1, -1):
            self.add_state(other.states[i])
            other.states.pop(i)

    @staticmethod
    def reduce(current, other):
        """
        Reduces the stats of `current` and `other` variable stats
        :param current: a `VariableStat` instance
        :param other: another `VariableStat` to merge with `current`
        :return: `current` with combined stats
        """
        current.consume_update(other)
        return current

    def copy(self):
        stat = copy.copy(self)
        stat._states = copy.copy(self._states)
        return stat

    def __repr__(self):
        states_repr = [
            f"{s} ({s.history.depth})" if s else str(s)
            for s in self._states[: min(10, len(self._states))]
        ]
        if len(self._states) > 10:
            states_repr.append("...")
        return f"<{self.__class__.__name__} r={self._n_reads} w={self._n_writes}, states=[{', '.join(states_repr)}]>"


class VariableManager:
    def __init__(
        self, stack: intervaltree.Interval, hook_interval: intervaltree.Interval
    ):
        self._stack = stack
        self._write_hook_iv = hook_interval
        self._stop_recording = False
        self._ptr_vars = intervaltree.IntervalTree()
        self._vars = intervaltree.IntervalTree()
        self._heap_chunks = intervaltree.IntervalTree()
        self._heap_id_size = dict()
        self._heap_returns = set()
        self._goal_avoid_vars = intervaltree.IntervalTree()
        self._const_vars = intervaltree.IntervalTree()
        self._UNPACK_SYM = {
            1: "B",
            2: "H",
            4: "I",
            8: "Q",
        }

    @property
    def stop_recording(self) -> bool:
        return self._stop_recording

    @stop_recording.setter
    def stop_recording(self, v: bool):
        self._stop_recording = v

    def in_stack(self, begin: int, end: int):
        return self._stack.overlaps(begin, end)

    def in_heap(self, begin: int, end: int):
        return self._heap_chunks.overlaps(begin, end)

    def maybe_pointer(self, val: int):
        return (
            self.in_stack(val, val + 1)
            or self.in_heap(val, val + 1)
            or self._write_hook_iv.overlaps(val, val + 1)
        )

    def write_panda_hook(self, emu, cpustate, memory_access_desc):
        if self._stop_recording:
            return
        pc = cpustate.panda_guest_pc
        addr = memory_access_desc.addr
        size = memory_access_desc.size
        (value,) = struct.unpack(
            self._UNPACK_SYM[size], emu.panda.virtual_memory_read(cpustate, addr, size)
        )
        dlog(
            LOG_MEM,
            f"{self.__class__.__name__}::write_panda_hook: "
            f"PC({pc:#010x}), addr={addr:#010x}, size={size}, value={value:#x}",
        )
        if self.maybe_pointer(value):
            self._ptr_vars.add(utils.Interval(addr, addr + size, value))
        else:
            self._vars.add(utils.Interval(addr, addr + size))

    def heap_alloc_hook(self, emu, cpustate, _tb, _hook, size_reg: str):
        if self._stop_recording:
            return
        size = emu.qemu.pypanda.arch.get_reg(cpustate, size_reg)
        ret_addr = emu.qemu.pypanda.arch.get_return_address(cpustate)
        self._heap_id_size[ret_addr & ~1] = size
        dlog(
            LOG_HEAP,
            f"{self.__class__.__name__}::heap_alloc_hook: "
            f"ret_addr({ret_addr:#010x}), size={size}",
        )
        if ret_addr & ~1 not in self._heap_returns:
            self._heap_returns.add(ret_addr & ~1)
            emu.add_panda_hook(ret_addr & ~1, self._heap_alloc_ret_hook)

    def trace_memory_read(self, state: angr.SimState):
        """
        Trace all memory read operations
        :param state:
        :return:
        """
        addr = state.inspect.mem_read_address
        addr = state.solver.eval(addr)
        size = state.inspect.mem_read_length
        value = state.inspect.mem_read_expr
        if self._ptr_vars.overlaps(addr, addr + size):
            dlog(
                LOG_MEM,
                f"mem_read: PTR_VARS addr={addr:#010x}, size={size}, expr={value}",
            )
        elif self._vars.overlaps(addr, addr + size):
            if (
                state.globals[START_VAR_RECORD]
                and not self._ptr_vars.overlaps(addr, addr + size)
                and not state.globals[INIT_VARS].overlaps(addr, addr + size)
                and not value.symbolic
                and (
                    state.globals[GOAL_SEEN]
                    or not self._goal_avoid_vars.overlaps(addr, addr + size)
                )
                and not self._const_vars.overlaps(addr, addr + size)
            ):

                stat = VariableStat()
                stat.read(d=(state.history.depth, len(state.callstack)))
                stat.add_state(state.copy())
                state.vars.add_rbi_var(addr, addr + size, stat)
                dlog(
                    LOG_MEM,
                    f"mem_read: VARS addr={addr:#010x}, size={size}, expr={value}, RBI_VAR",
                )
            else:
                dlog(
                    LOG_MEM,
                    f"mem_read: INIT_VARS addr={addr:#010x}, size={size}, expr={value}",
                )

    def trace_memory_write(self, state: angr.SimState):
        addr = state.inspect.mem_write_address
        addr = state.solver.eval(addr)
        size = state.inspect.mem_write_length
        value = state.inspect.mem_write_expr
        bw = state.arch.byte_width
        size = value.length // bw if size is None else size
        assert size is not None or isinstance(value, claripy.ast.Base)
        if self._ptr_vars.overlaps(addr, addr + size):
            dlog(
                LOG_MEM,
                f"mem_write: PTR_VARS addr={addr:#010x}, size={size}, expr={value}",
            )
        elif self._vars.overlaps(addr, addr + size):
            dlog(
                LOG_MEM,
                f"mem_write: INIT_VARS addr={addr:#010x}, size={size}, expr={value}",
            )
            state.globals[INIT_VARS].add(utils.Interval(addr, addr + size))

    def taint_variable(self, state: angr.SimState, var: intervaltree.Interval):
        # It is important to create a symbolic variable using the state solver instead of claripy to register
        # the variable with a key that can be accessed later through `solver.get_variables`
        bw = state.arch.byte_width
        addr = var.begin
        assert isinstance(addr, int)
        size = var.end - var.begin
        assert isinstance(size, int)
        key = (VAR_PREFIX, addr, size)
        sym_val = state.solver.BVS(
            utils.var_key2name(key),
            size * bw,
            explicit_name=True,
            eternal=True,
            key=key,
        )
        state.memory.store(addr, sym_val, size=size, endness="Iend_LE")

    def update_goal_avoid_vars(self, t: intervaltree.IntervalTree):
        self._goal_avoid_vars.update(t)

    def update_const_vars(self, t: intervaltree.IntervalTree):
        self._const_vars.update(t)

    @staticmethod
    def eval_variables(
        state: angr.SimState, n: int = 256
    ) -> Dict[tuple, List[Union[range, int]]]:
        variables = state.solver.get_variables(VAR_PREFIX)
        unconstrained_var_keys = {
            k
            for k, v in variables
            if all(
                [
                    utils.extract_name(v) not in cns.variables
                    for cns in state.solver.constraints
                ]
            )
        }
        results = dict()
        variables = state.solver.get_variables(VAR_PREFIX)
        inputs = state.solver.get_variables(INPUT_PREFIX)
        for k, v in itertools.chain(variables, inputs):
            if k in unconstrained_var_keys:
                continue
            solutions = state.solver.eval_upto(v, n)
            results[k] = utils.compress_numbers(solutions)
        return results

    def _heap_alloc_ret_hook(self, _emu, cpustate, _tb, _hook):
        if self.stop_recording:
            return
        ptr = cpustate.env_ptr.regs[0]
        pc = cpustate.env_ptr.regs[15]
        size = self._heap_id_size.pop(pc, -1)
        if size == -1:
            log.error(f"Failed to fetch size of heap chunk {ptr:#010x} (pc={pc:#010x})")
            return
        dlog(
            LOG_HEAP,
            f"{self.__class__.__name__}::_heap_alloc_ret_hook: PC({pc:#010x}), ptr={ptr:#010x}, size={size}",
        )
        self._heap_chunks.add(utils.Interval(ptr, ptr + size))


class Variables(angr.SimStatePlugin):
    def __init__(self, rbi_vars: Optional[intervaltree.IntervalTree] = None):
        super(Variables, self).__init__()
        if rbi_vars is None:
            rbi_vars = intervaltree.IntervalTree()
        self._rbi_vars = intervaltree.IntervalTree(iv.copy() for iv in rbi_vars)

    @property
    def rbi_vars(self) -> intervaltree.IntervalTree:
        return self._rbi_vars

    @property
    def rbi_intervals(self) -> intervaltree.IntervalTree:
        t = intervaltree.IntervalTree()
        for v in self._rbi_vars:
            t.add(utils.Interval(v.begin, v.end))

        return t

    def _any_empty_states(self) -> bool:
        return any(len(iv.data.states) == 0 for iv in self._rbi_vars)

    def add_rbi_var(self, begin: int, end: int, data: VariableStat):
        assert not self._any_empty_states()
        self._rbi_vars.add(utils.Interval(begin, end, data))
        assert not self._any_empty_states()
        self._rbi_vars.merge_equals(data_reducer=VariableStat.reduce)
        assert not self._any_empty_states()

    def next_var(self) -> Optional[intervaltree.Interval]:
        if len(self._rbi_vars) == 0:
            return None
        var_list = list(self._rbi_vars.all_intervals)
        var_list.sort(
            key=lambda _iv: (
                # _iv.end - _iv.begin,  # size
                _iv.data.min_states_depth,
                _iv.begin,
            )
        )
        return var_list[0]

    def next_random_var(self) -> Optional[intervaltree.Interval]:
        if len(self._rbi_vars) == 0:
            return None
        var_list = list(self._rbi_vars.all_intervals)
        idx = random.randint(0, len(var_list) - 1)
        return var_list[idx]

    def log_vars(self, head=10):
        var_list = list(self._rbi_vars.all_intervals)
        var_list.sort(
            key=lambda _iv: (
                # _iv.end - _iv.begin,  # size
                _iv.data.min_states_depth,
                _iv.begin,
            )
        )
        head = min(len(var_list), head)
        for iv in var_list[:head]:
            dlog(LOG_SOLVER, f"s: {iv.end - iv.begin: 6} {iv}")

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return Variables(self._rbi_vars)
