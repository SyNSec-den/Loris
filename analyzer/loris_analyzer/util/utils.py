import angr
import archinfo
import argparse
import claripy
import ctypes
import gc
import importlib
import intervaltree
import itertools
import json
import logging
import os
import re
import sys
import time
import types

from itertools import count, groupby
from pathlib import Path
from typing import Iterable, List, Optional, Tuple, Union

from loris_analyzer.globals import *


log = logging.getLogger(__name__)


class Interval(intervaltree.Interval):
    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        begin = f"{self.begin:#x}" if isinstance(self.begin, int) else str(self.begin)
        end = f"{self.end:#x}" if isinstance(self.end, int) else str(self.end)
        data = f"{self.data:#x}" if isinstance(self.data, int) else str(self.data)
        if self.data is None:
            return f"{self.__class__.__name__}({begin}, {end})"

        return f"{self.__class__.__name__}({begin}, {end}, {data})"


class SimProcedure(angr.SimProcedure):
    def __init__(
        self, *args, analyzer=None, **kwargs
    ):  # to avoid passing `analyzer` to angr
        super().__init__(*args, **kwargs)


class SimulationManager(angr.SimulationManager):
    def __init__(self, *args, exception_list: Optional[list] = None, **kwargs):
        super().__init__(*args, **kwargs)
        if exception_list is None:
            exception_list = list()

        for ex_class in exception_list:
            if issubclass(ex_class, Exception):
                continue
            raise ValueError(f"expected Exception subclass got {ex_class}")
        self._exception_list = exception_list

    def step_state(
        self, state: angr.SimState, successor_func=None, error_list=None, **run_args
    ):
        error_list = error_list if error_list is not None else self._errored

        try:
            return super().step_state(state, successor_func, error_list, **run_args)
        except Exception as ex:
            if any([isinstance(ex, bypass_ex) for bypass_ex in self._exception_list]):
                log.warning(f"Caught an exception to bypass: {ex}")
                error_list.append(
                    angr.sim_manager.ErrorRecord(state, ex, sys.exc_info()[2])
                )
                state.solver.downsize()
                return dict()
            else:
                raise


def trim_global_memory():
    claripy.reset()
    gc.collect()
    time.sleep(1.0)
    libc = ctypes.CDLL("libc.so.6")
    libc.malloc_trim(0)


def ast_debug_str(ast: claripy.ast.Base, max_depth: int = 5):
    return (
        ast.shallow_repr(max_depth=max_depth)
        + f" (depth: {ast.depth}, variables: {ast.variables})"
    )


def import_source_file(filename: Union[str, Path], modname: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(modname, filename)
    if spec is None:
        raise ImportError(f"Could not load spec for module '{modname}' at: {filename}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module

    try:
        spec.loader.exec_module(module)
    except FileNotFoundError as e:
        raise ImportError(f"{e.strerror}: {filename}") from e

    return module


def remove_suffix(input_string: str, suffix: str) -> str:
    if suffix and input_string.endswith(suffix):
        return input_string[: -len(suffix)]
    return input_string


def extract_name(ast: claripy.ast.base.Base) -> str:
    assert len(ast.variables) == 1
    return next(iter(ast.variables))


def extract_address_from_name(var: claripy.ast.bv.BV) -> Optional[int]:
    name = extract_name(var)
    if name is None:
        return None
    var_name_exp = re.compile(r".*mem_(?P<addr>[0-9a-f]+).*")
    match = var_name_exp.search(name)
    if match is None:
        raise ValueError(f"no address in variable name ({name})")
    addr = int(match.group("addr"), 16)

    return addr


def var_name2key(name: str) -> Tuple[str, int, int]:
    parts = name.rsplit("_", maxsplit=2)
    return parts[0], int(parts[1], 16), int(parts[2], 16)


def var_key2name(key: tuple) -> str:
    """

    :param key: a tuple of (var_prefix, address, size)
    :return:
    """
    return f"{key[0]}_{key[1]:08x}_{key[2]:x}"


def find_variable_at(ast: claripy.ast.base.Base, addr: int) -> claripy.ast.bv.BV:
    for var in ast.variables:
        try:
            var_addr = extract_address_from_name(var)
            if var_addr == addr:
                return var
        except ValueError:
            continue


def try_remove_file(p):
    try:
        os.remove(p)
    except FileNotFoundError:
        pass


def try_eval_one(
    state: angr.SimState, data: claripy.ast.bv.BV, **kwargs
) -> Union[int, claripy.ast.Base]:
    try:
        return state.solver.eval_one(data, **kwargs)
    except angr.SimValueError:
        return data


def sizeof_fmt(num, suffix="B") -> str:
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def to_ranges(iterable):
    iterable = sorted(set(iterable))
    for key, group in itertools.groupby(enumerate(iterable), lambda t: t[1] - t[0]):
        group = list(group)
        yield group[0][1], group[-1][1]


def set_fmt(s: Iterable):
    out = set()
    for r in to_ranges(s):
        if r[0] == r[1]:
            out.add(f"{r[0]}")
        else:
            out.add(f"{r[0]}..{r[1]}")
    return f"{{{', '.join(out)}}}"


def list_fmt(li: list, *args, indent=0, indent_ch="\t", **kwargs) -> str:
    if len(li) == 0:
        return "[]"
    elems = list()
    for e in li:
        if isinstance(e, range):
            elems.append(range_fmt(e))
        elif isinstance(e, dict):
            elems.append(dict_fmt(e, indent=indent + 1, indent_ch=indent_ch, **kwargs))
        elif isinstance(e, int):
            elems.append(hex(e))
        else:
            try:
                elems.append(e.__repr__(*args, indent=indent + 1, **kwargs))
            except TypeError:
                elems.append(str(e))
    join_str = ", \n" + indent_ch * (indent + 1)
    elems_str = join_str.join(elems)
    return (
        f"[\n" + indent_ch * (indent + 1) + elems_str + "\n" + indent_ch * indent + "]"
    )


def dict_fmt(di: dict, *args, indent=0, indent_ch="\t", **kwargs) -> str:
    if len(di) == 0:
        return "{}"
    items = []
    for k, v in di.items():
        if isinstance(v, range):
            v_repr = range_fmt(v)
        elif isinstance(v, list):
            v_repr = list_fmt(v, indent=indent + 1, indent_ch=indent_ch, **kwargs)
        elif isinstance(v, int):
            v_repr = hex(v)
        else:
            try:
                v_repr = v.__repr__(*args, indent=indent + 1, **kwargs)
            except TypeError:
                v_repr = str(v)
        items.append(f'"{range_fmt(k) if isinstance(k, range) else str(k)}": {v_repr}')

    join_str = ", \n" + indent_ch * (indent + 1)
    items_str = join_str.join(items)
    return (
        f"{{\n" + indent_ch * (indent + 1) + items_str + "\n" + indent_ch * indent + "}"
    )


def range_fmt(r: range) -> str:
    return f"range({r.start:#x}, {r.stop:#x})"


def interval_fmt(iv: intervaltree.Interval) -> str:
    return f"Interval({iv.begin:#x}, {iv.end:#x}, {iv.data})"


def interval_tree_fmt(ivt: intervaltree.IntervalTree) -> str:
    ivs = [interval_fmt(iv) for iv in ivt]
    return list_fmt(ivs)


def range_size(r: range) -> int:
    """
    Returns the byte length of the given address range
    """
    return r.stop - r.start


def extract_interval_data(
    interval_tree: intervaltree.IntervalTree, addr: int, size: int
) -> claripy.ast.bv.BV:
    """
    :param interval_tree: the tree to search in
    :param addr: the address to look for
    :param size: bytes
    """
    mi = interval_tree.overlap(addr, addr + size)
    if len(mi) > 1:
        raise ValueError(f"there are more than one interval at {addr:#x}: {mi}")
    elif len(mi) == 0:
        raise KeyError(f"address {addr:#x} not found in the interval tree")
    i = next(iter(mi))
    start_bit = i.data.length - (addr - i.begin) * 8 - 1
    end_bit = start_bit - size * 8 + 1
    return claripy.Extract(start_bit, end_bit, i.data)


def get_initialized_intervals(
    memory: angr.storage.memory_mixins.MemoryMixin, addr_range: range
):
    obj: claripy.ast.Base = memory.load(
        addr_range.start, size=(addr_range.stop - addr_range.start)
    )
    result_intervals = intervaltree.IntervalTree()
    if obj.op == "Concat":
        this_base_bit = addr_range.start * 8
        arg: claripy.ast.Base
        arg_group = []
        for arg in (
            reversed(obj.args) if memory.endness == archinfo.Endness.LE else obj.args
        ):
            if (
                this_base_bit % 8 == 0
                and arg.op == "BVS"
                and arg.uninitialized
                and f"{this_base_bit // 8:x}" in next(iter(arg.variables))
                and arg.length % 8 == 0
            ):
                if len(arg_group) >= 1:
                    result_intervals.addi(
                        (this_base_bit - sum(this_arg.length for this_arg in arg_group))
                        // 8,
                        this_base_bit // 8,
                        claripy.Concat(*arg_group),
                    )
                    arg_group.clear()
            else:
                arg_group.append(arg)

            this_base_bit += arg.length

        if len(arg_group) >= 1:
            assert this_base_bit % 8 == 0
            result_intervals.addi(
                (this_base_bit - sum(this_arg.length for this_arg in arg_group)) // 8,
                this_base_bit // 8,
                claripy.Concat(*arg_group),
            )
    else:
        result_intervals.addi(addr_range.start, addr_range.stop, obj)

    return result_intervals


def get_updated_memory(
    state: angr.SimState, symbolic_memory: intervaltree.IntervalTree
) -> intervaltree.IntervalTree:
    intervals = intervaltree.IntervalTree()
    for i in symbolic_memory.all_intervals:
        value = state.memory.load(i.begin, size=i.data.length // 8, endness="Iend_LE")
        is_same = (
            value.symbolic and value.op == "BVS" and value.variables == i.data.variables
        )
        changed = not is_same
        if changed:
            log.debug(
                f"get_updated_memory:"
                f"changed={changed}, "
                f"i.begin={i.begin:#x}, i.data.variables={i.data.variables}, size={i.data.length // 8:#x}\n"
                f"\tvalue.symbolic={value.symbolic}, value.op={value.op}, value.variable={value.variables}"
            )
            intervals.addi(i.begin, i.begin + i.data.length // 8, value)

    return intervals


def get_heap_intervals(state: angr.SimState):
    intervals = intervaltree.IntervalTree()
    for ck in state.heap.allocated_chunks():
        ptr = try_eval_one(state, ck.data_ptr())
        if not isinstance(ptr, int):
            continue

        size = try_eval_one(state, ck.get_data_size())
        if not isinstance(size, int):
            continue
        log.debug(f"get_heap_intervals:" f"ptr={ptr:#010x}, size={size:#x}")
        intervals.update(
            get_initialized_intervals(state.memory, range(ptr, ptr + size))
        )

    return intervals


def validate_file(path: Optional[str] = None) -> Path:
    if path is None:
        raise ValueError("config file is not provided")

    path = Path(os.path.abspath(path))
    if not path.exists():
        raise FileNotFoundError(path.name)

    return path


def number_parse(s):
    match = re.match(r"^(0x[a-fA-f0-9]+)|([0-9]+)$", s)

    if not match:
        raise argparse.ArgumentTypeError('expected number, got "{}"'.format(s))

    if match.group(1):
        return int(match.group(1), 16)
    elif match.group(2):
        return int(match.group(2), 10)
    else:
        assert 0


def compress_numbers(data: List[int]) -> List[Union[range, int]]:
    data.sort()
    groups = [list(v) for _, v in groupby(data, lambda n, c=count(step=1): n - next(c))]
    return [range(j[0], j[-1] + 1) if len(j) > 1 else j[0] for j in groups]
