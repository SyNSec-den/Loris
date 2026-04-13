import angr
import claripy.ast.base
import copy
import functools
import intervaltree  # type: ignore
import itertools
import json
import logging
import multiprocessing
import os
import pickle
import re
import time

from collections import abc, OrderedDict
from importlib.machinery import SourceFileLoader
from typing import Iterable, List, NamedTuple, Optional, Set, Tuple

from loris_analyzer.globals import *
from loris_analyzer.loader import LorisLoader
from loris_analyzer.memory_trimmer import MemoryTrimmer
from loris_analyzer.project import LorisProject
from loris_analyzer.util import utils
from loris_analyzer.util.workspace import Workspace
from loris_analyzer.variable import Variables
from loris_analyzer.vendor import Vendor

log = logging.getLogger(__name__)


def suc_logger(state: angr.SimState):
    successors = state.inspect.sim_successors.successors
    for s in successors:
        if s.regs.pc.symbolic or s.addr == 0:
            print(f"suc_logger: {state}")


def reg_logger(state: angr.SimState):
    ip = state.solver.eval_upto(state.inspect.reg_write_offset, 1, cast_to=int)
    if ip == 68:
        print(
            f"reg_logger: reg_write_offset={state.inspect.reg_write_offset}, "
            f"reg_write_expr={state.inspect.reg_write_expr}, "
            f"reg_write_length={state.inspect.reg_write_length}, "
            f"reg_write_condition={state.inspect.reg_write_condition}, "
            f"reg_write_endness={state.inspect.reg_write_endness}"
        )


def has_successors(state: angr.SimState):
    return len(state.inspect.sim_successors.successors) > 1


def fork_logger(state: angr.SimState):
    successors = state.inspect.sim_successors.successors
    print(
        f"Forking states: {state.addr:#010x} -> [{', '.join([hex(s.addr) for s in successors])}]"
    )


class StateDump(NamedTuple):
    sym_vars: intervaltree.IntervalTree
    idx: int


class LorisAnalyzer:
    def __init__(
        self,
        workspace: Workspace,
        spec: Optional[str],
        loader: LorisLoader,
        soft_memory_limit: int,
    ):
        self._bp = dict()
        self._workspace = workspace
        if spec is None:
            log.warning("No spec provided, this may lead to crashes")
            self.spec_mod = None
        else:
            self.spec_mod = SourceFileLoader(
                "spec", os.path.abspath(spec)
            ).load_module()
        self._project = LorisProject(loader)
        self._symbols = copy.deepcopy(loader.symbol_table)
        self._var_mgr = copy.deepcopy(loader.var_mgr)
        self._tainted_vars = intervaltree.IntervalTree()
        self._vendor: Vendor = copy.deepcopy(loader.vendor)
        self._task = loader.task
        self._soft_memory_limit = soft_memory_limit * 1024**2
        self._stats = OrderedDict()
        self._stats["start"] = time.time()
        self._analyzer_path = self._workspace.path("/analyzer")
        self._add_constraints = list()
        self._goal_constraints = list()
        self._solver_timeout = 10  # seconds
        self._n_solutions = dict()
        self._completed_paths = 0
        self._candidate_next_vars = Variables()
        self._iter_idx = 0
        self._pickle_idx = 0
        self._goal_found = False
        if not self._analyzer_path.exists():
            self._analyzer_path.mkdir()

        symbols = self._load_symbols()
        self._vendor.add_symbols(symbols)

    def run(self, args):
        self._setup_hooks()
        state = self._setup_entry_state(args)
        self._load_add_constraints()
        const_vars = self._load_const_variables()
        self._var_mgr.update_const_vars(const_vars)
        self._iter_idx = 0
        dump = self._load_last_dump()
        goal_avoid_vars = self._load_goal_avoid_vars()
        self._var_mgr.update_goal_avoid_vars(goal_avoid_vars)
        if dump is not None:
            sym_vars, idx = dump
            sym_vars.difference_update(goal_avoid_vars)
            for v in sym_vars:
                log.info(f"Tainting variable {v}")
                self._tainted_vars.add(utils.Interval(v.begin, v.end))
                self._var_mgr.taint_variable(state, v)
            self._iter_idx = idx + 1
        states = [state]
        for _ in itertools.count() if args.n is None else range(args.n):
            if args.s and self._goal_found:
                break

            self._pickle_idx = 0
            self._n_solutions[self._iter_idx] = 0
            for st in states:
                self._setup_inspection(st, irsb=True, constraints=True)
                self._additional_constraints(st)
                log.debug(
                    f"{st}.solver.constraints={utils.list_fmt(st.solver.constraints)}"
                )
            sm: angr.SimulationManager = self._project.factory.simulation_manager(
                states
            )
            stat = LorisStat(self._analyzer_path.join(f"stat.json").to_path())
            sm.use_technique(stat)
            dfs = angr.exploration_techniques.dfs.DFS()
            sm.use_technique(dfs)
            if self._goal_found:
                memory_trimmer = MemoryTrimmer(
                    src_stash="avoid",
                    pickle_callback=functools.partial(self._pickle_findings, "found"),
                )
                sm.use_technique(memory_trimmer)
                sm.explore(avoid=self._second_msg)
                sm.remove_technique(stat)
                sm.remove_technique(dfs)
                sm.remove_technique(memory_trimmer)
                self._stats[f"setup{self._iter_idx}"] = time.time()
            else:
                memory_trimmer = MemoryTrimmer(
                    src_stash="avoid",
                    pickle_callback=functools.partial(self._pickle_findings, "avoid"),
                )
                sm.use_technique(memory_trimmer)
                self._stats[f"setup{self._iter_idx}"] = time.time()
                while sm.active:
                    sm.explore(find=args.goal, avoid=self._second_msg)
                sm.remove_technique(stat)
                sm.remove_technique(dfs)
                sm.remove_technique(memory_trimmer)

                if len(sm.found) > 0:
                    self._store_goal_constraints(sm.found)
                    memory_trimmer = MemoryTrimmer(
                        src_stash="avoid",
                        pickle_callback=functools.partial(
                            self._pickle_findings, "found"
                        ),
                    )
                    sm.use_technique(stat)
                    sm.use_technique(dfs)
                    sm.use_technique(memory_trimmer)
                    sm.move(from_stash="found", to_stash="active")
                    sm.explore(avoid=self._second_msg)
                    sm.remove_technique(stat)
                    sm.remove_technique(dfs)
                    sm.remove_technique(memory_trimmer)

                self._stats[f"explore{self._iter_idx}"] = time.time()

            log.info(sm)
            log.info(f"errored: {sm.errored}")

            new_var, not_all_states_agree = self._next_major_var()
            if new_var is None:
                log.info("No more variables to explore, stopping")
                args.rem = 0
                break
            self._tainted_vars.add(utils.Interval(new_var.begin, new_var.end))
            self._dump_state()
            if args.n is not None:
                args.rem = args.rem - 1
            elif args.s:
                args.rem = int(self._goal_found == False)
            else:
                args.rem = 1

            log.info(f"Adding symbolic var: {new_var}")
            if not_all_states_agree:
                new_state = self._setup_entry_state(args)
                for v in self._tainted_vars:
                    log.info(f"Tainting variable {v}")
                    self._var_mgr.taint_variable(new_state, v)
                new_states = [new_state]
            else:
                new_states: List[angr.SimState] = new_var.data.states

            for st in new_states:
                self._var_mgr.taint_variable(st, new_var)
                log.debug("--------------------------------")
                log.debug(f"# rbi_vars: {len(st.vars.rbi_vars)}")
                log.debug(f"# bbl_addrs: {len(st.history.bbl_addrs)}")
                st.vars.log_vars(head=5)
            states = new_states
            self._candidate_next_vars = Variables()

            self._iter_idx += 1

        self._stats["end"] = time.time()

    def log_stats(self):
        start_t = 0
        prev_t = 0
        for name, t in self._stats.items():
            if name == "start":
                start_t = t
                prev_t = t
                continue
            if name == "end":
                log.info(f"Total elapsed time: {t - start_t:.2f}")
                break
            log.info(f"Elapsed time for {name}: {t - prev_t:.2f}")
            prev_t = t

    def _dump_state(self):
        fp = self._analyzer_path.join(f"sym_vars.{self._iter_idx}.json").to_path()
        log.info(f"Dumping state {fp}")
        state_dump = dict()
        state_dump[TAINTED_VARS] = list()
        for v in self._tainted_vars:
            state_dump[TAINTED_VARS].append((v.begin, v.end))
        state_dump[ITER_IDX] = self._iter_idx
        with open(fp, "w") as f:
            json.dump(state_dump, f)

    def _load_last_dump(self) -> Optional[Tuple[intervaltree.IntervalTree, int]]:
        pat = re.compile("sym_vars.([0-9]+).json")
        files = [f for f in os.listdir(self._analyzer_path.to_path()) if pat.match(f)]
        if len(files) == 0:
            return None

        indices = sorted([int(pat.search(f).group(1), 10) for f in files], reverse=True)
        fp = self._analyzer_path.join(f"sym_vars.{indices[0]}.json")
        if not fp.exists():
            return None

        log.info(f"Loading sym_vars {fp.to_path()}")
        with open(fp.to_path(), "r") as f:
            dump = json.load(f)
            sym_vars = intervaltree.IntervalTree()
            for v in dump[TAINTED_VARS]:
                sym_vars.add(utils.Interval(*v))
            idx = dump[ITER_IDX]
        return sym_vars, idx

    def _load_const_variables(self) -> intervaltree.IntervalTree:
        const_vars = intervaltree.IntervalTree()
        if hasattr(self.spec_mod, CONST_VARS):
            const_vars.update(self.spec_mod.__getattribute__(CONST_VARS))

        return const_vars

    def _load_symbols(self) -> List[dict]:
        symbols = list()
        if hasattr(self.spec_mod, SYMBOLS):
            symbols.extend(self.spec_mod.__getattribute__(SYMBOLS))

        return symbols

    def _load_goal_avoid_vars(self) -> intervaltree.IntervalTree:
        fp = self._analyzer_path.join("goal.avoid_vars.json")
        avoid_vars = intervaltree.IntervalTree()
        if not fp.exists():
            return avoid_vars

        with open(fp.to_path(), "r") as f:
            dump = json.load(f)
            for v in dump[AVOID_VARS]:
                avoid_vars.add(utils.Interval(*v))

        return avoid_vars

    def _dump_goal_avoid_vars(self, avoid_vars: intervaltree.IntervalTree):
        fp = self._analyzer_path.join("goal.avoid_vars.json")

        dump = dict()
        dump[AVOID_VARS] = list()
        for iv in avoid_vars:
            dump[AVOID_VARS].append((iv.begin, iv.end))
        with open(fp.to_path(), "w") as f:
            json.dump(dump, f)

    def _setup_entry_state(self, args):
        state = self._project.factory.entry_state(
            soft_memory_limit=self._soft_memory_limit,
            add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
            remove_options={angr.options.COPY_STATES},
        )

        self._init_globals(state)
        state = self._add_input_fields(state, args.pd, args.nas)
        self._load_registers(state)

        return state

    def _setup_inspection(self, state: angr.SimState, irsb=False, constraints=False):
        # Optional inspection
        state.inspect.remove_breakpoint(
            "irsb", filter_func=lambda _: True
        )  # Remove all breakpoints
        state.inspect.b("irsb", action=self._instruction_logger)

        state.inspect.remove_breakpoint("constraints", filter_func=lambda _: True)
        state.inspect.b(
            "constraints", when=angr.BP_AFTER, action=self._constraint_logger
        )

        # Mandatory inspection
        state.inspect.remove_breakpoint("mem_write", filter_func=lambda _: True)
        state.inspect.b(
            "mem_write", when=angr.BP_AFTER, action=self._var_mgr.trace_memory_write
        )
        state.inspect.remove_breakpoint("mem_read", filter_func=lambda _: True)
        state.inspect.b(
            "mem_read", when=angr.BP_AFTER, action=self._var_mgr.trace_memory_read
        )

        # Develop inspection
        # state.inspect.b("engine_process", when=angr.BP_AFTER, action=fork_logger, condition=has_successors)
        # state.inspect.b("engine_process", when=angr.BP_AFTER, action=suc_logger)
        # state.inspect.b("reg_write", when=angr.BP_AFTER, action=reg_logger)

    def _add_input_fields(
        self, state: angr.SimState, pd: int = 7, nas_msg_id: Optional[int] = None
    ):
        return self._vendor.add_input_fields(state, self._task.name, pd, nas_msg_id)

    def _load_registers(self, state: angr.SimState):
        self._vendor.load_registers(state)

    @staticmethod
    def _init_globals(state: angr.SimState):
        state.globals[SHANNON_NO_MSG] = False
        state.globals[INIT_VARS] = intervaltree.IntervalTree()
        state.globals[START_VAR_RECORD] = False
        state.globals[GOAL_SEEN] = False
        state.globals[ERRORED] = False

    def _setup_hooks(self):
        hooks = []
        if hasattr(self.spec_mod, SYMBOL_MAPPINGS):
            hooks.extend(self.spec_mod.__getattribute__(SYMBOL_MAPPINGS))
        log.info(f"Added {len(hooks)} hooks from workspace")

        self._install_symbol_hooks(hooks + self._vendor.symbol_mappings)

    def _load_add_constraints(self):
        add_cns = []
        if hasattr(self.spec_mod, ADD_CONSTRAINTS):
            add_cns.extend(self.spec_mod.__getattribute__(ADD_CONSTRAINTS))
        log.info(f"Loaded {len(add_cns)} additional constraints from workspace")
        self._add_constraints.extend(add_cns)

        goal_cns = list()
        goal_cns_path = self._analyzer_path.join("goal.constraints.pickle")
        if goal_cns_path.exists():
            with open(goal_cns_path.to_path(), "rb") as f:
                goal_cns = pickle.load(f)
        log.info(f"Loaded {len(goal_cns)} goal constraints from workspace")
        if len(goal_cns):
            self._goal_found = True
        self._goal_constraints.extend(goal_cns)

    def _additional_constraints(self, state: angr.SimState):
        for cns in self._add_constraints:
            assert "address" in cns.keys()
            assert "size" in cns.keys()
            addr = cns["address"]
            size = cns["size"]
            if not self._tainted_vars.overlaps(addr, addr + size):
                continue
            var = state.memory.load(addr, size=size, endness="Iend_LE")
            if not var.symbolic:
                continue

            if "min" in cns:
                state.solver.add(var >= cns["min"])
            if "max" in cns:
                state.solver.add(var <= cns["max"])
            if "choices" in cns:
                assert isinstance(cns["choice"], abc.Iterable)
                state.solver.add(claripy.Or(*(var == n for n in cns["choices"])))

        state.solver.add(*self._goal_constraints)

    def _lookup_symbol(self, name: str) -> int:
        sym = self._symbols.lookup(name)
        if sym is None:
            raise KeyError(f"{name}: no such symbol")
        return sym.address

    def _install_symbol_hooks(self, mappings: List[dict]):
        """
        Installs user provided hooks
        """
        for hook in mappings:
            hook = self._prepare_mapping(hook)
            if hook is None:
                continue

            for addr in hook["address"]:
                simproc = hook["simproc"]
                if not issubclass(simproc, angr.SimProcedure):
                    log.error(
                        f"Expected {angr.SimProcedure.__name__} got {simproc.__name__}"
                    )
                    continue
                log.info(f"Installing hook {simproc.__name__} at {addr:#010x}")
                self._project.hook_symbol(
                    addr, simproc(*hook["args"], analyzer=self, **hook["kwargs"])
                )

    def _prepare_mapping(self, m):
        if "symbol" in m:
            try:
                addr = self._lookup_symbol(m["symbol"])
            except KeyError:
                log.error(f"Failed to find symbol {m['symbol']} for mapping")
                return None
            m["address"] = addr

        if not isinstance(m["address"], list):
            m["address"] = [m["address"]]

        if "args" not in m:
            m["args"] = []

        if "kwargs" not in m:
            m["kwargs"] = {}

        m = self._vendor.prepare_mapping(m)

        return m

    def _second_msg(self, state: angr.SimState):
        if state.globals[ERRORED] or state.globals[SHANNON_NO_MSG]:
            self._completed_paths += 1
            log.info(f"Completed paths: {self._completed_paths}")
            return True
        return False

    def _next_major_var(self) -> Tuple[intervaltree.Interval, bool]:
        return (
            self._candidate_next_vars.next_var(),
            len(self._candidate_next_vars.rbi_vars) > 1,
        )

    def _pickle_findings(self, stash: str, state: angr.SimState):
        global loris_finished_states
        loris_finished_states += 1
        next_var = state.vars.next_var()
        if next_var is not None:
            self._candidate_next_vars.add_rbi_var(
                next_var.begin, next_var.end, next_var.data.copy()
            )
        p = multiprocessing.Process(
            target=self._pickle_findings_inner,
            args=(stash, state, self._iter_idx, self._pickle_idx),
        )
        p.start()
        p.join(self._solver_timeout)
        if p.is_alive():
            log.warning(
                f"Couldn't solve {state} constraints in {self._solver_timeout} seconds"
            )
            p.terminate()
        else:
            self._n_solutions[self._iter_idx] += 1
        self._pickle_idx += 1

    def _pickle_findings_inner(
        self, stash: str, state: angr.SimState, iter_idx: int, pickle_idx: int
    ):
        log.info("--------------------------------")
        log.info(f"# rbi_vars: {len(state.vars.rbi_vars)}")
        log.info(f"# bbl_addrs: {len(state.history.bbl_addrs)}")
        state.vars.log_vars(head=5)
        self._dump_constraints(stash, state, iter_idx, pickle_idx)
        self._dump_solutions(stash, state, iter_idx, pickle_idx)

    def _dump_constraints(
        self, stash: str, state: angr.SimState, iter_idx: int, pickle_idx: int
    ):
        filepath = self._analyzer_path.join(
            f"{stash}.constraints.{iter_idx}.txt"
        ).to_path()
        with open(filepath, "a") as f:
            f.write(f"{pickle_idx}\n")
            f.write(utils.list_fmt(state.solver.constraints))
            f.write("\n--------------------------------\n")

    def _dump_solutions(
        self, stash: str, state: angr.SimState, iter_idx: int, pickle_idx: int
    ):
        txt_fp = self._analyzer_path.join(f"{stash}.solutions.{iter_idx}.txt").to_path()
        pickle_fp = self._analyzer_path.join(
            f"{stash}.solutions.{iter_idx}.{pickle_idx}.pickle"
        ).to_path()

        log.info(f"Dumping solution into {pickle_fp}")
        res = self._var_mgr.eval_variables(state, n=10)
        with open(txt_fp, "a") as f:
            f.write(f"{pickle_idx}\n")
            f.write(utils.dict_fmt(res))
            f.write("\n--------------------------------\n")
        with open(pickle_fp, "wb") as f:
            pickle.dump(res, f)

    def _store_goal_constraints(self, states: List[angr.SimState]):
        txt_fp = self._analyzer_path.join("goal.constraints.txt")
        pickle_fp = self._analyzer_path.join("goal.constraints.pickle")
        if len(states) == 0 or pickle_fp.exists():
            return

        avoid_vars = intervaltree.IntervalTree()
        avoid_var_names = set()
        for i, st in enumerate(states[1:]):
            for iv, name in self._check_goal_constraints(
                states[0].solver.constraints, st.solver.constraints
            ):
                avoid_vars.add(iv)
                avoid_var_names.add(name)
        self._dump_goal_avoid_vars(avoid_vars)

        log.info(f"Dumping goal constraints into {pickle_fp}")
        self._goal_found = True
        all_constraints = [
            claripy.Or(
                *[
                    claripy.And(
                        *[
                            cns
                            for cns in self._filter_constraints(
                                st.solver.constraints,
                                prefix=VAR_PREFIX,
                                avoid_vars=avoid_var_names,
                            )
                        ]
                    )
                    for st in states
                ]
            )
        ]

        with open(txt_fp.to_path(), "w") as f:
            f.write(str(all_constraints))
        with open(pickle_fp.to_path(), "wb") as f:
            pickle.dump(all_constraints, f)

        if len(states) == 1:
            return

    @staticmethod
    def _filter_constraints(
        constraints: Iterable[claripy.ast.base.Base],
        prefix: Optional[str] = None,
        avoid_vars: Optional[Set[str]] = None,
    ):
        for cns in constraints:
            if prefix:
                if not any([utils.var_name2key(v)[0] == prefix for v in cns.variables]):
                    continue
            if avoid_vars:
                if all([v in avoid_vars for v in cns.variables]):
                    continue
            yield cns

    def _check_goal_constraints(
        self,
        constraints1: List[claripy.ast.base.Base],
        constraints2: List[claripy.ast.base.Base],
    ):
        all_vars = set()
        for cns in self._filter_constraints(
            itertools.chain(constraints1, constraints2), VAR_PREFIX
        ):
            all_vars.update(cns.variables)

        for v in all_vars:
            var_constraints1 = filter(lambda _cns: v in _cns.variables, constraints1)
            var_constraints2 = filter(lambda _cns: v in _cns.variables, constraints2)

            combined = itertools.starmap(
                claripy.Or, itertools.product(var_constraints1, var_constraints2)
            )
            simplified_cns = list()
            for cns in combined:
                solver = claripy.SolverCacheless()
                solver.add(cns)
                simplified_cns.append(solver.simplify().pop().is_true())
                if all(simplified_cns):
                    var_key = utils.var_name2key(v)
                    yield utils.Interval(var_key[1], var_key[1] + var_key[2]), v

    @staticmethod
    def _constraint_logger(state: angr.SimState):
        if any(ast.op != "BoolV" for ast in state.inspect.added_constraints):
            print(
                f"{state.regs.pc}: Added path constraints: {state.inspect.added_constraints}"
            )

    @staticmethod
    def _instruction_logger(state: angr.SimState):
        if log.parent.level <= logging.DEBUG:
            print("--------------------------------")
            print(f"{state} ({state.history.depth})")
            state.block().disassembly.pp()


loris_finished_states = 0
loris_last_ts = time.time()
loris_stat = {"time": list(), "finished": list(), "active": list()}


def dump_stat(filepath):
    global loris_stat
    with open(filepath, "w") as f:
        json.dump(loris_stat, f)


class LorisStat(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, stat_filepath):
        super().__init__()
        self._stat_filepath = stat_filepath

    def step(self, simgr, stash="active", **kwargs):
        global loris_finished_states, loris_last_ts, loris_stat
        simgr.step(stash=stash, **kwargs)

        curr_ts = time.time()
        if curr_ts - loris_last_ts > 5:
            loris_last_ts = curr_ts
            active_paths = len(simgr.stashes["active"]) + len(simgr.stashes["deferred"])
            loris_stat["time"].append(curr_ts)
            loris_stat["finished"].append(loris_finished_states)
            loris_stat["active"].append(active_paths)
            log.info(
                f"Finished paths: {loris_finished_states}, Active paths: {active_paths}"
            )
            dump_stat(self._stat_filepath)

        return simgr
