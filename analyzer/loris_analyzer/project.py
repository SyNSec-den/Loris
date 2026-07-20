import angr
import claripy
import logging
import psutil
import time
import z3

from typing import List, Optional, Union

from loris_analyzer.util import heap
from loris_analyzer.util.concretization import (
    SimConcretizationStrategyAny,
    SimConcretizationStrategyMax,
    SimConcretizationStrategyRange,
    SimConcretizationStrategySolutions,
)
from loris_analyzer.util import utils
from loris_analyzer.util.logging import dlog, LOG_HEAP, LOG_SOLVER, LOG_LOADER
from loris_analyzer.variable import Variables

log = logging.getLogger(__name__)


class BackendZ3Limited(type(claripy.backends.z3)):
    def __init__(self, soft_memory_limit: int):
        super().__init__()
        # self.analyzer = analyzer
        self.soft_memory_limit = soft_memory_limit

    def _check_is_too_complex(self, expr: claripy.ast.Base):
        return

    def _check_needs_downsize(self):
        mem_usage = psutil.Process().memory_info().rss
        if mem_usage >= self.soft_memory_limit:
            log.warning(
                f"Hit soft memory limit (usage: {mem_usage//1024**2} MiB). Clearing caches..."
            )

            self.downsize()
            # TODO: FIX ME
            # self.analyzer.explorer.downsize()
            utils.trim_global_memory()
            time.sleep(0.5)

            mem_usage = psutil.Process().memory_info().rss
            if mem_usage >= self.soft_memory_limit:
                raise RuntimeError(
                    f"Could not reduce memory usage below soft memory limit "
                    f"(usage: {mem_usage//1024**2} MiB)."
                )
            else:
                log.info(f"Reduced memory usage to {mem_usage//1024**2} MiB")

    def add(self, s, c, track=False):
        self._check_needs_downsize()
        for cns in c:
            self._check_is_too_complex(cns)

        super().add(s, c, track)

    def simplify(self, expr):
        self._check_needs_downsize()
        self._check_is_too_complex(expr)
        return super().simplify(expr)

    def eval(self, expr, n, extra_constraints=(), solver=None, model_callback=None):
        self._check_needs_downsize()
        self._check_is_too_complex(expr)
        for expr in extra_constraints:
            self._check_is_too_complex(expr)
        return super().eval(expr, n, extra_constraints, solver, model_callback)

    def batch_eval(
        self, exprs, n, extra_constraints=(), solver=None, model_callback=None
    ):
        self._check_needs_downsize()
        for expr in exprs:
            self._check_is_too_complex(expr)
        for expr in extra_constraints:
            self._check_is_too_complex(expr)
        return super().batch_eval(exprs, n, extra_constraints, solver, model_callback)

    def check_satisfiability(
        self, extra_constraints=(), solver=None, model_callback=None
    ):
        self._check_needs_downsize()
        for expr in extra_constraints:
            self._check_is_too_complex(expr)
        return super().check_satisfiability(extra_constraints, solver, model_callback)

    def satisfiable(self, extra_constraints=(), solver=None, model_callback=None):
        self._check_needs_downsize()
        for expr in extra_constraints:
            self._check_is_too_complex(expr)
        return super().satisfiable(extra_constraints, solver, model_callback)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} soft_memory_limit={self.soft_memory_limit}>"


class SimUCManager(angr.state_plugins.SimStatePlugin):
    def __init__(self, man=None):
        angr.state_plugins.SimStatePlugin.__init__(self)
        if man is None:
            self._alloc_size = 0x300
            self._max_alloc_depth = 20
            self._alloc_depth_map = {}
        else:
            self._alloc_size = man._alloc_size
            self._max_alloc_depth = man._max_alloc_depth
            self._alloc_depth_map = man._alloc_depth_map.copy()

    @property
    def alloc_size(self) -> int:
        return self._alloc_size

    def assign(self, dst_addr_ast):
        """
        Assign a new region for under-constrained symbolic execution.

        :param dst_addr_ast: the symbolic AST which address of the new allocated region will be assigned to.
        :return: as ast of memory address that points to a new region
        """

        if dst_addr_ast.uc_alloc_depth > self._max_alloc_depth:
            raise angr.errors.SimUCManagerAllocationError(
                f"Current allocation depth {dst_addr_ast.uc_alloc_depth} "
                f"is greater than the cap ({self._max_alloc_depth})"
            )

        abs_addr = heap.allocate(self.state, self._alloc_size)
        ptr = self.state.solver.BVV(abs_addr, self.state.arch.bits)

        self._alloc_depth_map[abs_addr] = dst_addr_ast.uc_alloc_depth

        dlog(LOG_HEAP, f"Assigned new memory region {ptr}(size={self._alloc_size:#x})")
        return ptr

    @angr.sim_state.SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        return SimUCManager(man=self)

    def get_alloc_depth(self, addr: int):
        if addr not in self._alloc_depth_map:
            return None

        return self._alloc_depth_map[addr]

    def is_bounded(self, ast):
        """
        Test whether an AST is bounded by any existing constraint in the related solver.

        :param ast: a claripy.AST object
        :return: True if there is at least one related constraint, False otherwise
        """
        res = len(ast.variables.intersection(self.state.solver._solver.variables)) != 0
        dlog(
            LOG_SOLVER,
            f"{self.__class__.__name__}::is_bounded:addr={ast}, res={res}\n"
            f"\tast.variables={ast.variables}\n"
            f"\tself.state.solver._solver.variables={self.state.solver._solver.variables}\n"
            f"\tself.state.solver.constraints={self.state.solver.constraints}\n",
        )
        return res


class LorisFactory(angr.factory.AngrObjectFactory):
    def entry_state(
        self, soft_memory_limit: Optional[int] = None, **kwargs
    ) -> angr.SimState:
        add_options = {
            angr.options.BYPASS_UNSUPPORTED_SYSCALL,
            angr.options.TRACK_CONSTRAINTS,
            angr.options.UNDER_CONSTRAINED_SYMEXEC,
        }
        add_options.update(kwargs.pop("add_options", set()))

        dlog(LOG_LOADER, f"add_options: {add_options}")
        state = super().entry_state(add_options=add_options, **kwargs)
        if soft_memory_limit is None:
            solver = claripy.Solver()
        else:
            claripy.backends._register_backend(
                BackendZ3Limited(soft_memory_limit), "BackendZ3Limited", False, False
            )
            max_memory = 8000  # Maximum Z3 memory in megabytes
            timeout = 3000  # Timeout (in milliseconds) used for Z3 solver
            solver = claripy.Solver(
                backend=BackendZ3Limited(soft_memory_limit),
                max_memory=max_memory,
                timeout=timeout,
            )
        state.register_plugin("solver", angr.state_plugins.SimSolver(solver=solver))
        state.register_plugin(
            "heap", angr.SimHeapPTMalloc(heap_base=0xBD000000, heap_size=0x1000000)
        )
        state.register_plugin("vars", Variables())
        heap.print_all_chunks(state)
        state.register_plugin("uc_manager", SimUCManager())
        state.memory.read_strategies = [
            SimConcretizationStrategySolutions(20),
            SimConcretizationStrategyRange(1024),
            SimConcretizationStrategyAny(),
        ]
        state.memory.write_strategies = [
            SimConcretizationStrategyRange(128),
            SimConcretizationStrategyMax((1 << state.arch.bits) - 1),
        ]
        heap.print_all_chunks(state)

        return state

    def simulation_manager(
        self, thing: Union[List[angr.SimState], angr.SimState, None] = None, **kwargs
    ) -> utils.SimulationManager:

        if thing is None:
            thing = [self.entry_state()]
        elif isinstance(thing, (list, tuple)):
            if any(not isinstance(val, angr.SimState) for val in thing):
                raise angr.AngrError("Bad type to initialize SimulationManager")
        elif isinstance(thing, angr.SimState):
            thing = [thing]
        else:
            raise angr.AngrError(
                "BadType to initialze SimulationManager: %s" % repr(thing)
            )

        return utils.SimulationManager(
            self.project, active_states=thing, exception_list=[z3.Z3Exception], **kwargs
        )


class LorisProject(angr.Project):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.factory = LorisFactory(self)
