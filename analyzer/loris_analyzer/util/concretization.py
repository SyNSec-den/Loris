import angr
import claripy

from typing import Optional

from loris_analyzer.util.logging import dlog, LOG_CONC


class SimConcretizationStrategyRange(
    angr.concretization_strategies.SimConcretizationStrategy
):
    """
    Concretization strategy that resolves addresses to a range.
    Use for debugging
    """

    def __init__(self, limit, **kwargs):  # pylint:disable=redefined-builtin
        super().__init__(**kwargs)
        self._limit = limit

    def _concretize(self, memory, addr, **kwargs):
        addr_str = f"{addr:#010x}" if isinstance(addr, int) else str(addr)
        dlog(LOG_CONC, f"{self.__class__.__name__}::_concretize:" f"addr={addr_str}")
        a = memory.state.solver.satisfiable(**kwargs)
        if not a:
            import traceback

            traceback.print_stack()
            dlog(
                LOG_CONC,
                f"{self.__class__.__name__}::_concretize:"
                f"constraints={memory.state.solver.constraints}, kwargs={kwargs}",
            )
            extra_constraints = kwargs.get("extra_constraints", (claripy.false,))
            kwargs["extra_constraints"] = (
                claripy.Or(*[claripy.Not(e) for e in extra_constraints]),
            )
        mn, mx = self._range(memory, addr, **kwargs)
        addr_str = f"{addr:#010x}" if isinstance(addr, int) else str(addr)
        mn_str = f"{mn:#010x}" if isinstance(mn, int) else str(mn)
        mx_str = f"{mx:#010x}" if isinstance(mx, int) else str(mx)
        sub_str = f"{mx - mn:#x}" if isinstance(mx - mn, int) else str(mx - mn)
        dlog(
            LOG_CONC,
            f"{self.__class__.__name__}::_concretize:"
            f"limit={self._limit}, mn={mn_str}, mx={mx_str}, mx - mn={sub_str}\n"
            f"addr={addr_str}",
        )
        if mx - mn <= self._limit:
            conc = self._eval(memory, addr, self._limit, **kwargs)
            conc_repr = [f"{addr:#010x}" for addr in conc]
            dlog(
                LOG_CONC, f"{self.__class__.__name__}::_concretize:" f"conc={conc_repr}"
            )
            return conc
        return None


class SimConcretizationStrategyAny(
    angr.concretization_strategies.SimConcretizationStrategy
):
    """
    Concretization strategy that returns any single solution.
    Use for debugging
    """

    def _concretize(self, memory, addr, **kwargs):
        addr_str = f"{addr:#010x}" if isinstance(addr, int) else str(addr)
        dlog(LOG_CONC, f"{self.__class__.__name__}::_concretize:" f"addr={addr_str}")
        a = memory.state.solver.satisfiable(**kwargs)
        if not a:
            dlog(
                LOG_CONC,
                f"{self.__class__.__name__}::_concretize:"
                f"constraints={memory.state.solver.constraints}, kwargs={kwargs}",
            )
            extra_constraints = kwargs.get("extra_constraints", (claripy.false,))
            kwargs["extra_constraints"] = (
                claripy.Or(*[claripy.Not(e) for e in extra_constraints]),
            )
        if self._exact:
            conc = [self._any(memory, addr, **kwargs)]
            conc_repr = [f"{addr:#010x}" for addr in conc]
            dlog(
                LOG_CONC, f"{self.__class__.__name__}::_concretize:" f"conc={conc_repr}"
            )
            return conc
        else:
            mn, mx = self._range(memory, addr, **kwargs)
            mn_str = f"{mn:#010x}" if isinstance(mn, int) else str(mn)
            mx_str = f"{mx:#010x}" if isinstance(mx, int) else str(mx)
            dlog(
                LOG_CONC,
                f"{self.__class__.__name__}::_concretize:" f"mn={mn_str}, mx={mx_str}",
            )
            if mn == mx:
                return [mn]


class SimConcretizationStrategySolutions(
    angr.concretization_strategies.SimConcretizationStrategy
):
    """
    Concretization strategy that resolves an address into some
    limited number of solutions.
    Use for debugging
    """

    def __init__(self, limit, **kwargs):
        super().__init__(**kwargs)
        self._limit = limit

    def _concretize(self, memory, addr, **kwargs):
        addr_str = f"{addr:#010x}" if isinstance(addr, int) else str(addr)
        dlog(LOG_CONC, f"{self.__class__.__name__}::_concretize:" f"addr={addr_str}")
        a = memory.state.solver.satisfiable(**kwargs)
        if not a:
            dlog(
                LOG_CONC,
                f"{self.__class__.__name__}::_concretize:"
                f"constraints={memory.state.solver.constraints}, kwargs={kwargs}",
            )
            extra_constraints = kwargs.get("extra_constraints", (claripy.false,))
            kwargs["extra_constraints"] = (
                claripy.Or(*[claripy.Not(e) for e in extra_constraints]),
            )
        addrs = self._eval(memory, addr, self._limit + 1, **kwargs)
        addrs_repr = ", ".join([f"{a:#010x}" for a in addrs])
        dlog(
            LOG_CONC,
            f"{self.__class__.__name__}::_concretize:"
            f"self._limit={self._limit}, addr={addr}, len(addrs)={len(addrs)}, addrs={addrs_repr}",
        )
        if len(addrs) <= self._limit:
            return addrs
        return None


class SimConcretizationStrategyMax(
    angr.concretization_strategies.SimConcretizationStrategy
):
    """
    Concretization strategy that returns the maximum address.
    Use for debugging
    """

    def __init__(self, max_addr: Optional[int] = None):
        super().__init__()
        self._max_addr = max_addr

    def _concretize(self, memory, addr, **kwargs):
        extra_constraints = kwargs.pop("extra_constraints", None)
        extra_constraints = (
            tuple(extra_constraints) if extra_constraints is not None else ()
        )
        if self._max_addr is None:
            return [
                self._max(memory, addr, extra_constraints=extra_constraints, **kwargs)
            ]
        else:
            try:
                child_constraints = (addr <= self._max_addr,) + extra_constraints
                return [self._max(memory, addr, extra_constraints=child_constraints)]
            except angr.SimSolverError:
                return [
                    self._max(
                        memory, addr, extra_constraints=extra_constraints, **kwargs
                    )
                ]
