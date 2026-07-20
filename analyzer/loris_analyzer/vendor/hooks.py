import claripy
import logging

from loris_analyzer.globals import *
from loris_analyzer.util import utils

log = logging.getLogger(__name__)


class SimMemzero(utils.SimProcedure):
    def run(self, buf_ptr, size):
        self._log_call(buf_ptr, size)
        if self.state.solver.max(size, signed=False) > 0x100000:
            log.warning(
                f"Maximum size for Memzero exceeded: "
                f"{utils.ast_debug_str(size)} to address {utils.ast_debug_str(buf_ptr)}"
            )
        else:
            size = self.state.solver.eval(size)
            buf_ptr = self.state.solver.eval_one(buf_ptr)
            for i in range(size):
                self.state.memory.store(
                    buf_ptr + i, self.state.solver.BVV(0, 8), endness="Iend_LE"
                )


class SimMemcmp(utils.SimProcedure):
    def run(self, ptr1, ptr2, size):
        self._log_call(ptr1, ptr2, size)
        conc_len = self.state.solver.max(size, signed=False)
        if conc_len > 0x100000:
            log.warning("Maximum size for memequal exceeded")
            return claripy.Or(claripy.BVV(0, 32), claripy.BVV(1, 32))
        else:
            ptr1 = self.state.solver.eval_one(ptr1)
            ptr2 = self.state.solver.eval_one(ptr2)

            ptr1_value = self.state.memory.load(ptr1, size=conc_len, endness="Iend_LE")
            ptr2_value = self.state.memory.load(ptr2, size=conc_len, endness="Iend_LE")
            # FIXME: only works for equality checking
            return claripy.If(
                ptr1_value != ptr2_value, claripy.BVV(1, 32), claripy.BVV(0, 32)
            )


class SimMemcpy(utils.SimProcedure):
    def run(self, dst_ptr, src_ptr, size):
        self._log_call(dst_ptr, src_ptr, size)
        if self.state.solver.max(size, signed=False) > 0x100000:
            log.warning(
                f"Maximum size for Memcpy exceeded: {utils.ast_debug_str(size)} from address "
                f"{utils.ast_debug_str(src_ptr)} to {utils.ast_debug_str(dst_ptr)}"
            )
        else:
            size = self.state.solver.eval(size)
            src_ptr = self.state.solver.eval_one(src_ptr)
            dst_ptr = self.state.solver.eval_one(dst_ptr)
            data = self.state.memory.load(src_ptr, size=size, endness="Iend_BE")
            self.state.memory.store(dst_ptr, data, endness="Iend_BE")


class SimSkipFunction(utils.SimProcedure):
    def run(self):
        self._log_call()
        return


class SimReturnZero(utils.SimProcedure):
    def run(self, *args, **kwargs):
        self._log_call(*args)
        return 0


class SimError(utils.SimProcedure):
    def run(self, *args, **kwargs):
        self._log_call(*args)
        self.state.globals[ERRORED] = True
        return


class SimReturnOne(utils.SimProcedure):
    def run(self, *args, **kwargs):
        self._log_call(*args)
        return 1
