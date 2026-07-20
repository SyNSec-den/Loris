import angr
import claripy
import logging

from typing import Optional

from loris_analyzer.globals import *
from loris_analyzer.util import heap, utils
from loris_analyzer.util.logging import dlog, LOG_SIM
from loris_analyzer.vendor.hooks import (
    SimError,
    SimMemcpy,
    SimSkipFunction,
    SimReturnZero,
)

log = logging.getLogger(__name__)


class SimMemAlloc(utils.SimProcedure):
    def run(self, _type, size, _file, _line):
        self._log_call(_type, size, _file, _line)
        if size.symbolic:
            alloc_size = self.state.solver.max(size)
        else:
            alloc_size = self.state.solver.eval(size)
        return heap.allocate(self.state, alloc_size)


class SimMemFree(utils.SimProcedure):
    def run(self, pp_buf):
        self._log_call(pp_buf)
        ptr_size = self.state.arch.bits // self.state.arch.byte_width
        pp_buf = utils.try_eval_one(self.state, pp_buf)
        if not isinstance(pp_buf, int):
            log.warning(f"Attempted to free a symbolic ptr in {pp_buf}")
            return 1
        p_buf = self.state.memory.load(pp_buf, size=ptr_size, endness="Iend_LE")
        return heap.free(self.state, p_buf)


class SimMemsetBSV(utils.SimProcedure):
    """
    Memset Buffer-Size-Value
    """

    def run(self, buf_ptr, size, value):
        self._log_call(buf_ptr, size, value)
        if self.state.solver.max(size, signed=False) > 0x100000:
            log.warning(
                f"Maximum size for Memset exceeded: "
                f"{utils.ast_debug_str(size)} to address {utils.ast_debug_str(buf_ptr)}"
            )
        else:
            size = self.state.solver.eval(size)
            buf_ptr = self.state.solver.eval_one(buf_ptr)
            for i in range(size):
                self.state.memory.store(buf_ptr + i, value[7:0], endness="Iend_LE")


class SimMemequal(utils.SimProcedure):
    def run(self, ptr1, ptr2, size):
        self._log_call(ptr1, ptr2, size)
        conc_len = self.state.solver.max(size, signed=False)
        if conc_len > 0x100000:
            log.warning("Maximum size for memequal exceeded")
            return claripy.Or(claripy.BVV(0, 32), claripy.BVV(1, 32))
        else:
            size = self.state.solver.eval(size)
            ptr1 = self.state.solver.eval_one(ptr1)
            ptr2 = self.state.solver.eval_one(ptr2)
            dlog(
                LOG_SIM,
                f"{self.__class__.__name__}: ptr1={ptr1:#010x}, ptr2={ptr2:#010x}, size={size:#x}",
            )

            ptr1_value = self.state.memory.load(ptr1, size=conc_len, endness="Iend_LE")
            ptr2_value = self.state.memory.load(ptr2, size=conc_len, endness="Iend_LE")
            return claripy.If(
                ptr1_value == ptr2_value, claripy.BVV(1, 32), claripy.BVV(0, 32)
            )


class SimSendMsg(utils.SimProcedure):
    def run(self, qid, buf_addr, item_type):
        self._log_call(qid, buf_addr, item_type)
        log.info(f"Sent message at {buf_addr} to queue ID {qid} (type={item_type})")
        heap.free(self.state, buf_addr)
        return 0


class SimReceiveMessageMbx(utils.SimProcedure):
    def __init__(
        self,
        *args,
        qid: Optional[int] = None,
        sync_qid: Optional[int] = None,
        num_msg_buf: int = 1,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._num_msg_buf = num_msg_buf
        self._qid = qid
        self._sync_qid = sync_qid

    def run(self, qid, pp_qitem, p_qitem_type, blocking):
        self._log_call(qid, pp_qitem, p_qitem_type, blocking)
        try:
            conc_qid = self.state.solver.eval_exact(qid, 1)[0]
        except angr.SimValueError:
            log.warning(
                f"Message receive unsuccessful: Could not determine queue ID from expression {qid}"
            )
            return 1

        if conc_qid == self._sync_qid:
            dlog(LOG_SIM, "Received message on sync queue, returning 1.")
            return 1

        if conc_qid == self._qid:
            curr_msg_idx = 0
            if SHANNON_MSG_RCVD in self.state.globals:
                curr_msg_idx = self.state.globals[SHANNON_MSG_RCVD]

            if curr_msg_idx < self._num_msg_buf:
                msg_buf = self.state.globals[SHANNON_MSG_BUF]
                log.info(
                    f"Receiving simulated external queue message at {msg_buf:#010x}"
                )
                self.state.memory.store(pp_qitem, msg_buf, size=4, endness="Iend_LE")
                self.state.memory.store(p_qitem_type, 2, size=1, endness="Iend_LE")

                self.state.globals[SHANNON_MSG_RCVD] = curr_msg_idx + 1
                self.state.globals[START_VAR_RECORD] = True
                return 0
            else:
                log.info(
                    f"Message receive unsuccessful: No messages left in external queue."
                )
                self.state.globals[SHANNON_NO_MSG] = True
                self.state.globals[START_VAR_RECORD] = False
                return 1
        else:
            log.warning(
                f"Attempted to receive message on unknown queue ID {conc_qid:#x} (expected {self._qid:#x})"
            )
            return 1


class SimRetrieveEvents(utils.SimProcedure):
    def __init__(self, event_group, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._event_group = event_group

    def run(self, event_group, param_2, param_3, param_4, param_5):
        self._log_call(event_group, param_2, param_3, param_4, param_5)
        event_flag = self.state.memory.load(
            event_group + 0x2C, size=4, endness="Iend_LE"
        )
        log.info(
            f"OS_Retrieve_Events(event_group={event_group}) event_flag={event_flag}"
        )
        try:
            event_group = self.state.solver.eval_exact(event_group, 1)[0]
        except angr.SimValueError:
            log.warning(
                f"Event retrieve unsuccessful: Could not determine event group from expression {event_group}"
            )
            return 1

        if event_group == self._event_group:
            # curr_msg_idx = self.state.globals.get(SHANNON_MSG_RCVD, 0)
            # if curr_msg_idx < 1:
            if utils.try_eval_one(self.state, event_flag) == 1:
                log.info(f"Retrieving an event")
                self.state.memory.store(
                    event_group + 0x2C, 0, size=4, endness="Iend_LE"
                )
                # msg_buf = self.state.globals[SHANNON_MSG_BUF]
                # log.info(f"Retrieving simulated external queue message at {msg_buf:#010x}")
                # self.state.globals[SHANNON_MSG_RCVD] = curr_msg_idx + 1
                return 0
            else:
                log.info(
                    f"Event retrieve unsuccessful: No messages left in external queue."
                )
                self.state.globals[SHANNON_NO_MSG] = True
                self.state.globals[START_VAR_RECORD] = False
                return 1
        else:
            log.warning(
                f"Attempted to retrieve event on unknown event_group 0x{event_group:x}."
            )
            return 1


# def prepare_mapping(m, queues) -> dict:
#     if m["name"] == "pal_MsgReceiveMbx":
#         m["kwargs"] = {
#             "num_msg_buf": 1,
#             "qid": queues.get(SHANNON_SAEL3),
#             # "sync_qid": self._vendor["queues"].get("SAEL3_SYNC"),
#         }

#     return m


symbol_mappings = [
    {
        "name": "disableIRQinterrupts",
        "symbol": "disableIRQinterrupts",
        "simproc": SimSkipFunction,
    },
    {
        "name": "disableIRQinterrupts_trap",
        "symbol": "disableIRQinterrupts_trap",
        "simproc": SimSkipFunction,
    },
    {
        "name": "enableIRQinterrupts",
        "symbol": "enableIRQinterrupts",
        "simproc": SimSkipFunction,
    },
    {
        "name": "enableIRQinterrupts_trap",
        "symbol": "enableIRQinterrupts_trap",
        "simproc": SimSkipFunction,
    },
    {
        "name": "log_printf",
        "symbol": "log_printf",
        "simproc": SimSkipFunction,
    },
    {
        "name": "OS_fatal_error",
        "symbol": "OS_fatal_error",
        "simproc": SimError,
    },
    {
        "name": "pal_MemAlloc",
        "symbol": "pal_MemAlloc",
        "simproc": SimMemAlloc,
    },
    {
        "name": "pal_MemFree",
        "symbol": "pal_MemFree",
        "simproc": SimMemFree,
    },
    {
        "name": "pal_MsgSendTo",
        "symbol": "pal_MsgSendTo",
        "simproc": SimSendMsg,
    },
    {
        "name": "pal_SmSetEvent",
        "symbol": "pal_SmSetEvent",
        "simproc": SimReturnZero,
    },
    {
        "name": "pal_MsgReceiveMbx",
        "symbol": "pal_MsgReceiveMbx",
        "simproc": SimReceiveMessageMbx,
    },
]
