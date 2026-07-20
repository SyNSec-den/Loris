import angr
import avatar2
import claripy
import logging
import struct

from typing import List, Optional, Union

from loris_analyzer.globals import *
from loris_analyzer.util import heap
from loris_analyzer.util.logging import dlog, LOG_SIM, LOG_LOADER
from loris_analyzer.vendor import shannon, Vendor
from loris_analyzer.util import utils
from loris_analyzer.vendor.shannon.qitem import get_payload, QItem

log = logging.getLogger(__name__)


class Shannon(Vendor):
    def __init__(self, queues: list, task, regs=None, thumb=False):
        super().__init__(shannon.hooks.symbol_mappings)
        self._queues = queues
        self._thumb = thumb
        if regs is not None:
            for name in regs.__dict__.keys():
                if name == "_target":
                    continue
                try:
                    self._regs.__setattr__(name, regs.__getattribute__(name))
                except ValueError:
                    dlog(LOG_LOADER, f"Skipping non-scalar register: {name}")

    def add_input_fields(
        self,
        state: angr.SimState,
        task: str,
        protocol_disc: int,
        nas_msg_id_list: Optional[Union[int, List[int]]] = None,
    ):
        if task == SHANNON_SAEL3:
            return self._add_input_fields_sael3(state, protocol_disc, nas_msg_id_list)
        elif task == SHANNON_NASOT:
            return self._add_input_fields_nasot(state, protocol_disc, nas_msg_id_list)

    def load_registers(self, state: angr.SimState):
        super(Shannon, self).load_registers(state)
        if self._thumb:
            state.regs.pc |= 1

    def prepare_mapping(self, m) -> Optional[dict]:
        if m["name"] == "pal_MsgReceiveMbx":
            try:
                qid = self._get_qid_by_name(SHANNON_SAEL3)
            except KeyError:
                log.error(f"Failed to find queue {SHANNON_SAEL3} for mapping")
                return None
            try:
                sync_qid = self._get_qid_by_name("SAEL3_SYNC")
            except KeyError:
                sync_qid = None

            m["kwargs"] = {
                "num_msg_buf": 1,
                "qid": qid,
                "sync_qid": sync_qid,
            }

        return m

    def _add_input_fields_sael3(
        self,
        state: angr.SimState,
        protocol_disc: int,
        nas_msg_id_list: Optional[Union[int, List[int]]] = None,
    ):
        assert (
            protocol_disc == 2 or protocol_disc == 7
        ), "Unknown protocol discriminator"

        if nas_msg_id_list is None:
            if protocol_disc == 7:
                nas_msg_id_list = self.NAS_EMM_MSG_ID_LIST
            elif protocol_disc == 2:
                nas_msg_id_list = self.NAS_ESM_MSG_ID_LIST
        elif isinstance(nas_msg_id_list, int):
            nas_msg_id_list = [nas_msg_id_list]

        # Get message info
        msg_id = 0x3C7B
        src_qid = self._get_qid_by_name("LTERRC")
        assert src_qid, "no such queue: LTERRC"
        dst_qid = self._get_qid_by_name(SHANNON_SAEL3)
        assert dst_qid, "no such queue: SAEL3"
        qitem = QItem(payload=get_payload(msg_id))
        # allocate qitem
        p_msg = heap.allocate(state, qitem.header_size + qitem.payload.size)
        state.globals[SHANNON_MSG_BUF] = p_msg
        # populate qitem header
        state.memory.store(p_msg + 0, src_qid, size=2, endness="Iend_LE")
        state.memory.store(p_msg + 2, dst_qid, size=2, endness="Iend_LE")
        state.memory.store(p_msg + 4, qitem.payload.size, size=2, endness="Iend_LE")
        state.memory.store(p_msg + 6, msg_id, size=2, endness="Iend_LE")

        # populate qitem payload
        bw = state.arch.byte_width
        ptr_size = state.arch.bits // bw
        p_payload = p_msg + qitem.header_size
        state.memory.store(p_payload, 0, size=1)
        p_ded_info_nas = state.memory.load(
            p_payload + 8, size=ptr_size, endness="Iend_LE"
        )
        assert p_ded_info_nas.uc_alloc_depth == 0

        # the next load will use state.uc_manager to allocate a memory region for p_ded_info_nas
        _ = state.memory.load(p_ded_info_nas, size=1)
        p_ded_info_nas = state.solver.eval_one(p_ded_info_nas)
        dlog(
            LOG_SIM,
            f"{self.__class__.__name__}::add_input_fields:"
            f"p_payload={p_payload}, p_ded_info_nas={p_ded_info_nas:#010x}",
        )

        if protocol_disc == 7:
            addr = p_ded_info_nas + 1
            size = 1
            key = (INPUT_PREFIX, addr, size, NAS_MSG_ID)
        elif protocol_disc == 2:
            addr = p_ded_info_nas + 2
            size = 1
            key = (INPUT_PREFIX, addr, size, NAS_MSG_ID)
        else:
            raise AssertionError("Unknown protocol discriminator")
        name = utils.var_key2name(key)
        nas_msg_id = state.solver.BVS(
            name, size * bw, explicit_name=True, eternal=True, key=key
        )

        state.solver.add(claripy.Or(*(nas_msg_id == n for n in nas_msg_id_list)))

        addr = p_ded_info_nas
        size = 1
        key = (INPUT_PREFIX, addr, size, SHT_PD)
        name = utils.var_key2name(key)
        first_byte = state.solver.BVS(
            name, size * bw, explicit_name=True, eternal=True, key=key
        )
        pd = first_byte[3:0]
        state.solver.add(pd == protocol_disc)  # EMM Message

        sec_hdr_type = first_byte[7:4]
        state.solver.add(sec_hdr_type == 0)  # Plain

        first_byte = claripy.Concat(sec_hdr_type, pd)
        state.memory.store(p_ded_info_nas, first_byte)
        if protocol_disc == 7:
            state.memory.store(p_ded_info_nas + 1, nas_msg_id)
        elif protocol_disc == 2:
            state.memory.store(p_ded_info_nas + 2, nas_msg_id)

        ded_info_nas_size = state.memory.load(p_payload + 4, size=2, endness="Iend_LE")
        dlog(
            LOG_SIM,
            f"{self.__class__.__name__}::add_input_fields:"
            f"ded_info_nas_size={ded_info_nas_size}",
        )
        state.solver.add(ded_info_nas_size == state.uc_manager.alloc_size)

        if protocol_disc == 7:
            two_bytes = state.memory.load(p_ded_info_nas, size=2, endness="Iend_BE")
        elif protocol_disc == 2:
            two_bytes = state.memory.load(p_ded_info_nas, size=3, endness="Iend_BE")
        dlog(
            LOG_SIM,
            f"{self.__class__.__name__}::add_input_fields:"
            f"p_ded_info_nas={p_ded_info_nas}\n"
            f"ded_info_nas(few bytes)={two_bytes}\n"
            f"state.solver.constraints={state.solver.constraints}",
        )

        return state

    def _add_input_fields_nasot(
        self,
        state: angr.SimState,
    ):
        p_msg = heap.allocate(state, 0x1000 + 8)

        msg_name = "MM_RRC_DATA_IND"
        p_msg_name = heap.allocate(state, len(msg_name))
        state.memory.store(p_msg_name, msg_name, size=len(msg_name), endness="Iend_BE")

        nrmm_data = struct.pack(
            "<IIIBBHIIIIBHBIIIH",
            0x440E087,  # field_0x0
            (0x440E087 >> 0xC) | 0x7FE00400,  # field_0x4
            (0x440E087 >> 0x16) | 0x7FE00400,  # field_0x8
            0x40,  # field_0xc
            0,  # domain_type
            0,
            0x80,  # field_0x10
            0,
            0,
            0,
            4,  # field_0x20
            0,
            0,
            0x48,  # size
            p_msg_name,  # name
            p_msg + 8,  # pData
            0x1000,  # dataLength
        )
        p_nrmm_data = heap.allocate(state, len(nrmm_data))
        state.memory.store(
            p_nrmm_data, nrmm_data, size=len(nrmm_data), endness="Iend_BE"
        )

        state.inspect.b("call", when=angr.BP_AFTER, action=self._function_hooks)
        state.globals[SHANNON_MSG_BUF] = p_nrmm_data

    @staticmethod
    def _function_hooks(state: angr.SimState):
        dlog(
            LOG_SIM,
            f"_function_hooks: function_address={state.inspect.function_address}",
        )
        faddr = state.inspect.function_address & ~1
        faddr = utils.try_eval_one(state, faddr)
        ptr_size = state.arch.bits // state.arch.byte_width
        if faddr == 0x41C54000:
            # set FtObj ptr
            param_1 = state.regs.r0
            p_ftobj = 0x46B5853C
            pp_ftobj = state.memory.load(
                param_1 + 0x24, size=ptr_size, endness="Iend_LE"
            )
            state.memory.store(pp_ftobj, p_ftobj, size=ptr_size, endness="Iend_LE")
            state.memory.store(param_1 + 0x14, 1, size=4, endness="Iend_LE")
            p_transceiver = state.memory.load(
                p_ftobj + 0x24, size=ptr_size, endness="Iend_LE"
            )

            p_nrmm_data = state.globals[SHANNON_MSG_BUF]
            pp_nrmm_data = heap.allocate(state, ptr_size)
            state.memory.store(
                pp_nrmm_data, p_nrmm_data, size=ptr_size, endness="Iend_LE"
            )

            state.memory.store(p_transceiver + 0x10, 1, size=4, endness="Iend_LE")
            state.memory.store(
                p_transceiver + 0x20, pp_nrmm_data, size=ptr_size, endness="Iend_LE"
            )

            dlog(
                LOG_SIM,
                f"_function_hooks: SchedDataPriority={param_1}, pp_ftobj={pp_ftobj}",
            )
            state.globals[START_VAR_RECORD] = True

    def _get_qid_by_name(self, name: str) -> Optional[int]:
        for q in self._queues:
            if q.name == name:
                return q.qid

        return None
