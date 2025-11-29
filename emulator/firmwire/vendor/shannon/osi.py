## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct

from abc import ABC, abstractmethod
from collections import OrderedDict
from pandare import Panda
from typing import Optional

from .task import Task
from .pal_structs import PALQueue
from firmwire.util.panda import read_cstring_panda


class ShannonOSI(ABC):
    @property
    @abstractmethod
    def panda(self) -> Panda:
        pass

    @property
    @abstractmethod
    def symbol_table(self):
        pass

    @property
    @abstractmethod
    def task_layout(self):
        pass

    def physical_memory_read(self, ptr: int, size: int) -> bytes:
        return self.panda.physical_memory_read(ptr, size)

    def physical_memory_write(self, ptr: int, buf: bytes) -> bool:
        return self.panda.physical_memory_write(ptr, buf)

    def read_cstring_panda(self, ptr: int) -> str:
        return read_cstring_panda(self.panda, ptr)

    def get_task_name_by_id(self, task_id):
        task_arr = self.symbol_table.lookup("SYM_TASK_LIST").address

        if task_arr is None:
            return None

        task_struct = self._read_task(task_arr, task_id)

        if task_struct.name_ptr == 0:
            return None

        task_struct.name = read_cstring_panda(self.panda, task_struct.name_ptr)
        return task_struct

    def get_task_by_name(self, name: str) -> Optional[Task]:
        tasks = self.get_tasks()
        for t in tasks:
            if t.name == name:
                return t

        return None

    def get_current_task_id(self):
        if self.modem_soc.name == "S5123AP":
            return struct.unpack("I", self.panda.physical_memory_read(0x4618b6c0, 4))[0]
        else:
            sym = self.symbol_table.lookup("SYM_CUR_TASK_ID", single=True)

            if sym is None:
                return None

            return struct.unpack("I", self.panda.physical_memory_read(sym.address, 4))[0]

    def get_current_task_name(self, cpustate):
        if self.modem_soc.name in ("S5123AP", "S5123"):
            sym = self.symbol_table.lookup("SYM_CUR_TASK_PTR")
            if sym is None:
                return "ERROR_MISSING_SYM"

            p_task_struct = struct.unpack("I", self.panda.physical_memory_read(sym.address, 4))[0]
            if p_task_struct == 0 or p_task_struct == 0x50505050:
                return "NO_TASK"
            return read_cstring_panda(self.panda, p_task_struct + 0x24, max_length=9)
        elif self.modem_soc.name == "S5133AP":
            p_task_struct = cpustate.env_ptr.cp15.tpidrprw_ns
            if p_task_struct == 0:
                return "NO_TASK"

            return read_cstring_panda(self.panda, p_task_struct + self.task_layout.SUBTASK_NAME_OFFSET, max_length=self.task_layout.SUBTASK_NAME_SIZE+1)
        else:
            tid = self.get_current_task_id()

            if tid is None:
                return "ERROR_MISSING_SYM"

            name = self.get_sch_task_name_by_id(tid)

            if name == "ERR_NO_TASK":
                return "NO_TASK"
            else:
                return name

    def get_sch_task_name_by_id(self, task_id):
        sched_task_table = self.symbol_table.lookup("SYM_SCHEDULABLE_TASK_LIST")

        if task_id < 0 or task_id > 0x420:
            task_name = read_cstring_panda(
                self.panda, task_id + self.task_layout.SUBTASK_NAME_OFFSET
            )[: self.task_layout.SUBTASK_NAME_SIZE]
        elif task_id == 0x420:
            task_name = "ERR_NO_TASK"
        elif sched_task_table is None:
            task_name = "ERR_UNRESOLVABLE_TASK_NAME(%d)" % task_id
        else:
            task_struct_p = self.panda.physical_memory_read(
                sched_task_table.address + task_id * 4, 4
            )
            task_struct_p = struct.unpack("I", task_struct_p)[0]

            task_magic = self.panda.physical_memory_read(
                task_struct_p + self.task_layout.SUBTASK_MAGIC_OFFSET, 4
            )

            if task_magic[::-1] != b"TASK":
                return "ERR_INVALID_TASK_MAGIC(0x%x)" % (task_id,)

            task_struct_upper_p = self.panda.physical_memory_read(
                task_struct_p + self.task_layout.SUBTASK_TASK_P_OFFSET, 4
            )
            task_struct_upper_p = struct.unpack("I", task_struct_upper_p)[0]

            if task_struct_upper_p != 0:
                task = self._read_task(task_struct_upper_p)
                task_name = read_cstring_panda(self.panda, task.name_ptr)
            else:
                # truncate to the size of the task name
                # This is not the ideal name, but its good enough
                task_name = read_cstring_panda(
                    self.panda, task_struct_p + self.task_layout.SUBTASK_NAME_OFFSET
                )[: self.task_layout.SUBTASK_NAME_SIZE]

            if len(task_name) == 0:
                task_name = "TASK_NAME_BLANK(%d)" % task_id

        return task_name

    def _read_task(self, address, idx=0):
        offset = address + idx * self.task_layout.SIZE()
        task_struct_data = self.panda.physical_memory_read(
            offset, self.task_layout.SIZE()
        )

        return Task(offset, self.task_layout, raw_bytes=task_struct_data)

    def get_nv_item_info(self, head: int, idx: int):
        """get_nv_item_info
        struct NVItemInfo {
            char *name;
            uint elem_size;
            uint num_elem;
            uint unk;
            char *type;
        }"""
        struct_size = 0x14

        ptr = head + idx * struct_size

        info_struct = self.panda.physical_memory_read(
            ptr, struct_size
        )

        name_ptr, elem_size, num_elem, unk, type_ptr = struct.unpack(
            "<IIIII", info_struct
        )

        if name_ptr == 0:
            return None
        name = read_cstring_panda(self.panda, name_ptr)
        _typ = read_cstring_panda(self.panda, type_ptr)

        return {
            "name": name,
            "elem_size": elem_size,
            "num_elem": num_elem,
            "unk": unk,
            "type": _typ,
        }

    def get_nv_items(self, head: int, num: int):
        items = OrderedDict()
        for i in range(num):
            nv_item_info = self.get_nv_item_info(head, i)
            if nv_item_info:
                items[f"{i:#x}"] = nv_item_info

        return items

    def get_queues(self):
        return self._get_object_array(
            "SYM_QUEUE_LIST",
            self.get_queue_by_id,
            lambda queue: queue.name.startswith("ERR_"),
        )

    def get_tasks(self):
        return self._get_object_array(
            "SYM_TASK_LIST", self.get_task_name_by_id, lambda name: name is None
        )

    def _get_object_array(self, symbol, fn, stop_fn):
        sym = self.symbol_table.lookup(symbol, single=True)

        if sym is None:
            return []

        items = []

        idx = 0
        while True:
            obj = fn(idx)

            if stop_fn(obj):
                break

            items += [obj]
            idx += 1

        return items

    def get_queue_by_name(self, name: str) -> Optional[PALQueue]:
        queues = self.get_queues()
        for q in queues:
            if q.name == name:
                return q

        return None

    def get_queue_by_id(self, qid) -> PALQueue:
        sym = self.symbol_table.lookup("SYM_QUEUE_LIST", single=True)

        if sym is None:
            return PALQueue(name="ERR_MISSING_SYM")

        queue_struct = self.panda.physical_memory_read(
            sym.address + qid * PALQueue.QUEUE_STRUCT_SIZE, PALQueue.QUEUE_STRUCT_SIZE
        )
        (qname_ptr, t, queue_alias_or_callback) = struct.unpack(
                "<IBI",
                queue_struct[PALQueue.QUEUE_NAME_PTR_OFFSET: PALQueue.QUEUE_NAME_PTR_OFFSET + 4] +
                queue_struct[PALQueue.QUEUE_QTYPE_OFFSET: PALQueue.QUEUE_QTYPE_OFFSET + 1] +
                queue_struct[PALQueue.QUEUE_ALIAS_OR_CALLBACK_OFFSET: PALQueue.QUEUE_ALIAS_OR_CALLBACK_OFFSET + 4]
            )

        if qname_ptr == 0:
            return PALQueue(name="ERR_OUT_OF_BOUNDS")
        qname = read_cstring_panda(self.panda, qname_ptr)

        if t not in PALQueue.QTYPE_NAMES.keys():
            qtype_name = 'UNKNOWN'
        else:
            qtype_name = PALQueue.QTYPE_NAMES[t]

        return PALQueue(qid, qname, t, qtype_name, queue_alias_or_callback)

    def get_event_groups(self):
        sym = self.symbol_table.lookup("SYM_EVENT_GROUP_LIST")

        if sym is None:
            return []

        items = []
        event_ptr = sym.address
        struct_size = 0x24
        first_event = event_ptr
        while event_ptr:

            event_struct = self.panda.physical_memory_read(
                event_ptr, struct_size
            )

            (next_event, prev_event, unk1, unk2, unk3, event_name, unk4, unk5) = struct.unpack(
                "<IIIII8sII", event_struct
            )
            event_ptr = next_event

            items.append({
                "next_event": next_event,
                "prev_event": prev_event,
                "unk1": unk1,
                "unk2": unk2,
                "event_name": event_name,
                "unk4": unk4,
                "unk5": unk5,
            })
            if event_ptr == first_event:
                break

        return items
