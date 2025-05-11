## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct
import logging
from firmwire.util.BinaryPattern import BinaryPattern

from .task import get_task_layouts
from .pal_structs import PALQueue

log = logging.getLogger(__name__)

TASK_NAME_TO_FIND = b"GLAPD"


class ShannonMemEntry(object):
    def __init__(self, src, dst, size, fn):
        self.src = src
        self.dst = dst
        self.size = size
        self.fn = fn

    def __repr__(self):
        return "ShannonMemEntry<src=%08x dst=%08x sz=%08x fn=%08x>" % (
            self.src,
            self.dst,
            self.size,
            self.fn,
        )


def dereference(self, sym, data, offset):
    main_toc = self.modem_file.get_section("MAIN")
    offset = sym.address - main_toc.load_address
    data = main_toc.data
    new_address = struct.unpack("I", data[offset : offset + 4])[0]

    log.info("Dereference [0x%08x] -> 0x%08x", sym.address, new_address)
    self.symbol_table.remove(sym.name)
    self.symbol_table.add(sym.name, new_address)

    return True


def fixup_bios_symbol(self, sym, data, offset):
    bios_start = self.symbol_table.lookup("TCM_COPY_START")
    bios_end = self.symbol_table.lookup("TCM_COPY_END")

    if not bios_end or not bios_start:
        return False

    bios_start = bios_start.address
    bios_end = bios_end.address

    if sym.address >= bios_start and sym.address <= bios_end:
        new_address = sym.address - bios_start + 0x04000000
        log.info(
            "Fixing up TCM region symbol %s (%08x -> %08x)",
            sym.name,
            sym.address,
            new_address,
        )
        self.symbol_table.remove(sym.name)

        self.symbol_table.add(sym.name, new_address)
        return True

    return False


def parse_memory_table(self, sym, data, offset):
    main_toc = self.modem_file.get_section("MAIN")
    address = sym.address - main_toc.load_address
    data = main_toc.data

    entries = []
    # scan forwards
    while True:
        src, dst, size, fn = struct.unpack("IIII", data[address : address + 0x10])
        address += 0x10

        # we dont know the table size, so process entries until they look funny
        if src > 0x50000000 or size >= 0x10000000 or fn > 0x50000000 or fn < 0x40010000:
            break

        entries += [ShannonMemEntry(src, dst, size, fn)]

    address = sym.address - main_toc.load_address

    # scan backwards
    while True:
        src, dst, size, fn = struct.unpack("IIII", data[address : address + 0x10])
        address -= 0x10

        # we dont know the table size, so process entries until they look funny
        if src > 0x50000000 or size >= 0x10000000 or fn > 0x50000000 or fn < 0x40010000:
            break

        entries += [ShannonMemEntry(src, dst, size, fn)]

    # make sure we find (somewhat) safe regions for placing new code that dont get overwritten later!
    for entry in entries:
        self.unsafe_regions += [(entry.dst, entry.dst + entry.size)]

    for entry in entries:
        # TCM region copy
        if entry.dst == 0x04000000:
            self.symbol_table.add("TCM_COPY_START", entry.src)
            self.symbol_table.add("TCM_COPY_END", entry.src + entry.size)
            return True

    return False


#  4162e604 04 10 9f e5     ldr        r1,[PTR_DAT_4162e610]                            = 0480109c
#  4162e608 04 00 81 e5     str        param_1,[r1,#0x4]=>DAT_048010a0                  = ??
#  4162e60c 1e ff 2f e1     bx         lr
#                       PTR_DAT_4162e610
#  4162e610 9c 10 80 04     addr       DAT_0480109c                                     = ??
def find_current_task_ptr(data, offset):
    bp = BinaryPattern("task_set_function", offset=0xC)
    bp.from_hex("04 10 9f e5 04 00 81 e5 1e ff 2f e1")

    locs = bp.findall(data, maxresults=2)

    if len(locs) == 0:
        return None

    for loc in locs:
        # make sure our find is byte aligned
        if loc[0] & 0x3:
            continue

        ptr = struct.unpack("I", data[loc[0] : loc[0] + 4])[0]

        # make sure the pointer is valid
        # MM: we only check upper bound, needed for some modems apparantly
        if ptr >= (offset + len(data)):
            continue

        return ptr + 4

    return None


def find_current_task_ptr_a(data, offset):
    bp = BinaryPattern("get_task_function", offset=0x0)
    bp.from_hex("?? ?? ?? e3 ?? ?? ?? e3 00 01 91 e7 1e ff 2f e1")

    locs = bp.findall(data, maxresults=2)

    for loc in locs:
        # make sure our find is byte aligned
        if loc[0] & 0x3:
            continue

        instr1 = struct.unpack("<I", data[loc[0]: loc[0] + 4])[0]
        if instr1 & 0xfff0f000 != 0xe3001000:  # movw r1, ??
            continue
        right = instr1 & 0x00000fff | (instr1 & 0x000f0000) >> 0x4
        instr2 = struct.unpack("<I", data[loc[0] + 4: loc[0] + 8])[0]
        if instr2 & 0xfff0f000 != 0xe3401000:  # movt r1, ??
            continue
        left = instr2 & 0x00000fff | (instr2 & 0x000f0000) >> 0x4
        ptr = (left << 0x10) | right
        return ptr
    return None


def find_event_group_list(data, offset):
    # bp = BinaryPattern("create_event_group_functions", offset=0)
    # bp.from_hex("??????e3 ??????e5 ??????e5 ??????e5 ??????e5 ??????e5 ??????e5 ??????e3 ??????eb")
    # bp.from_hex("??????e3 04 10 a0 e1 80 50 03 e2 ??????e3 ??????eb")

    # locs = bp.findall(data)
    # for loc in locs:
    #     print(f"loc={offset + loc[0]:#010x}")
    return 0x44a26cc0


def find_schedulable_task_table(data, offset):
    bp = BinaryPattern("OSTaskGetArg0", offset=0x1C)
    bp.from_hex("420e50e3 0000a003 0200000a 08109fe5 000191e7 ??0090e5")

    locs = bp.findall(data, maxresults=2)
    if len(locs) == 0:
        return None

    for loc in locs:
        # make sure our find is byte aligned
        if loc[0] & 0x3:
            continue
        ptr = struct.unpack("I", data[loc[0] : loc[0] + 4])[0]

        # NB: no sanity checks here
        return ptr

    return None


"""
                       **************************************************************
                       *                          FUNCTION                          *
                       **************************************************************
                       void __stdcall exception_stack_switch(void)
       void              <VOID>         <RETURN>
       OSTaskStruct *    r0:4           task
                       exception_stack_switch
  40c71734 0c 12 9f e5     ldr        r1,[->SCHED_VAR]                           = 418385f4
  40c71738 00 10 91 e5     ldr        r1,[r1,#0x0]=>SCHED_VAR                    = 00000420h
  40c7173c 42 0e 51 e3     cmp        r1,#0x420
  40c71740 1f 00 00 0a     beq        LAB_40c717c4
  ...
  ...
  ...
  40c71948 f4 85 83 41     addr       SCHED_VAR                                  = 00000420h
  40c7194c 68 6e a3 43     addr       OsSchedulableTaskList                      = 00000000
  40c71950 e0 8d e4 43     addr       SAVED_STACK
  40c71954 24 86 83 41     addr       IRQ_VAR
  40c71958 28 86 83 41     addr       SCHED_LR_STORAGE
  40c7195c 2c 86 83 41     addr       TASKID_WHICH_DISABLED_INTR
  40c71960 ef be ad de     undefined4 DEADBEEFh
"""


def find_exception_switch(data, offset):
    bp = BinaryPattern("fn")
    bp.from_hex("????9fe5 001091e5 420e51e3 ??????0a")

    locs = bp.findall(data, maxresults=2)

    for loc in locs:
        # make sure our find is byte aligned
        if loc[0] & 0x3:
            continue

        return loc[0] + offset

    return None


def is_ptr_to_ascii(data, offset, maxlength=0x10):
    name = data[offset: offset + maxlength]
    name = name.tobytes()
    try:
        name = name[: name.find(b"\x00")].decode("ascii", "strict")
        if len(name) == 0:
            return False
    except UnicodeError:
        return False
    return True


def find_queue_table(data, offset):
    bp = BinaryPattern("queue_name", offset=1)
    bp.from_str(b"\x00AdcTask\x00")

    locs = bp.findall(data, maxresults=2)

    if len(locs) == 0:
        return None

    queue_offset = None
    for loc in locs:
        xref_target = loc[0] + offset

        bp_x = BinaryPattern("xref")
        bp_x.from_str(struct.pack("I", xref_target))
        x_locs = bp_x.findall(data)

        if len(x_locs) == 0:
            continue
        for x_loc in x_locs:
            test_offset = x_loc[0]
            test_offset -= PALQueue.QUEUE_STRUCT_SIZE
            p_test_name = struct.unpack("<I", data[test_offset: test_offset + 4])[0]
            test_name_offset = p_test_name - offset
            if not is_ptr_to_ascii(data, test_name_offset):
                continue
            queue_offset = x_loc[0]
            break
    if queue_offset is None:
        return None

    # iterate one queue struct back until we find the first queue struct with an ASCII name
    while True:
        queue_offset -= PALQueue.QUEUE_STRUCT_SIZE
        p_queue_name = struct.unpack("<I", data[queue_offset: queue_offset + 4])[0]
        queue_name_offset = p_queue_name - offset
        if p_queue_name < offset or not is_ptr_to_ascii(data, queue_name_offset):
            ptr = queue_offset + PALQueue.QUEUE_STRUCT_SIZE
            break
        next_ptr = struct.unpack("<I", data[queue_offset + 4: queue_offset + 8])[0]
        next_ptr_offset = next_ptr - offset
        prev_ptr = struct.unpack("<I", data[queue_offset - 4: queue_offset])[0]
        prev_ptr_offset = prev_ptr - offset
        if is_ptr_to_ascii(data, next_ptr_offset) or is_ptr_to_ascii(data, prev_ptr_offset):
            ptr = queue_offset + PALQueue.QUEUE_STRUCT_SIZE
            break

    return offset + ptr


def find_boot_mmu_table(data, offset):
    print(f"find_boot_mmu_table: len(data)={len(data)}")
    print(f"find_boot_mmu_table: table={data[0x2b76720]}")
    struct_size = 0x10
    num = 0x1b
    for i in range(num):
        off = 0x2b76720 + i * struct_size
        entry_data = data[off: off + struct_size]
        (addr, start, end, flags) = struct.unpack("<IIII", entry_data)
        dst = (addr >> 0x12) | 0x40008000
        val = addr & 0xfff00000 | flags | 2
        print(f"addr={addr:#010x}, start={start:#010x}, end={end:#010x}, size={end-start:#010x}, flags={flags:#07x}, dst={dst:#010x}, val={val:#010x}")


def find_task_table(data, offset):
    bp_task = BinaryPattern("task", offset=1)
    bp_task.from_str(b"\x00" + TASK_NAME_TO_FIND + b"\x00")

    # Find the null terminated strings like 'task'
    locs = []
    npos = 0

    while True:
        res = bp_task.find(data, pos=npos)

        if res is None:
            break

        npos = res[1]
        locs += [res]

    if len(locs) == 0:
        return None

    rez = []
    for xref_target, _ in locs:
        xref_target += offset

        bp_task_x = BinaryPattern("xref")
        bp_task_x.from_str(struct.pack("I", xref_target))
        rez = bp_task_x.findall(data, maxresults=2)

        if len(rez) > 1:
            break

    if len(rez) == 0:
        return None

    # the first result is another reference we dont care about
    ptr = rez[1][0]

    return ptr


def fixup_set_task_layout(self, sym, data, offset):
    ptr = sym.address

    # try to figure out task layout:
    found_layout = None

    for layout in get_task_layouts():
        test_ptr = ptr
        test_ptr -= layout.SIZE()
        task_name_p = struct.unpack("I", data[test_ptr : test_ptr + 4])[0]
        task_name_p_off = task_name_p - offset
        name = data[task_name_p_off: task_name_p_off + 10]
        name_bytes = name.tobytes()
        end_of_string = name_bytes.find(b"\x00")
        # not a cstring
        if end_of_string == -1:
            continue
        # contents are as expected
        if all(
            [c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ__" for c in name_bytes[:end_of_string]]
        ):
            log.info(f"Found likely task name: {name_bytes}, keeping task layout (size={layout.SIZE()})")
            found_layout = layout
            break
    if found_layout is None:
        log.error("Couldn't retrieve correct task layout, aborting!")
        raise ValueError("Missing task layout")

    while True:
        ptr -= found_layout.SIZE()
        task_name_p = struct.unpack("I", data[ptr: ptr + 4])[0]
        task_name_p_off = task_name_p - offset
        name = data[task_name_p_off: task_name_p_off + 10]
        # print(hex(task_name_p), name.tobytes())

        # search backwards until we see an invalid address
        if task_name_p < offset or task_name_p >= (offset + len(data)) or name.tobytes().startswith(b"../.."):
            self.task_layout = found_layout
            self.symbol_table.replace(
                sym.name,
                offset + ptr + found_layout.SIZE() - found_layout.TASK_NAME_PTR_OFFSET,
            )
            return True

    raise ValueError("Invalid task layout")


def find_lterrc_int_mob_cmd_ho_from_irat_msgid(data, offset):
    bp = BinaryPattern("lte_rrc_int_mob_cmd_ho_from_irat_msgid", offset=0x12)
    bp.from_hex(
        "?? ?? 14 ?? ?? d0 ?? ?? ?? d0 ?? ?? ?? d0 ?? f5 43 ?? ?? ?? ?? d0 01 20"
    )

    off = bp.find(data)
    if off is None:
        bp = BinaryPattern("lte_rrc_int_mob_cmd_ho_from_irat_msgid", offset=0x16)
        bp.from_hex("????4c?? ???? ????14?? ??d0 ????44?? ??d0 ???? ???????? 8245")  # S5123AP
        off = bp.find(data)
        if off is None:
            return None
    off = off[0]
    res = 0xC3 << 8 | data[off]
    return res


def get_dsp_sync0(self, sym, data, offset):
    main_toc = self.modem_file.get_section("MAIN")

    sync_word = main_toc.data[sym.address - main_toc.load_address]
    self.symbol_table.remove(sym.name)
    self.symbol_table.add(sym.name, sync_word)
    log.info(f"Retrieved sync word 0: {sync_word}")
    return True


def get_dsp_sync1(self, sym, data, offset):
    main_toc = self.modem_file.get_section("MAIN")

    sync_word = main_toc.data[sym.address - main_toc.load_address] * 2
    self.symbol_table.remove(sym.name)
    self.symbol_table.add(sym.name, sync_word)
    log.info(f"Retrieved sync word 1: {sync_word}")
    return True


def find_LteRrm_Task__ReceivedLteRrc(data, offset):
    return 0x40e16800 + 1


def find_debug_handler_func(data, offset):
    return 0x40d4ff44 + 1


def find_debug_handler_func2(data, offset):
    return 0x40d4ff18 + 1


def find_pal_MsgReceiveMbx(data, offset):
    # return 0x411560a2 + 1
    return 0x41f772aa + 1


def find_LTERRM_Init_Event_Group(data, offset):
    return 0x40e184ce + 1


def find_LTERRM_RetrieveEvent(data, offset):
    return 0x40e1851a + 1


def find_SIM_Task__Handler(data, offset):
    return 0x40e616b8 + 1


def find_SIM_ContextDef(data, offset):
    return 0x40fcbc94 + 1


def find_SIM_Registration(data, offset):
    return 0x41055226 + 1


def find_SAEMM_DelieverPduForEstRequest(data, offset):
    return 0x40fe5df0 + 1