## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import re
import os
import struct
import logging
import binascii
import collections

from avatar2 import *
from pandare import Panda

from firmwire.util.logging import COLOR_DEFAULT, COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE, COLOR_PURPLE, COLOR_CYAN, COLOR_RED_INTENSE
from firmwire.vendor.shannon.pal_structs import PALMsg, PALMsg_pattern, MSG_HEADER_SIZE
from string import printable

from firmwire.util.panda import read_cstring_panda

log = logging.getLogger(__name__)
unpack_sym = {
    1: "B",
    2: "H",
    4: "I",
    8: "Q",
}
panda: Panda

##########################################################
## HOOKS BEGIN
##########################################################


def log_fatal_error_file_line(self):
    return False


# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0458c/CHDJHAGA.html
# NA - no access, RO - read only, RW - read write, RESV - reserved
# U_* - unpriviledged, P_* - priviledged
AP_NAME = ["NA", "P_RW", "P_RW/U_RO", "RW", "RESV", "P_RO/U_NA", "RO", "RESV"]
VARARG_SENTINEL = 0xFECDBA98
VARARG_DUMP_CSTRING = 0xFFFFFFFF


def set_mpu_slot_modem(self, cpustate, tb, hook):
    sp = cpustate.env_ptr.regs[13]
    slot = cpustate.env_ptr.regs[0]
    base = cpustate.env_ptr.regs[1]
    size = cpustate.env_ptr.regs[2]
    r3 = cpustate.env_ptr.regs[3]

    arg4_arg9 = panda.virtual_memory_read(cpustate, sp, 4 * 6)
    arg4_arg9 = struct.unpack("6I", arg4_arg9)

    size_bytes = (size >> 1) & 0b11111
    assert size_bytes >= 7
    size_bytes = 2 ** (8 + size_bytes - 7)

    enable = arg4_arg9[-1]
    access_control = sum([r3] + list(arg4_arg9[:-1]))

    XN = (access_control >> 12) & 1
    AP = (access_control >> 8) & 0b111
    B = (access_control) & 1
    C = (access_control >> 1) & 1
    S = (access_control >> 2) & 1
    TEX = (access_control >> 3) & 0b111

    args = [
        slot,
        bool(enable),
        base,
        base + size_bytes,
        XN,
        AP_NAME[AP],
        access_control,
    ]

    log.info("MPU RGN=%-2d ENABLE=%s [%08x - %08x] XN=%d AP=%s (0x%x)", *args)

    return False


def OS_log(self):
    return False


def OS_enter_idle(self, cpustate, tb, hook):
    r0 = cpustate.env_ptr.regs[0]

    log_emit(self, cpustate, "OS_enter_idle(%d)", r0)


"""
Enables per-basic block stepping and debugging output
"""


def panda_step_debug(self):
    @panda.cb_before_block_exec(enabled=True)
    def bbe(cpustate, tb):
        pc = panda.current_pc(cpustate)
        sym = self.symbol_table.lookup(pc)
        offset = pc - sym.address

        while True:
            log.info("========================> %s", sym.format(offset))
            dump_state(panda, cpustate)
            # sleep seems required otherwise BlockingIOError is common
            time.sleep(0.05)


def hw_MCU_Sleep(self, cpustate, tb, hook):
    log_emit(self, cpustate, "hw_MCU_Sleep")


def OS_Schedule_Task(self, cpustate, tb, hook, func_name=None, **kwargs):
    r0 = cpustate.env_ptr.regs[0]
    r1 = cpustate.env_ptr.regs[1]

    name = self.get_sch_task_name_by_id(r0)

    if func_name is None:
        func_name = "OS_Schedule_Task"
    else:
        assert isinstance(func_name, str)

    log_emit(self, cpustate, f"{func_name}({name} ({r0:#x}), {r1:#x})")


def boot_after_uart_setup(self):
    print(
        self.qemu.call(
            0x400009BC, args=[b"HelloWorld\n"], playground=0x1000000, step=True
        )
    )
    self.qemu.cont(blocking=False)


def OS_handle_irq(self, cpustate, tb, hook):
    # to be extedted called from 0x42393f50:
    # 42393f50 50 f8 26 40     ldr.w      r4,[r0=>OSSyscallArray,r6,lsl #0x2]

    r0 = cpustate.env_ptr.regs[0]
    r6 = cpustate.env_ptr.regs[6]
    lr = cpustate.env_ptr.regs[14]
    handler = panda.virtual_memory_read(cpustate, r0 + 4 * r6, 0x4)
    log.info("%08x: OS_handle_interrupt(irq=%08x, handler=%08x)", lr, r6, handler)


def OS_enable_irq(self, cpustate, tb):
    # addr 0x42380242

    r0 = cpustate.env_ptr.regs[1]
    lr = cpustate.env_ptr.regs[14]

    log.info("%08x: Enabled IRQ %d", r0, lr)


def OS_create_task(self, cpustate, tb, hook):
    r0 = cpustate.env_ptr.regs[0]
    r1 = cpustate.env_ptr.regs[1]
    r3 = cpustate.env_ptr.regs[3]
    sp = cpustate.env_ptr.regs[13]
    lr = cpustate.env_ptr.regs[14]

    task_name = read_cstring_panda(panda, r1, max_length=9)
    arg4_arg7 = panda.virtual_memory_read(cpustate, sp, 4 * 4)
    arg4_arg7 = struct.unpack("IIII", arg4_arg7)

    start_function = arg4_arg7[2]
    log.info(
        "%08x: OS_create_task(0x%x, %s, stack=%08x, cb=%08x)",
        lr,
        r0,
        task_name,
        r3,
        start_function,
    )
    return False


FORMAT_SPECIFIER = re.compile("%?%[#]?[0-9lh.]*[a-zA-Z]")


def vsprintf(self, cpustate, fmt, argv, dump=False):
    argv_resolved = []

    res = FORMAT_SPECIFIER.findall(fmt)

    res = [
        x for x in res if "%%" not in x
    ]  # MM: hotfix to deal with "%%%%" in messages

    for i, r in enumerate(res):
        if r[0] == "%" and r[1] == "%":
            continue

        try:
            arg = argv[i]
        except IndexError:
            return "FORMAT INDEX ERROR: %s %s %s" % (fmt, res, argv)

        if r[-1] == "s":
            arg = read_cstring_panda(panda, arg)
        elif r[-1] == "C":
            fmt = fmt.replace(r, r[:-1] + "c")
        elif r[-1] == "p":
            fmt = fmt.replace(r, "0x%08x")

        argv_resolved += [arg]

    try:
        formatted = fmt % tuple(argv_resolved[: len(res)])
    except (TypeError, ValueError) as e:
        formatted = "FORMAT ERROR: [%s] [%s] [%s]" % (str(fmt), str(res), str(argv))

    if dump:
        dump_commands = argv[len(argv_resolved):]

        if len(dump_commands) > 0 and dump_commands[0] == VARARG_DUMP_CSTRING:
            dump_commands = dump_commands[1:]

        # need at least an address and size
        if len(dump_commands) < 2:
            return formatted

        # blank string for join separator between formatted message and dumps
        dump_command_results = [""]

        for i in range(len(dump_commands) // 2):
            addr = dump_commands[i * 2]
            size = dump_commands[i * 2 + 1]
            if size == VARARG_DUMP_CSTRING:
                s = read_cstring_panda(panda, addr)
            else:
                s = panda.virtual_memory_read(cpustate, addr, size)
                s = binascii.hexlify(s).decode()

            dump_command_results += [s]

        formatted += " -- ".join(dump_command_results)

    return formatted


def _read_trace_cstring(self, cpustate, address):
    s = _read_trace_data(self, cpustate, address, 0x100)
    return s[: s.find(b"\x00")].decode("ascii", "ignore")


def _read_trace_data(self, cpustate, address, size):
    offset = address - self.trace_data_offset

    # fallback to other memory ranges
    if offset < 0 or offset > len(self.trace_data):
        return panda.virtual_memory_read(cpustate, address, size)

    if offset + size > len(self.trace_data):
        size = len(self.trace_data) - offset

    return self.trace_data[offset: offset + size]


def _vsprintf_get_va_list(cpustate):
    sp = cpustate.env_ptr.regs[13]

    # _cdecl calling convention passes the rest of the args on the stack after R3
    # 7 stack args appears to be the max! (as seen from the log_printf function)
    stack_args = panda.virtual_memory_read(cpustate, sp, 4 * 7)
    stack_args = list(struct.unpack("7I", stack_args))
    argv = [
               cpustate.env_ptr.regs[1],
               cpustate.env_ptr.regs[2],
               cpustate.env_ptr.regs[3],
           ] + stack_args

    max_idx = 0
    for arg in argv:

        if arg == VARARG_SENTINEL:
            break

        max_idx += 1

    return argv[:max_idx]


def _log_printf_common(self, cpustate, tb, dump):
    pc = panda.current_pc(cpustate)
    r0 = cpustate.env_ptr.regs[0]
    logcontext = panda.virtual_memory_read(cpustate, r0, 8)

    logcontext = struct.unpack("II", logcontext)
    trace_entry = _read_trace_data(self, cpustate, logcontext[0], 4 * 7)
    trace_entry = struct.unpack("IIIIIII", trace_entry)

    fmt = _read_trace_cstring(self, cpustate, trace_entry[4])
    filename = _read_trace_cstring(self, cpustate, trace_entry[6])
    filename = filename.split('/')[-1]

    argv = _vsprintf_get_va_list(cpustate)
    formatted = vsprintf(self, cpustate, fmt, argv, dump=dump)

    loglevel = logcontext[1] & 0b11111
    log_emit(
        self, cpustate, "%s: [%s] - %s", bin(loglevel), filename, formatted.rstrip()
    )

    return False


def log_printf(self, cpustate, tb, hook):
    return _log_printf_common(self, cpustate, tb, False)


def log_printf_debug(self, cpustate, tb, hook):
    return _log_printf_common(self, cpustate, tb, True)


def log_emit(self, cpustate, fmt, *args, color=None):
    caller = cpustate.env_ptr.regs[14]
    name = self.get_current_task_name(cpustate)

    if color is None:
        self.guest_logger.log_emit(fmt, *args, task_name=name, address=caller)
    else:
        self.guest_logger.log_emit(color + fmt + COLOR_DEFAULT, *args, task_name=name, address=caller)


def log_printf_stage(self, cpustate, tb, hook):
    cplog_buffer_p = cpustate.env_ptr.regs[0]
    trace_entry_stage_p = cpustate.env_ptr.regs[1]
    flags = cpustate.env_ptr.regs[2]
    fmt_p = cpustate.env_ptr.regs[3]

    cplog_buffer = panda.virtual_memory_read(cpustate, cplog_buffer_p, 4 * 4)
    cplog_buffer = struct.unpack("IIII", cplog_buffer)
    cplog_buffer_name = read_cstring_panda(panda, cplog_buffer[0])

    trace_entry_stage = panda.virtual_memory_read(cpustate, trace_entry_stage_p, 4 * 4)
    trace_entry_stage = struct.unpack("IIII", trace_entry_stage)
    filename = read_cstring_panda(panda, trace_entry_stage[3])

    fmt = read_cstring_panda(panda, fmt_p)
    argv = _vsprintf_get_va_list(cpustate)
    formatted = vsprintf(self, cpustate, fmt, argv)

    log_emit(
        self, cpustate, "[%s][%s] - %s", cplog_buffer_name, filename, formatted.rstrip()
    )

    return False


def OS_event(self, cpustate, tb, hook):
    event_group = cpustate.env_ptr.regs[0]
    event_group_name_p = cpustate.env_ptr.regs[1]

    event_group_name = read_cstring_panda(panda, event_group_name_p)

    log.info("OS_Create_Event_Group(0x%08x, %s)", event_group, event_group_name)

    return True


# keyed by thread id (which we treat as task ID)
target_invocation_stack = {}


def read_msg(self, addr, item_type):
    if item_type == 5:
        op, size, mid = struct.unpack("<IHH", panda.physical_memory_read(addr, MSG_HEADER_SIZE))
        dataPtr = addr + MSG_HEADER_SIZE
        data = panda.physical_memory_read(dataPtr, size)
        src_queue = self.get_queue_by_id(0)
        dst_queue = self.get_queue_by_id(0)
        return PALMsg(src_queue, dst_queue, size, op, data, item_type)
    else:
        src, dst, size, mid = struct.unpack(
            PALMsg_pattern, panda.physical_memory_read(addr, MSG_HEADER_SIZE)
        )

        dataPtr = addr + MSG_HEADER_SIZE
        data = panda.physical_memory_read(dataPtr, size)
        src_queue = self.get_queue_by_id(src)
        dst_queue = self.get_queue_by_id(dst)
        return PALMsg(src_queue, dst_queue, size, mid, data, item_type)


def pal_MsgReceiveMbx(self, cpustate, tb, hook):
    fromLoc = cpustate.env_ptr.regs[14]
    qid = cpustate.env_ptr.regs[0]
    ppItem = cpustate.env_ptr.regs[1]
    pItemClass = cpustate.env_ptr.regs[2]
    flags = cpustate.env_ptr.regs[3]

    ctx = {
        "caller": cpustate.env_ptr.regs[14],
        "args": [qid, ppItem, pItemClass, flags],
    }

    ctx_id = self.get_current_task_id()
    assert ctx_id is not None

    if ctx_id not in target_invocation_stack:
        target_invocation_stack[ctx_id] = []

    target_invocation_stack[ctx_id].append(ctx)

    queue = self.get_queue_by_id(qid)
    name = queue.name
    self.pal_waiting_for_msg(self.get_current_task_name(cpustate), name)
    log_emit(self, cpustate, "pal_MsgReceiveMbx(%s (%d)) - ENTER", name, qid, color=COLOR_YELLOW)


def pal_MsgReceiveMbx_ret(self, cpustate, tb, hook):
    ctx_id = self.get_current_task_id()
    assert ctx_id != None

    # TODO: save context stack on snapshot
    if (
            ctx_id not in target_invocation_stack
            or len(target_invocation_stack[ctx_id]) == 0
    ):
        log_emit(self, cpustate, "pal_MsgReceiveMbx(???) - NO CONTEXT", color=COLOR_YELLOW)
        return

    ctx = target_invocation_stack[ctx_id].pop()

    qid = ctx["args"][0]
    ppItem = ctx["args"][1]

    # We can't get item type because its assigned to a pointer at the last TB,
    # so grab it from the stack instead
    sp = cpustate.env_ptr.regs[13]
    itemType = struct.unpack("<I", panda.physical_memory_read(sp + 0x0, 4))[0]

    queue = self.get_queue_by_id(qid)
    name = queue.name

    if itemType == 2 or itemType == 5:
        pItem = struct.unpack("<I", panda.physical_memory_read(ppItem, 4))[0]
        msg = read_msg(self, pItem, itemType)
        self.pal_log_recv_msg(self.get_current_task_name(cpustate), name, msg)
        log_emit(
            self, cpustate, "pal_MsgReceiveMbx(%s (%d)) - %s", name, qid, repr(msg), color=COLOR_YELLOW
        )
    elif itemType == 3:
        log_emit(
            self, cpustate, "pal_MsgReceiveMbx(%s (%d)) - TIMER 0x%x", name, qid, ppItem, color=COLOR_YELLOW
        )
    else:
        log_emit(
            self,
            cpustate,
            "pal_MsgReceiveMbx(%s (%d)) - UNKNOWN TYPE 0x%x",
            name,
            qid,
            itemType,
            color=COLOR_YELLOW
        )


def pal_MsgSendTo(self, cpustate, tb, hook):
    qid = cpustate.env_ptr.regs[0]
    msgAddr = cpustate.env_ptr.regs[1]
    itemType = cpustate.env_ptr.regs[2]

    queue = self.get_queue_by_id(qid)
    name = queue.name

    if itemType == 2 or itemType == 5:
        if qid == 0x1a:  # SAEMM
            msg = read_msg(self, msgAddr, 2)
        else:
            msg = read_msg(self, msgAddr, itemType)
        log_emit(self, cpustate, "pal_MsgSendTo(%s (%d)) - %s", name, qid, repr(msg), color=COLOR_YELLOW)
        self.pal_log_send_msg(self.get_current_task_name(cpustate), name, msg)
    elif itemType == 3:
        log_emit(
            self, cpustate, "pal_MsgSendTo(%s (%d)) - TIMER 0x%x", name, qid, msgAddr, color=COLOR_YELLOW
        )
    else:
        log_emit(
            self,
            cpustate,
            "pal_MsgSendTo(%s (%d)) - UNKNOWN TYPE 0x%x",
            name,
            qid,
            itemType,
            color=COLOR_YELLOW
        )


def pal_QueueCreate(self, cpustate, tb, hook):
    queue_name_p = cpustate.env_ptr.regs[2]
    queue_name = read_cstring_panda(panda, queue_name_p)

    log.info("pal_QueueCreate(%s)", queue_name)

    return True


def log_format_unk(self, cpustate, tb, hook):
    fmt = cpustate.env_ptr.regs[0]

    fmt = read_cstring_panda(panda, fmt)
    argv = _vsprintf_get_va_list(cpustate)

    formatted = vsprintf(self, cpustate, fmt, argv)
    log_emit(self, cpustate, "%s", formatted.rstrip())

    return True


def pal_Sleep(self, cpustate, tb, hook):
    sleep_time = cpustate.env_ptr.regs[0]
    log_emit(self, cpustate, "pal_Sleep(%d)", sleep_time)


def NV_STUFF(self, cpustate, tb, hook):
    log.info("NV_STUFF this will take a while (time so far %.2f)", self.time_running())
    return True


def memory_hexdump(cpustate, addr, label='', n=1, first_line=True, int_values=False):
    _range = range(0)
    if isinstance(n, int):
        _range = range(n)
    elif isinstance(n, tuple):
        _range = n

    addr_str = f"{addr:#010x}"

    if first_line:
        mem_str = f"{addr_str}:" + (f" ({label})" if label else "") + "\n"
    else:
        mem_str = "\n"
    for i in _range:
        value = panda.virtual_memory_read(cpustate, addr + i * 0x10, 0x10)
        # value_int_str = f"{unpack('<I', value)[0]:#010x}"
        value_str = ''.join(f'{chr(x)}' if chr(x) in printable[:-5] else '.' for x in value)
        if int_values:
            ints = []
            for j in range(4):
                ints.append(f"{struct.unpack('<I', value[j * 4:j * 4 + 4])[0]:#010x}")
            value = ' '.join(ints)
        else:
            value_hex = ' '.join(f'{x:02x}' for x in value[:8])
            value_hex += ' ' + ' '.join(f'{x:02x}' for x in value[8:])
            value = value_hex

        cur_offset = i * 0x10
        mem_str += f"\t{cur_offset:#010x}: {value} |{value_str}|\n"

    return mem_str


def write_addr(self, cpustate, tb, hook, addr, value, label=None):
    assert isinstance(value, bytes)
    panda.physical_memory_write(addr, value)


def func_called(self, cpustate, tb, hook, func_name='', num_args=0, args=None, **kwargs):
    if args:
        assert len(args) == num_args
    r0 = cpustate.env_ptr.regs[0]
    argv = []
    argv = _vsprintf_get_va_list(cpustate)
    args_str = []
    argv = [r0, *argv]
    if args:
        for j, arg in enumerate(argv[:num_args]):
            if args[j]['type'] is str:
                arg = read_cstring_panda(panda, arg)
                args_str.append(f"{args[j]['name']}={arg}")
            else:
                args_str.append(f"{args[j]['name']}={arg:#010x}")
    else:
        for arg in argv[:num_args]:
            args_str.append(f"{arg:#010x}")

    log_emit(self, cpustate, f"{func_name}({', '.join(args_str)})", color=COLOR_CYAN)


def dump_variables(self, cpustate, tb, hook, _vars=None, **kwargs):
    if _vars is None:
        return
    vars_str = []
    for var in _vars:
        if var["type"][0] == "u8":
            c = panda.virtual_memory_read(cpustate, var["addr"], 1)
            (value, ) = struct.unpack("<B", c)
            string = ""
            if var["type"][1] is not None:
                string = var["type"][1][value]
            vars_str.append(f"{var['name']}={string}({value:#04x})")
        else:
            # not implemented
            continue
    log_emit(
        self, cpustate,
        ", ".join(vars_str), color=COLOR_PURPLE
    )


def dump_reg(self, cpustate, tb, hook, reg=0, dump=0, label=None, **kwargs):
    if reg == -1:
        R = cpustate.env_ptr.regs
        regs_dump = """pc:  %08x      lr:  %08x      sp:  %08x
r0:  %08x      r1:  %08x      r2:  %08x
r3:  %08x      r4:  %08x      r5:  %08x
r6:  %08x      r7:  %08x      r8:  %08x
r9:  %08x      r10: %08x      r11: %08x
r12: %08x""" % (R[15], R[14], R[13], R[0], R[1], R[2], R[3], R[4], R[5], R[6], R[7], R[8], R[9], R[10], R[11], R[12])
        log_emit(self, cpustate, regs_dump)
        if dump > 0:
            log_emit(self, cpustate, memory_hexdump(cpustate, R[13], n=dump), color=COLOR_YELLOW)
    else:
        try:
            r = cpustate.env_ptr.regs[reg]
            addr_str = f"{r:#010x}"
            if label:
                log_emit(self, cpustate, f"{label}: r{reg} => {addr_str}")
            else:
                log_emit(self, cpustate, f"r{reg} => {addr_str}")

            if r == 0:
                return
            if (isinstance(dump, int) and dump > 0) or (isinstance(dump, tuple), len(dump) > 0):
                content = memory_hexdump(cpustate, r, n=dump)
                log_emit(self, cpustate, content, color=COLOR_PURPLE)
        except Exception:
            pass


def debug_hook(self, cpustate, tb, hook, addr=None, dump=0, **kwargs):
    if addr is not None:
        (value,) = struct.unpack('<I', panda.virtual_memory_read(cpustate, addr, 4))
        log_emit(self, cpustate, memory_hexdump(cpustate, value, n=dump), color=COLOR_PURPLE)


def dump_addr(self, cpustate, tb, hook, addr=None, dump=0, label="", **kwargs):
    if addr is not None:
        log_emit(self, cpustate, memory_hexdump(cpustate, addr, n=dump, label=label), color=COLOR_PURPLE)


def shannon_hexdump(self, cpustate, tb, hook):
    r0 = cpustate.env_ptr.regs[0]
    logcontext = panda.virtual_memory_read(cpustate, r0, 8)

    logcontext = struct.unpack("II", logcontext)
    trace_entry = _read_trace_data(self, cpustate, logcontext[0], 4 * 7)
    trace_entry = struct.unpack("IIIIIII", trace_entry)

    fmt = _read_trace_cstring(self, cpustate, trace_entry[4])
    filename = _read_trace_cstring(self, cpustate, trace_entry[6])
    filename = filename.split('/')[-1]

    buf_addr = cpustate.env_ptr.regs[1]
    size = cpustate.env_ptr.regs[2]
    n = (size + 0xf)//0x10
    n = min(20, n)
    loglevel = logcontext[1] & 0b11111
    log_emit(
        self, cpustate, "%s: [%s] - %s%s", bin(loglevel), filename, fmt.rstrip(), memory_hexdump(cpustate, buf_addr, n=n, first_line=False)
    )


def shannon_fatal_error(self, cpustate, tb, hook, error_name=None, **kwargs):
    r0 = cpustate.env_ptr.regs[0]
    r0 = r0 & 0xffff
    err_desc = f"{r0:#06x}"
    err_info_list = error_name
    if error_name is not None:
        p_name = 1
        while p_name != 0:
            error_info = panda.virtual_memory_read(cpustate, err_info_list, 8)
            p_name, errno = struct.unpack("<II", error_info)
            if errno == r0:
                name = read_cstring_panda(panda, p_name)
                err_desc = f"{name} ({r0:#06x})"
                break
            err_info_list += 8
    log_emit(self, cpustate, f"FatalError({err_desc})", color=COLOR_RED_INTENSE)


def warm_boot_change(self, cpustate, tb, hook, **kwargs):
    soc_per = self.get_peripheral("SOC")
    soc_per.warm_boot[1] = 0x1


def dump_memory_sections(self, cpustate, tb, hook, **kwargs):
    table = 0x40008000
    ap_str = {0b000: "--", 0b001: "rw", 0b010: "rw", 0b011: "rw", 0b100: "--", 0b101: "r-", 0b110: "r-", 0b111: "r-"}
    sections = list()

    for sec in range(0, 0x4000, 4):
        desc = panda.physical_memory_read(table | sec, 4)
        (desc, ) = struct.unpack("<I", desc)
        if sec != 0 and desc == 0:
            continue

        start_addr = sec << 0x12  # virtual addr
        ap = ((desc >> 10) & 3) | ((desc >> 13) & 4)
        prot = ap_str[ap]
        pxn = desc & 1
        xn = desc & (1 << 4)
        if pxn == 1:
            xn = 1
        if prot != "--" and xn == 0:
            prot += "x"
        else:
            prot += "-"
        if sec == 0x10a8:
            print(f"({sec:x}, {start_addr:08x}, {prot}, {desc:#08x})")
        if len(sections) == 0:
            sections.append((start_addr, 0x100000, prot),)
        else:
            end_addr = sections[-1][0] + sections[-1][1]
            if sections[-1][2] == prot and end_addr == start_addr:  # same permissions and adjacent section
                sections[-1] = (sections[-1][0], sections[-1][1] + 0x100000, sections[-1][2])
            else:
                sections.append((start_addr, 0x100000, prot),)

    for sec in sections:
        print(f"{sec[0]:08x} - {sec[0] + sec[1]:08x} {sec[2]}")


def protect_write_access(self, cpustate, memory_access_desc, label=None, const_value=0):
    addr = memory_access_desc.addr
    acc_size = memory_access_desc.size
    format = unpack_sym[acc_size]
    (value,) = struct.unpack(format, panda.virtual_memory_read(cpustate, addr, acc_size))
    value = const_value
    panda.physical_memory_write(addr, struct.pack("<I", value))
    offset = addr - memory_access_desc.hook.start_address
    log_emit(
        self, cpustate,
        f"Protected write access: PC({cpustate.panda_guest_pc:#010x}) Addr({addr:#010x})" +
        (f" ({label}+{offset:#x})" if label else "") + f" Value({value:#x})",
        color=COLOR_PURPLE
    )


def write_hook(self, cpustate, memory_access_desc, label=None):
    state = ""
    if memory_access_desc.on_before:
        state = "ON_BEFORE"
    elif memory_access_desc.on_after:
        state = "ON_AFTER"
    addr = memory_access_desc.addr
    acc_size = memory_access_desc.size
    format = unpack_sym[acc_size]
    (value,) = struct.unpack(format, panda.virtual_memory_read(cpustate, addr, acc_size))
    offset = addr - memory_access_desc.hook.start_address
    log_emit(
        self, cpustate,
        f"Write access: PC({cpustate.panda_guest_pc:#010x}) Addr({addr:#010x})" +
        (f" ({label}+{offset:#x})" if label else "") + f" Value({value:#x}) {state}",
        color=COLOR_GREEN
    )


def read_hook(self, cpustate, memory_access_desc, label=None):
    state = ""
    if memory_access_desc.on_before:
        state = "ON_BEFORE"
    elif memory_access_desc.on_after:
        state = "ON_AFTER"
    addr = memory_access_desc.addr
    acc_size = memory_access_desc.size
    format = unpack_sym[acc_size]
    (value,) = struct.unpack(format, panda.virtual_memory_read(cpustate, addr, acc_size))
    offset = addr - memory_access_desc.hook.start_address
    log_emit(
        self, cpustate,
        f"Read access: PC({cpustate.panda_guest_pc:#010x}) Addr({addr:#010x})" +
        (f" ({label}+{offset:#x})" if label else "") + f" Value({value:#x}) {state}",
        color=COLOR_YELLOW
    )


def update_sael3_state(self, cpustate, memory_access_desc, state_name="", **kwargs):
    assert len(state_name) > 0
    write_hook(self, cpustate, memory_access_desc)
    addr = memory_access_desc.addr
    state_id = struct.unpack('B', panda.virtual_memory_read(cpustate, addr, 1))[0]
    access = "UNKNOWN"
    if memory_access_desc.on_before:
        access = "ON_BEFORE"
    elif memory_access_desc.on_after:
        access = "ON_AFTER"
    log_emit(self, cpustate,
             f"\tupdate_sael3_state addr={addr:#010x} state_id={state_id}, {access}",
             color=COLOR_BLUE)
    if memory_access_desc.on_before and hasattr(self, "sael3"):
        self.sael3.update_curr_state(state_name, state_id)
    if memory_access_desc.on_after and hasattr(self, "sael3"):
        self.sael3.update_state(state_name, state_id)


###############################


def handle_RESET(self, cpustate, tb, hook):
    log.info("RESET CALLED")


def OS_fatal_error(self, cpustate, tb, hook):
    lr = cpustate.env_ptr.regs[14]
    r0 = cpustate.env_ptr.regs[0]

    osfatalerror = panda.virtual_memory_read(cpustate, r0, 4 * 3)
    osfatalerror = struct.unpack("3I", osfatalerror)

    iLine, szFile, szError = osfatalerror

    szFile = read_cstring_panda(panda, szFile)
    szError = read_cstring_panda(panda, szError)

    log.error(
        "FATAL ERROR (%s): from 0x%08x [%s:%d - %s]",
        self.get_current_task_name(cpustate),
        lr,
        szFile,
        iLine,
        szError,
    )


def handle_UDI(self, cpustate, tb, hook):
    lr = cpustate.env_ptr.regs[14]
    log.error(
        "EXCEPTION: UNDEFINED INSTRUCTION (%s) - Faulting PC: 0x%08x",
        self.get_current_task_name(cpustate),
        lr,
    )
    return False


def handle_SWI(self, cpustate, tb, hook):
    return False


def handle_PREFETCH(self, cpustate, tb, hook):
    lr = cpustate.env_ptr.regs[14]
    log.error(
        "EXCEPTION: PREFETCH ABORT (%s) - Faulting PC: 0x%08x",
        self.get_current_task_name(cpustate),
        lr,
    )

    return False


def handle_DA(self, cpustate, tb, hook):
    lr = cpustate.env_ptr.regs[14]
    pc = panda.current_pc(cpustate)
    log.error(
        "EXCEPTION: DATA ABORT (%s) - Faulting PC: 0x%08x",
        self.get_current_task_name(cpustate),
        lr,
    )

    return False


def handle_NA(self, cpustate, tb, hook):
    return False


def handle_IRQ(self, cpustate, tb, hook):
    return False


def handle_FIQ(self, cpustate, tb, hook):
    return False


def crash(self, cpustate, tb, hook):
    log.error("CRASH")
    panda.arch.set_pc(cpustate, 0x10)
    panda.break_exec()


# a hacky way to find the address of the begining of the block
def hash(addr):
    TARGET_PAGE_BITS = 10
    TB_JMP_CACHE_BITS = 12
    TB_JMP_PAGE_BITS = (TB_JMP_CACHE_BITS // 2)
    TB_JMP_CACHE_SIZE = (1 << TB_JMP_CACHE_BITS)
    TB_JMP_PAGE_SIZE = (1 << TB_JMP_PAGE_BITS)
    TB_JMP_ADDR_MASK = (TB_JMP_PAGE_SIZE - 1)
    TB_JMP_PAGE_MASK = (TB_JMP_CACHE_SIZE - TB_JMP_PAGE_SIZE)
    tmp = addr ^ (addr >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS))
    return (((tmp >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS)) & TB_JMP_PAGE_MASK) | (tmp & TB_JMP_ADDR_MASK))

def get_jmp_cache_block(cpustate, addr):
    idx = hash(addr)
    if "NULL" in f"{cpustate.tb_jmp_cache[idx]}":
        return None
    if idx < 0 or idx >= 4096:
        return None
    if int(cpustate.tb_jmp_cache[idx].pc) == addr:
        return cpustate.tb_jmp_cache[idx]
    return None

def get_block_addr(cpustate, addr):
    for offset in range(0, 1<<10, 2):
        block = get_jmp_cache_block(cpustate, addr - offset)
        if block is None:
            continue
        if offset >= block.size:
            return None
        # log.info(f"PC={addr-offset:#010x}, block.size={block.size}")
        return addr - offset
    return None


def heap_oob_write(self, cpustate, memory_access_desc):
    addr = memory_access_desc.addr
    acc_size = memory_access_desc.size
    log.error(
        f"FW_HEAP sanitizer: Heap out-of-bound write on {addr:#010x} (size={acc_size:#x}) - "
        f"Faulting PC: {cpustate.panda_guest_pc:#010x}"
    )
    pc = panda.current_pc(cpustate)
    log.info(f"PC={pc:#010x}")

    addr = get_block_addr(cpustate, pc)
    if addr is None:
        log.warning(f"Could not find the start of block for PC={pc:#010x}. hooking LR")
        self.add_panda_hook(lr, crash)
    else:
        self.add_panda_hook(addr, crash, cb_type="end_block_exec")


def heap_oob_read(self, cpustate, memory_access_desc):
    addr = memory_access_desc.addr
    acc_size = memory_access_desc.size
    lr = cpustate.env_ptr.regs[14]
    log.error(
        f"FW_HEAP sanitizer: Heap out-of-bound read on {addr:#010x} (size={acc_size:#x}) - "
        f"Faulting PC: {cpustate.panda_guest_pc:#010x}"
    )
    pc = panda.current_pc(cpustate)
    log.info(f"PC={pc:#010x}")

    addr = get_block_addr(cpustate, pc)
    if addr is None:
        log.warning(f"Could not find the start of block for PC={pc:#010x}. hooking LR")
        self.add_panda_hook(lr, crash)
    else:
        self.add_panda_hook(addr, crash, cb_type="end_block_exec")


def heap_free_access(self, cpustate, memory_access_desc):
    addr = memory_access_desc.addr
    acc_size = memory_access_desc.size
    log.error(
        f"FW_HEAP sanitizer: Heap use after free on {addr:#010x} (size={acc_size:#x}) - "
        f"Faulting PC: {cpustate.panda_guest_pc:#010x}"
    )
    pc = panda.current_pc(cpustate)
    log.info(f"PC={pc:#010x}")

    addr = get_block_addr(cpustate, pc)
    if addr is None:
        log.warning(f"Could not find the start of block for PC={pc:#010x}. hooking LR")
        self.add_panda_hook(lr, crash)
    else:
        self.add_panda_hook(addr, crash, cb_type="end_block_exec")


def hook_guard_buf(self, addr, size, func_read, func_write=None):
    if func_write is None:
        func_write = func_read

    self.install_mem_hooks([{
        "start": addr,
        "end": addr + size,
        "handler": func_write,
        "write": True,
        "kwargs": {
            "on_before": True,
            "on_after": False,
        },
    }, {
        "start": addr,
        "end": addr + size,
        "handler": func_read,
        "write": False,
        "kwargs": {
            "on_before": True,
            "on_after": False,
        },
    }])


def fw_alloc(self, cpustate, tb, hook):
    _typ = cpustate.env_ptr.regs[0]
    size = cpustate.env_ptr.regs[1]
    p_filename = cpustate.env_ptr.regs[2]
    linenum = cpustate.env_ptr.regs[3]
    lr = cpustate.env_ptr.regs[14]
    pc = panda.current_pc(cpustate)
    filename = read_cstring_panda(panda, p_filename)
    log.debug(f"FW_HEAP alloc: {filename}:{linenum} _typ={_typ}, size={size:#x}, lr={lr:#010x}")
    if _typ != 4:
        return False
    if size % 8 != 0:
        size = ((size // 8) + 1) * 8
    pre_guard_size = max(size // 2, 8)
    post_guard_size = max(size // 2, 8)
    total_size = pre_guard_size + size + post_guard_size
    if self.heap_top + total_size > self.heap.end:
        log.error("FW_HEAP sanitizer: write unmapped")
        panda.arch.set_pc(cpustate, 0x10)
        panda.break_exec()

    # Allocate pre guard buf
    hook_guard_buf(self, self.heap_top, pre_guard_size, heap_oob_read, heap_oob_write)
    self.heap_top += pre_guard_size

    # Allocate the buffer
    p_buf = self.heap_top
    self.heap_meta[p_buf] = {"freed": False, "size": size}
    cpustate.env_ptr.regs[0] = p_buf
    self.heap_top += size
    log.debug(f"FW_HEAP alloc: ptr={p_buf:#010x}")

    # Allocate post guard buf
    hook_guard_buf(self, self.heap_top, post_guard_size, heap_oob_read, heap_oob_write)
    self.heap_top += post_guard_size

    # log.debug(f"FW_HEAP self.heap_meta={self.heap_meta}")
    panda.arch.set_pc(cpustate, lr & ~1)
    panda.break_exec()

    return False


def fw_free(self, cpustate, tb, hook):
    addr = cpustate.env_ptr.regs[0]
    p_filename = cpustate.env_ptr.regs[1]
    linenum = cpustate.env_ptr.regs[2]
    lr = cpustate.env_ptr.regs[14]
    filename = read_cstring_panda(panda, p_filename)
    ptr = panda.virtual_memory_read(cpustate, addr, 4)
    ptr = struct.unpack("<I", ptr)[0]
    log.debug(f"FW_HEAP free: {filename}:{linenum} addr={addr:#010x}, ptr={ptr:#010x} lr={lr:#010x}")
    if ptr < self.heap.begin or self.heap.end <= ptr:
        return False

    chunk = self.heap_meta.get(ptr)
    log.debug(f"FW_HEAP free: chunk={chunk}")
    size = chunk["size"]
    if chunk is None:
        log.error("FW_HEAP sanitizer: free unallocated")
        panda.arch.set_pc(cpustate, 0x10)
        panda.break_exec()
    elif chunk["freed"]:
        log.error(
            f"FW_HEAP sanitizer: Double free on {ptr:#010x} (size={size:#x}) - "
            f"Faulting PC: {cpustate.panda_guest_pc:#010x}"
        )
        panda.arch.set_pc(cpustate, 0x10)
        panda.break_exec()
    else:
        self.heap_meta[ptr]["freed"] = True
        hook_guard_buf(self, ptr, size, heap_free_access)
        panda.arch.set_pc(cpustate, lr & ~1)
        panda.break_exec()
    return False



##########################################################
## HOOKS END
##########################################################

# NOTE: there a lot of hooks that need patterns. They are hardcoded for the CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar image
# They are all just informative - emulation will still work for other firmware
mappings = [
    {
        "name": "OS_handle_interrupt",
        # TODO: pattern
        "address": 0x42393EEE,
        "handler": OS_handle_irq,
    },
    {
        "name": "OS_fatal_error",
        "symbol": "OS_fatal_error",
        "handler": OS_fatal_error,
    },
    {
        "name": "log_format_unk",
        # TODO: pattern
        "address": 0x40C22608,
        "handler": log_format_unk,
    },
    {
        "name": "log_format_unk_s5123ap",
        "address": 0x419110b4,
        "handler": log_format_unk,
    },
    {
        "name": "log_printf",
        "symbol": "log_printf",
        "handler": log_printf,
    },
    {
        "name": "log_printf2",
        "symbol": "log_printf2",
        "handler": log_printf,
    },
    {
        "name": "log_printf_stage",
        # TODO: pattern
        "address": 0x40CB8F5C,
        "handler": log_printf_stage,
    },
    {
        "name": "log_early_clk",
        # TODO: pattern
        "address": 0x4054C9DE,
        "handler": log_format_unk,
    },
    # {
    #     "name": "OS_create_task",
    #     # TODO: pattern
    #     "address": 0x416F90F0,
    #     "handler": OS_create_task,
    # },
    {
        "name": "OS_enter_idle",
        # TODO: pattern
        "address": 0x4054C88E,
        "handler": OS_enter_idle,
    },
    {
        "name": "hw_MCU_Sleep",
        # TODO: pattern
        "address": 0x40D4F9E0,
        "handler": hw_MCU_Sleep,
    },
    {
        "name": "OS_Schedule_Task",
        # TODO: pattern
        "address": 0x416F8D24,
        "handler": OS_Schedule_Task,
    },
    {
        "name": "OS_Create_Event_Group",
        # TODO: pattern
        "address": 0x4054D4FC,
        "handler": OS_event,
    },
    {
        "name": "pal_QueueCreate",
        # TODO: pattern
        "address": 0x405B2464,
        "handler": pal_QueueCreate,
    },
    {
        "name": "pal_Sleep",
        "symbol": "pal_Sleep",
        "handler": pal_Sleep,
    },
    {
        "name": "set_mpu_slot_modem",
        # TODO: pattern
        "address": 0x41739484,
        "handler": set_mpu_slot_modem,
    },
    {
        "name": "OS_DispatchIRQ",
        # TODO: pattern
        "address": 0x42393F4E,
        "handler": OS_handle_irq,
    },
    {
        "name": "pal_MsgReceiveMbx",
        # TODO: pattern
        "address": 0x411560A2,
        "handler": pal_MsgReceiveMbx,
    },
    {
        "name": "pal_MsgReceiveMbx_ret",
        # TODO: pattern
        "address": 0x4115610E,
        "handler": pal_MsgReceiveMbx_ret,
    },
    {
        "name": "pal_MsgSendTo",
        "symbol": "pal_MsgSendTo",
        "handler": pal_MsgSendTo,
    },
    {
        "name": "NV_STUFF",
        # TODO: pattern
        "address": 0x40CAAE84,
        "handler": NV_STUFF,
    },
]

# Add hooks to exception handlers at various locations
handlers = [handle_RESET, handle_UDI, handle_SWI, handle_PREFETCH, handle_DA]

for base_address in [0x00000000]:
    for i, handler in enumerate(handlers):
        mappings += [
            {"name": str(handler), "address": base_address + i * 4, "handler": handler}
        ]
