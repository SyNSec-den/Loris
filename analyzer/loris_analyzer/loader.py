import angr
import archinfo
import argparse
import avatar2
import cle
import copy
import gzip
import io
import logging
import pickle

from functools import partial
from importlib.machinery import SourceFileLoader
from os import path
from typing import List, Optional

import firmwire

from loris_analyzer.globals import *
from loris_analyzer.util.workspace import Workspace
from loris_analyzer.project import LorisProject
from loris_analyzer.symbol import SymbolTable
from loris_analyzer.util import utils
from loris_analyzer.util.logging import dlog, LOG_LOADER
from loris_analyzer.variable import VariableManager
from loris_analyzer.vendor import VendorRegs
from loris_analyzer.vendor.mtk import Mtk
from loris_analyzer.vendor.shannon import Shannon

log = logging.getLogger(__name__)


class LorisSegment(cle.Segment):
    def __init__(
        self, readable: bool, writable: bool, executable: bool, *args, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.readable = readable
        self.writable = writable
        self.executable = executable

    @property
    def is_readable(self) -> bool:
        return self.readable

    @property
    def is_writable(self) -> bool:
        return self.writable

    @property
    def is_executable(self) -> bool:
        return self.executable


class LorisLoader(cle.Loader):
    def __init__(
        self,
        emu: firmwire.loader.FirmWireEmu,
        task,
        workspace: Optional[Workspace] = None,
        entry_point: Optional[int] = None,
        symbols: str = None,
        load_options: Optional[dict] = None,
    ):
        self._task = task
        self._workspace: Workspace = workspace
        self._var_mgr: Optional[VariableManager] = None

        if symbols is not None:
            self._symbols = SymbolTable()
            self._symbols.load_json(symbols)

        self.vendor = None

        uses_thumb = False
        if emu.loader.ARCH.qemu_name == "arm" and task.main_fn & 1 == 1:
            uses_thumb = True

        # if emu.loader.NAME == SHANNON_LOADER:
        if entry_point is None:
            if uses_thumb:
                entry_point = emu.qemu.regs.pc | 1
            else:
                entry_point = emu.qemu.regs.pc
        main_section: avatar2.MemoryRange = emu.get_main_section()
        end_address = main_section.address + main_section.size - 1
        dlog(
            LOG_LOADER,
            f"Loading main section: {main_section.address:#010x}-{end_address:#010x}",
        )
        main_section_data = emu.panda.virtual_memory_read(
            emu.panda.get_cpu(), main_section.address, main_section.size
        )
        if emu.loader.ARCH.qemu_name == "mipsel":
            arch = archinfo.ArchPcode("MIPS:LE:32:default")
        else:
            arch = archinfo.arch_from_id(emu.loader.ARCH.qemu_name)
        blob = cle.Blob(
            None,
            io.BytesIO(main_section_data),
            arch=arch,
            base_addr=main_section.address,
            entry_point=entry_point,
        )
        if load_options is None:
            load_options = dict()
        super().__init__(blob, **load_options)
        self._load_other_sections(emu, main_section)
        self.find_segment_containing(0).executable = False

    @property
    def task(self):
        return self._task

    @property
    def workspace(self) -> Workspace:
        return self._workspace

    @property
    def symbol_table(self) -> SymbolTable:
        return self._symbols

    @property
    def var_mgr(self) -> Optional[VariableManager]:
        return self._var_mgr

    @var_mgr.setter
    def var_mgr(self, mgr: Optional[VariableManager]):
        self._var_mgr = mgr

    def clone(self):
        return copy.deepcopy(self)

    def _load_other_sections(
        self, emu: firmwire.loader.FirmWireEmu, main_section: avatar2.MemoryRange
    ):
        self.main_object.segments = self._create_segments(
            main_section, self.main_object.segments
        )

        # Load segments data, except main section and memory mapped to peripherals
        for mem_range in emu.avatar.memory_ranges:
            sec: avatar2.MemoryRange = mem_range.data
            # TODO: find a better way to skip the main section
            if sec.name == main_section.name:
                continue
            if hasattr(sec, "python_peripheral"):
                continue
            # why would not a section be readable?
            if "r" not in sec.permissions:
                continue

            try:
                data = emu.panda.virtual_memory_read(
                    emu.panda.get_cpu(), sec.address, sec.size
                )
            except ValueError:
                log.warning(
                    f"Skip unmapped section {sec.name} at {sec.address:#010x} (size={sec.size:#x})"
                )
                continue
            if sec.size >= 0x10000000:
                begin = sec.address
                end = sec.address + sec.size - 1
                log.warning(
                    f"Large data section {sec.name} ({begin:#010x} - {end:#010x}) "
                    f"will be left uninitialized"
                )
            else:
                arch = archinfo.arch_from_id(emu.loader.ARCH.qemu_name)
                blob = cle.Blob(
                    None, io.BytesIO(data), arch=arch, base_addr=sec.address
                )
                blob.segments = self._create_segments(sec, blob.segments)
                try:
                    self._map_object(blob)
                except cle.CLEError:
                    log.warning(
                        f"Skip loading section {sec.address:#010x} (size={sec.size:#x})"
                    )

    @staticmethod
    def _create_segments(
        section: avatar2.MemoryRange, segments: cle.Regions[cle.Segment]
    ) -> List[LorisSegment]:
        return [
            LorisSegment(
                "r" in section.permissions,
                "w" in section.permissions,
                "x" in section.permissions,
                vaddr=segment.vaddr,
                filesize=segment.filesize,
                memsize=segment.memsize,
                offset=segment.offset,
            )
            for segment in segments
        ]


def get_firmwire_args(workspace: Workspace) -> argparse.Namespace:
    args = argparse.Namespace()
    args.workspace = workspace
    args.debug = False
    args.consecutive_ports = False
    args.injected_task = None
    args.fuzz = None
    args.fuzz_triage = None
    args.fuzz_input = None
    args.fuzz_persistent = False
    args.fuzz_crashlog_replay = None
    args.raw_asm_logging = True
    args.verbose_call_logging = False
    args.symbol_db = None
    args.additional_hooks = None
    args.asan = None

    return args


def store_regs(task_regs, emu):
    regs = VendorRegs()
    for name in emu.qemu.regs.__dict__.keys():
        if name == "_target":
            continue
        regs.__setattr__(name, emu.qemu.regs.__getattribute__(name))
    task_regs[emu.qemu.regs.pc] = regs


def variable_manager(
    emu: firmwire.loader.FirmWireEmu,
    task,
    init_func: Optional[int],
) -> Optional[VariableManager]:
    ret_addr = None
    if init_func is not None:
        emu.run_until(init_func & ~1, temporary=True)
        ret_addr = emu.qemu.pypanda.arch.get_return_address(emu.qemu.pypanda.get_cpu())
    else:
        emu.run_until(task.main_fn & ~1)

    # start variable recording
    main_section: avatar2.MemoryRange = emu.get_main_section()
    try:
        stack_iv = utils.Interval(task.stackbase, task.stackbase + task.stacksize)
    except AttributeError:
        stack_iv = utils.Interval(0, 0)
    end_addr = max(
        main_section.address + main_section.size,
        (main_section.address & 0xF0000000) + 0x10000000,
    )
    hook_iv = utils.Interval(main_section.address, end_addr)
    log.info(f"Task stack: {stack_iv}")
    log.info(f"Hooking memory accesses in {hook_iv}")
    var_mgr = VariableManager(stack_iv, hook_iv)
    emu.add_panda_mem_hook(
        hook_iv.begin,
        hook_iv.end,
        var_mgr.write_panda_hook,
        w=True,
        on_before=False,
        on_after=True,
    )
    if emu.loader.NAME == SHANNON_LOADER:
        malloc_sym = emu.symbol_table.lookup("pal_MemAlloc")
        malloc_addr = malloc_sym.address & ~1
        size_reg = "r1"
    elif emu.loader.NAME == MTK_LOADER:
        malloc_addr = emu.symbols["kal_get_buffer"]
        size_reg = "a2"
    else:
        return None
    emu.add_panda_hook(malloc_addr, var_mgr.heap_alloc_hook, size_reg=size_reg)

    if init_func is not None:
        assert ret_addr is not None
        emu.run_until(ret_addr & ~1, temporary=True)
    else:
        loader = LorisLoader(emu, task, load_options={"auto_load_libs": False})

        proj = LorisProject(loader)
        cfg = proj.analyses.CFGEmulated(
            context_sensitivity_level=1,
            call_depth=1,
            starts=(task.main_fn,),
            keep_state=False,
            resolve_indirect_jumps=False,
        )
        loop_finder = proj.analyses[angr.analyses.LoopFinder].prep(kb=cfg.kb)(
            normalize=True
        )
        if len(loop_finder.loops) == 0:
            log.error("Failed to find a loop")
            return None
        loop_entry: int = loop_finder.loops[0].entry.addr
        log.info(f"Found the outer loop entry: {loop_entry:#010x}")

        emu.run_until(loop_entry & ~1, temporary=True)

    # This is because Panda does not provide any API to remove the memory hook
    # and the heap alloc hook
    var_mgr.stop_recording = True
    return var_mgr


def prepare_machine(
    workspace: Workspace,
    loader: firmwire.loader.Loader,
    task_name: str,
    init_func: Optional[int],
):
    machine = loader.get_machine()

    firmwire_args = get_firmwire_args(workspace)

    modkit_path = path.join(path.dirname(firmwire.__file__), "..", "modkit")
    machine.modkit.append_search_path(path.join(modkit_path, loader.NAME, "build"))

    task_list = [task_name]
    if loader.NAME == SHANNON_LOADER:
        bg_task_name = "Background"
    elif loader.NAME == MTK_LOADER:
        bg_task_name = "0IDLE"
    task_list.append(bg_task_name)
    firmwire_args.exclusive = task_list

    if not machine.initialize(loader, firmwire_args):
        log.error("Machine failed to initialize")
        return None

    if loader.NAME == SHANNON_LOADER:
        # if not machine.load_and_inject_task(ANALYZER_MOD):
        #     return None
        machine.enable_tasks_exclusive(task_list)

    log.info(f"Machine initialization time took {machine.time_running():.2f} seconds")

    if loader.NAME == SHANNON_LOADER:
        machine.print_task_list()

    log.info("Starting emulator %s", machine.instance_name)

    task = machine.get_task_by_name(task_name)
    if task is None:
        log.error(f"Failed to find task: {task_name}")
        return None

    task_regs = dict()
    if init_func is not None:
        machine.set_breakpoint(
            task.main_fn & ~1,
            partial(store_regs, task_regs),
            temporary=True,
            continue_after=True,
        )

    var_mgr = variable_manager(machine, task, init_func)
    wait_for_bg_task = False
    if machine.get_current_task_name(machine.panda.get_cpu()) != task.name:
        wait_for_bg_task = True

    bg_task = machine.get_task_by_name(bg_task_name)
    regs = machine.qemu.regs
    if wait_for_bg_task:
        machine.run_until(bg_task.main_fn & ~1, temporary=True)
        # Revert the execution back to the task main function
        regs = task_regs[task.main_fn & ~1]

    return machine, var_mgr, task, regs


def prepare_loader(
    modem_file: Optional[str],
    workspace: Workspace,
    task_name: str,
    init_func: Optional[int],
) -> Optional[LorisLoader]:
    loader_path = workspace.path("/loader.pickle.gz")
    if loader_path.exists():
        with gzip.open(loader_path.to_path(), "rb") as f:
            return pickle.load(f)

    if modem_file is None:
        log.error(f"{loader_path.to_path()}: no such file. `modem_file` is required")
        return None

    loader = firmwire.loader.load_any(
        modem_file,
        workspace,
        keep_trying=True,
        loader_specific_args={"mtk": {"nv_data": "/loris_analyzer_deps/FirmWire/mnt/"}},
    )

    if loader is None:
        log.error("Failed to load firmware")
        return None

    machine, var_mgr, task, regs = prepare_machine(
        workspace, loader, task_name, init_func
    )

    uses_thumb = False
    if machine.loader.ARCH.qemu_name == "arm" and task.main_fn & 1 == 1:
        uses_thumb = True

    symbols_path = workspace.path("/symbol_table.sym")
    machine.symbol_table.save_json(symbols_path.to_path())

    loader = LorisLoader(
        machine,
        task,
        workspace=workspace,
        symbols=symbols_path.to_path(),
        load_options={"auto_load_libs": False},
    )
    loader.var_mgr = var_mgr

    # import IPython
    # IPython.embed()

    if machine.loader.NAME == SHANNON_LOADER:
        loader.vendor = Shannon(machine.get_queues(), task, regs, thumb=uses_thumb)
    elif machine.loader.NAME == MTK_LOADER:
        loader.vendor = Mtk(task, regs)

    # log.info("Extracting tables...")
    # utils.extract_tables(machine, workspace)

    with gzip.open(loader_path.to_path(), "wb") as f:
        pickle.dump(loader, f)

    return loader


def load_any(
    modem_file: str,
    workspace: Optional[str],
    task_name: str,
    init_func: Optional[int],
) -> Optional[LorisLoader]:
    if workspace:
        w = Workspace(workspace)
    else:
        w = Workspace(modem_file + "_workspace")

    w.create()

    loader = prepare_loader(modem_file, w, task_name, init_func)

    return loader
