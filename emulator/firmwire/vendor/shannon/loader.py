## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import firmwire.loader
import logging
import tarfile
import zipfile
import filetype
import lz4.frame
import re
import os

from pathlib import PurePath

from .TOCFile import *
from avatar2 import *

import firmwire.vendor.shannon as shannon
import firmwire.vendor.shannon.mpu
import firmwire.vendor.shannon.soc

from firmwire.hw.soc import get_soc
from .hw import *
from firmwire.hw.glink import GLinkPeripheral
from firmwire.emulator.patterndb import PatternDB, PatternDBEntry
from .machine import ShannonMachine
from .pattern import PATTERNS as CORTEX_R_PATTERNS
from .cortex_a.s5133_patterns import PATTERNS as S5133AP_PATTERNS
from .cortex_a.s5123_patterns import PATTERNS as S5123_PATTERNS

log = logging.getLogger(__name__)


class ARM_CORTEX_R7(ARM):
    cpu_model = "cortex-r7"
    qemu_name = "arm"
    gdb_name = "arm"
    angr_name = "arm"

    capstone_arch = CS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN | CS_MODE_THUMB
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_LITTLE_ENDIAN | KS_MODE_THUMB
    unicorn_arch = UC_ARCH_ARM
    unicorn_mode = UC_MODE_LITTLE_ENDIAN | UC_MODE_THUMB

    @staticmethod
    def init(avatar):
        pass


class ARM_CORTEX_A53(ARM):
    cpu_model = "cortex-a53"
    qemu_name = "aarch64"
    gdb_name = "aarch64"
    angr_name = "aarch64"
    capstone_arch = CS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN | CS_MODE_THUMB
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_LITTLE_ENDIAN | KS_MODE_THUMB
    unicorn_arch = UC_ARCH_ARM
    unicorn_mode = UC_MODE_LITTLE_ENDIAN | UC_MODE_THUMB

    @staticmethod
    def init(avatar):
        pass


class ARM_CORTEX_A78(ARM):
    cpu_model = "cortex-a78"
    qemu_name = "arm"
    gdb_name = "arm"
    angr_name = "arm"

    capstone_arch = CS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN | CS_MODE_THUMB
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_LITTLE_ENDIAN | KS_MODE_THUMB
    unicorn_arch = UC_ARCH_ARM
    unicorn_mode = UC_MODE_LITTLE_ENDIAN | UC_MODE_THUMB

    @staticmethod
    def init(avatar):
        pass


class ShannonLoader(firmwire.loader.Loader):
    NAME = "shannon"
    LOADER_ARGS = {
        "nv_data": {"type": PurePath, "help": "A path to a NV_DATA.bin file"},
        "external_peripherals": {"type": int, "help": "Do not load peripherals"},
    }

    @property
    def task_layout(self):
        return self._task_layout

    @task_layout.setter
    def task_layout(self, layout):
        self._task_layout = layout

    @property
    def ARCH(self):
        if self.modem_soc.name in ("S5123AP", "S5123"):
            return ARM_CORTEX_A78
        else:
            return ARM_CORTEX_R7

    @staticmethod
    def is_relevant(path):
        ft = filetype.guess(path)
        return (
            ft is not None and ft.mime in ["application/x-lz4", "application/x-tar"]
        ) or path.endswith(".bin")

    def try_load(self):
        # Make sure the path is a valid TOC file
        if not self.toc_load_modem_file(self.path):
            return False

        # We need the SoC version to handle quirks and memory layout changes
        if not self.guess_soc_version():
            return False

        # We now have an extracted TOC file and selected SoC definition

        # Resolve symbol patterns
        self.unsafe_regions = []

        # Set during patterndb finding
        self._task_layout = None

        if self.modem_soc.name in ("S5123AP", "S5123"):
            patterns = S5123_PATTERNS
        elif self.modem_soc.name == "S5133AP":
            patterns = S5133AP_PATTERNS
        else:
            patterns = CORTEX_R_PATTERNS

        try:
            db = PatternDB(self)

            for name, entry in patterns.items():
                pat = PatternDBEntry(name)
                for k, v in entry.items():
                    setattr(pat, k, v)

                db.add_pattern(pat)

            main_toc = self.modem_file.get_section("MAIN")
            db.find_patterns(main_toc.data, main_toc.load_address)
        except ValueError as e:
            log.exception("Error resolving symbols")
            return False

        assert self._task_layout is not None

        if not self.build_memory_map():
            return False

        self._machine_class = ShannonMachine

        return True

    def build_memory_map(self):
        if self.modem_soc.name == "S5123AP":
            from firmwire.vendor.shannon.mmu import MMUEntry
            mem_entries = [
                MMUEntry(0, 0x00000000, 0x00100000, 0x1940c),
                MMUEntry(1, 0x40000000, 0x01e00000, 0x1940c),
                MMUEntry(2, 0x41e00000, 0x06200000, 0x11c1d),
                MMUEntry(3, 0x48000000, 0x01a00000, 0x11c11),
                MMUEntry(4, 0x49a00000, 0x00200000, 0x11c1d),
                MMUEntry(5, 0x49c00000, 0x00100000, 0x11c11),
                MMUEntry(6, 0x49d00000, 0x00a00000, 0x19411),
                MMUEntry(7, 0x4a700000, 0x00400000, 0x11c11),
                MMUEntry(8, 0x4ab00000, 0x01a00000, 0x11c1d),
                MMUEntry(9, 0x4c500000, 0x01300000, 0x11c11),
                MMUEntry(10, 0x50000000, 0x07e00000, 0x11c11),
                MMUEntry(11, 0x80000000, 0x01000000, 0xc11),
                MMUEntry(12, 0x81000000, 0x01000000, 0xc11),
                MMUEntry(13, 0x82000000, 0x01000000, 0xc11),
                MMUEntry(14, 0x83000000, 0x01000000, 0xc11),
                MMUEntry(15, 0x84000000, 0x01000000, 0xc11),
                MMUEntry(16, 0x85000000, 0x01000000, 0xc11),
                MMUEntry(17, 0x87000000, 0x00100000, 0xc11),
                MMUEntry(18, 0x87200000, 0x00100000, 0xc11),
                MMUEntry(19, 0x88000000, 0x00100000, 0xc11),
                MMUEntry(20, 0x88100000, 0x00200000, 0xc11),
                MMUEntry(21, 0x8a000000, 0x01000000, 0xc11),
                MMUEntry(22, 0x8f000000, 0x01000000, 0xc11),
                MMUEntry(23, 0x90000000, 0x0f000000, 0xc11),
                MMUEntry(24, 0xc0000000, 0x20000000, 0xc11),
                MMUEntry(25, 0xe0000000, 0x08000000, 0x8411),
                MMUEntry(26, 0xe8000000, 0x08000000, 0xc11),
                MMUEntry(1313, 0x61e00000, 0x00100000, 0x11c0c),
            ]
            self.unsafe_regions += [(0, 0x00100000), (0x40000000, 0x48000000)]
        elif self.modem_soc.name == "S5123":
            from firmwire.vendor.shannon.mmu import MMUEntry
            modem_main = self.modem_file.get_section("MAIN")
            sym = self.symbol_table.lookup("main_mmu_table")
            if sym is None:
                log.error(
                    "Unable to find MPU table in modem binary. Cannot create memory map"
                )
                return False

            mem_entries, unsafe_regions = shannon.mmu.parse_mmu_table(modem_main, sym.address)
            # To inject task
            mem_entries.append(
                MMUEntry(1313, 0x70000000, 0x00100000, 0x11c0c),
            )
            self.unsafe_regions.extend(unsafe_regions)
        elif self.modem_soc.name == "S5133AP":
            from firmwire.vendor.shannon.mpu import MPUEntry
            mem_entries = [
                MPUEntry(0, 0x00000000, 0x00100000, 0x0329),
                MPUEntry(1, 0x40000000, 0x10000000, 0x0329),
                # MPUEntry(2, 0x48000000, 0x08000000, 0x1308),
                MPUEntry(3, 0x50000000, 0x10000000, 0x1308),
                MPUEntry(3, 0x60000000, 0x10000000, 0x1308),
                MPUEntry(3, 0x70000000, 0x10000000, 0x1308),
                MPUEntry(3, 0x80000000, 0x10000000, 0x1308),
                MPUEntry(3, 0x90000000, 0x10000000, 0x1308),
                MPUEntry(3, 0xa0000000, 0x10000000, 0x1308),
                MPUEntry(3, 0xb0000000, 0x10000000, 0x1308),
                MPUEntry(3, 0xc0000000, 0x10000000, 0x1308),
                MPUEntry(3, 0xd0000000, 0x10000000, 0x1308),
                MPUEntry(3, 0xe0000000, 0x10000000, 0x1308),
            ]
            self.unsafe_regions += [(0, 0x00100000), (0x47b00000, 0x49300000)]
        else:
            #######################
            # MPU Memory Map
            #######################

            modem_main = self.modem_file.get_section("MAIN")
            sym = self.symbol_table.lookup("boot_mpu_table")
            if sym is None:
                log.error(
                    "Unable to find MPU table in modem binary. Cannot create memory map"
                )
                return False

            mem_entries = shannon.mpu.parse_mpu_table(modem_main, sym.address)
        for ent in mem_entries:
            print(ent)
        table = shannon.mpu.consolidate_mpu_table(mem_entries)
        self.mpu_table = table

        for entry in table:
            mpu = entry.mpu
            name = "MPU%d_%08x" % (mpu.slot, entry.start)
            self.add_memory_range(
                entry.start, entry.size, name=name, permissions=mpu.get_rwx_str()
            )

        #######################
        # TOC File Memory Map
        #######################

        loader_workspace = self.workspace.path("/loader")
        loader_workspace.mkdir()

        # extract individual sections for the PANDA configurable machine to load
        for entry in self.modem_file.entries:
            print(entry)
            if not entry.meta_section:
                size = entry.size
                section_path = loader_workspace.join(
                    "modem_%08x.bin" % entry.load_address
                )

                with section_path.open(mode="wb") as fp:
                    fp.write(entry.data)

                if self.modem_soc.name != "S5123AP" and self.modem_soc.name != "S5123" and self.modem_soc.name != "S5133AP":
                    # TODO: add memory map merging to prevent this hardcode
                    if entry.name == "MAIN":
                        size = 0x3000000

                if self.modem_soc.name == "S5123":
                    if entry.name == "INFO":
                        continue
                # round up and page align
                if size % 0x1000 != 0:
                    size = (size + 0x1000) & ~0x1000

                name = "TOC_" + entry.name

                self.add_memory_range(
                    entry.load_address, size, file=section_path.to_path(), name=name
                )

                # It is still unclear why we need boot in high AND low
                # (probably interrupts vectors need to be at 0x0)
                if entry.name == "BOOT":

                    self.add_memory_range(
                        0x00000000,
                        size,
                        file=section_path.to_path(),
                        name=name + "_LOW",
                    )

        ########################
        # Peripheral Memory Map
        ########################
        external_peripherals = self.loader_args["external_peripherals"]

        for peripheral in self.modem_soc.peripherals:
            self.create_soc_peripheral(peripheral)

        for i in range(self.modem_soc.NUM_TIMERS):
            freq = 6000000
            if i == 0:
                freq = 100000
            self.create_timer(
                self.modem_soc.TIMER_BASE + i * 0x100, 0x100,
                "tim{}".format(i), self.modem_soc.iTINT0 + i, freq,
                gic_model=self.modem_soc.GIC_MODEL)

        self.create_peripheral(
            self.modem_soc.CLK_PERIPHERAL, self.modem_soc.SOC_CLK_BASE, 0xA000, name="SOC_CLK")
        self.create_peripheral(
            self.modem_soc.SOC_PERIPHERAL, self.modem_soc.SOC_BASE, 0x2000, name="SOC")
        self.create_peripheral(UARTPeripheral, 0x84000000, 0x1000, name="boot_uart")
        self.create_peripheral(
            self.modem_soc.SHM_PERIPHERAL, self.modem_soc.SHM_BASE, 0x500000, name="SHM")
        self.create_peripheral(
            self.modem_soc.IPC_PERIPHERAL, self.modem_soc.SIPC_BASE, 0x1000, name="SIPC")

        if self.modem_soc.name in ("S335AP", "S337AP", "S353AP", "S355AP", "S360AP", "S5000AP"):
            self.create_peripheral(ShannonTCU, 0x8200F000, 0x100, name="TCU")

            self.create_peripheral(LoggingPeripheral, 0x8F900000, 0x1000, name="unk_per10")
            self.create_peripheral(LoggingPeripheral, 0x8FC30000, 0x1000, name="usi1")
            self.create_peripheral(LoggingPeripheral, 0x8FC22000, 0x1000, name="usi2")
            self.create_peripheral(LoggingPeripheral, 0x8FC60000, 0x1000, name="usi3")
            self.create_peripheral(LoggingPeripheral, 0x8FD20000, 0x1000, name="usi4")

            self.create_peripheral(MarconiPeripheral, 0xC1800000, 0x5000, name="marconi")
            self.create_peripheral(CyclicBitPeripheral, 0xC2000000, 0x1000, name="marconi2")
        elif self.modem_soc.name in ("S5123", ):
            self.create_mc_timer(0x840f0000, 0x1000)
            self.create_peripheral(UARTPeripheral, 0x84010000, 0x1000, name="uart2")
            self.create_peripheral(Unknown2Peripheral, 0x81020000, 0x1000, name="unk_per8")
            self.create_peripheral(CyclicBitPeripheral, 0x14500000, 0x5000, name="marconi")
            self.create_peripheral(CyclicBitPeripheral, 0x14420000, 0x1000, name="marconi2")

        if self.modem_file.has_section("NV"):
            nv = self.modem_file.get_section("NV")
            nv_base_address = nv.load_address
            nv_data_size = nv.size
        # NOTE: this assumes that NV_PROT comes right after NV_NORM!
        elif self.modem_file.has_section("NV_NORM"):
            nv = self.modem_file.get_section("NV_NORM")
            nv_base_address = nv.load_address
            extra_size = nv_base_address % 0x1000
            nv_base_address &= 0xFFFFF000
            nv_data_size = nv.size * 2 + extra_size
            nv_data_size += 0x1000 - (nv_data_size & 0xFFF) 
        else:
            nv_base_address = 0x45600000
            nv_data_size = 0x100000
            log.warning(
                "Modem file does not have NV section information...defaulting to 0x%x",
                nv_base_address,
            )

        # size gathered from modem.bin TOC
        if self.loader_args["nv_data"]:
            nv_data_path = self.loader_args["nv_data"]

            if not os.access(nv_data_path, os.R_OK) or not os.path.isfile(nv_data_path):
                log.error("NV data file path is missing")
                return False

            nv_file_size = os.path.getsize(nv_data_path)

            if nv_file_size == 0:
                log.error("Blank NV data file provided")
                return False
            elif nv_file_size > nv_data_size:
                log.error(
                    "NV data file provided exceeds NV section size (0x%x > 0x%x)",
                    nv_file_size,
                    nv_data_size,
                )
                return False
            else:
                log.info(
                    "Loading NV data from file %s to %x (0x%x bytes)",
                    nv_data_path,
                    nv_base_address,
                    nv_data_size,
                )
                self.add_memory_range(
                    nv_base_address,
                    nv_data_size,
                    file=nv_data_path,
                    name="NV",
                    permissions="rw-",
                )
        else:
            log.info("Using blank NV data")
            self.add_memory_range(
                nv_base_address, nv_data_size, name="NV", permissions="rw-"
            )

        if self.modem_soc.name == "S5123AP":
            self.add_memory_range(
                0x81040000,
                0x8000,
                name="gic",
                qemu_name="a15mpcore_priv",  # hopefully close enough
                qemu_properties=[
                    {"name": "num_cpu", "value": 1, "type": "int"},
                    # max supported by shannon (0xLAB_42393f48)
                    {"name": "num_irq", "value": 0x12A, "type": "int"},
                ],
            )
        elif self.modem_soc.name == "S5133AP":
            self.add_memory_range(
                0x81000000 - 0x1000,
                0x8000,
                name="gic",
                qemu_name="a15mpcore_priv",  # hopefully close enough
                qemu_properties=[
                    {"name": "num_cpu", "value": 1, "type": "int"},
                    # max supported by shannon (0xLAB_42393f48)
                    {"name": "num_irq", "value": 0x12A, "type": "int"},
                ],
            )
        elif self.modem_soc.name == "S5123":
            self.add_memory_range(
                0x800f0000,
                0x8000,
                name="gic",
                qemu_name="a15mpcore_priv",  # hopefully close enough
                qemu_properties=[
                    {"name": "num_cpu", "value": 1, "type": "int"},
                    # max supported by shannon (0xLAB_42393f48)
                    {"name": "num_irq", "value": 0x12A, "type": "int"},
                ],
            )
        else:
            self.add_memory_range(
                0x80000000,
                0x2000,
                name="gic",
                qemu_name="a9mpcore_priv",  # hopefully close enough
                qemu_properties=[
                    {"name": "num_cpu", "value": 1, "type": "int"},
                    # max supported by shannon (0xLAB_42393f48)
                    {"name": "num_irq", "value": 0x12A, "type": "int"},
                ],
            )

        self.add_memory_annotation(0x44200000, 0x1400000, "sysmem")
        self.add_memory_annotation(0x04000000, 0x1D000, "BIOS")
        self.add_memory_annotation(0xC1001000, 0x1000, "twog_something")

        # TODO: move GLINK peripheral creation to emulation time
        self.create_peripheral(GLinkPeripheral, 0xEC000000, 0x1000, name="glink")

        # self.add_memory_annotation(0x47f04000, 0x10000, "m_mem_unk_32_rxtx")
        self.create_peripheral(ShannonAbox, 0x47F00000, 0x14000, name="abox")
        self.add_memory_annotation(0xC1000000, 0x1000, "twog_something_2")

        # Referenced in the modem after powerup of domains
        # Faulting address: 0x80001108
        # Faulting PC: 0x4004546: str.w   r1, [r0, #0x104]
        self.add_memory_annotation(0x80000000, 0x2000, "unk_per7")

        return True

    def create_timer(self, start, size, name, irq_num, freq=1000000, gic_model=0):
        self.add_memory_range
        props = [
            {"type": "uint32", "name": "irq_num", "value": irq_num},
            {"type": "uint32", "name": "freq", "value": freq},
            {"type": "uint32",  "name": "gic_model", "value": gic_model},
        ]
        mr = self.add_memory_range(
            start,
            size,
            name=name,
            qemu_name="shannon_timer",
            qemu_properties=props,
            permissions="rw-",
        )
        return mr

    def create_mc_timer(self, start, size):
        self.add_memory_range
        mr = self.add_memory_range(
            start,
            size,
            name="MC_TIMER",
            qemu_name="exynos4210.mct",
            permissions="rw-",
        )
        return mr

    def toc_load_modem_file(self, path):
        modem_fp = self.open_modem_bin(path)

        if modem_fp is None:
            return False

        # load and parse the firmware image, recovering memory sections
        try:
            self.modem_file = TOCFile(modem_fp)
            modem_fp.close()
        except IOError as e:
            log.error("Failed to read the modem file: %s", e)
            return False
        except TOCFileException as e:
            log.error("Failed to parse the modem file: %s", e)
            return False

        main = self.modem_file.get_section("MAIN")

        # just keep an overlay copy of MAIN that isn't zeroed on boot
        self.trace_data_offset = main.load_address
        self.trace_data = main.data.tobytes()

        return True

    def open_modem_bin(self, path):
        if path.endswith(".bin"):
            return open(path, "rb")

        tfp = None

        # extract the firmware from a Samsung CP_* tar file LZ4 encoded or not
        try:
            if path.endswith("lz4"):
                lzfp = lz4.frame.open(open(path, "rb"))
                tfp = tarfile.open(fileobj=lzfp)
            else:
                tfp = tarfile.open(path, "r")
        except tarfile.ReadError as e:
            log.error("Not a valid tar file")
            return None

        files = tfp.getnames()

        if len(files) < 1:
            log.error("Modem CP tarfile needs at least modem.bin")
            return None

        if len(files) > 2:
            log.warning("Modem CP tarfile has unexpected number of files: %s", files)

        lz4_compressed = "lz4" in files[0]

        modem_name = "modem.bin"

        if lz4_compressed:
            modem_name += ".lz4"

        if modem_name not in files:
            log.error("Modem CP tarfile is missing required modem.bin")
            return None

        modem_fp = tfp.extractfile(modem_name)

        if lz4_compressed:
            modem_fp = lz4.frame.open(modem_fp)

        return modem_fp

    def guess_soc_version(self):
        main = self.modem_file.get_section("MAIN")

        # Try to find the version with the date first
        found = re.search(
            rb"""
          (?P<SOC>[S][0-9]{3,}(AP)?) # SOC-ID
          .{,10}                    # garbage or unknown (usually underscores)
          (?P<date>[0-9]{8})        # Date as YYYYMMDD (for rough SoC revision)
          [^\x00]*                  # null terminator""",
            main.data,
            re.M | re.S | re.X,
        )

        if found is None:
            found = re.search(
                rb"""
              (?P<SOC>[S][0-9]{4,}(AP)?) # SOC-ID
              .{,30}                    # garbage or unknown (usually underscores)
              (?P<date>[0-9]{6})        # Date as YYYYMMDD (for rough SoC revision)
              .{,10}
              [^\x00]*                  # null terminator""",
                main.data,
                re.M | re.S | re.X,
            )

        # First pattern may fail for some OEM modified Shannon images
        if found is None:
            found = re.search(
                rb"""
              (?P<SOC>[S][0-9]{3,}(AP)?) # SOC-ID
              .{,10}                    # garbage or unknown (usually underscores)
              [^\x00]*                  # null terminator""",
                main.data,
                re.M | re.S | re.X,
            )

            if found is None:
                log.error(
                    "Unable to automatically determine the SoC type from the boot image"
                )
                return False

        soc_guess = found.group("SOC").decode()

        # SoC date is a best effort approach
        soc_date = (
            int(found.group("date").decode()) if "date" in found.groupdict() else 0
        )

        # Special handling for Moto One images; these don't use a classic date, but ID numbers
        if soc_guess == "S337AP":
            soc_date = int(found.group().split(b"SGCS_QB")[-1])

        self.modem_soc = get_soc(self.NAME, soc_guess)

        if self.modem_soc is None:
            found = re.search(
                rb"""
              \x00
              (?P<SOC>[S][0-9]{3,}(AP)?) # SOC-ID
              .{,10}                    # garbage or unknown (usually underscores)
              [^\x00]*                  # null terminator""",
                main.data,
                re.M | re.S | re.X,
            )
            if found:
                soc_guess = found.group("SOC").decode()
                self.modem_soc = get_soc(self.NAME, soc_guess)
                soc_date = 0

        if self.modem_soc is None:
            log.error("Guessed SoC '%s' is not supported", soc_guess)
            return False

        # Initialize SoC object
        self.modem_soc = self.modem_soc(soc_date, main)

        log.info("SoC %s (automatic)", repr(self.modem_soc))

        return True


firmwire.loader.register_loader(ShannonLoader)
