## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from enum import IntEnum

from firmwire.hw.peripheral import *

from .uart import UARTPeripheral, MotoUARTPeripheral
from .shannoncp import SHMPeripheral, SHM2Peripheral
from .shannonsoc import ShannonSOCPeripheral, ShannonSOC2Peripheral, ShannonSOC5133Peripheral
from .Unknown2Peripheral import Unknown2Peripheral
from .mc_timer import McTimerPeripheral
from .syscfg import SysCfgPeripheral
from .Unknown4Peripheral import Unknown4Peripheral
from .sipc import SIPCPeripheral, SIPC2Peripheral, GIPCPeripheral
from .ClkPeripheral import *
from .PMICPeripheral import PMICPeripheral, PMIC2Peripheral
from .DSPPeripheral import DSPPeripheral, DSP2Peripheral, S355DSPBufferPeripheral, MarconiPeripheral
from .shannon_timer import ShannonTimer, ShannonTCU, ShannonUptimer
from .abox import ShannonAbox
from .s3xxap import S3xxAPBoot
from .sys_cmu import SysCmuPeripheral
from .Unknown5Peripheral import Unknown5Peripheral, Unknown6Peripheral, Unknown7Peripheral, \
    Unknown8Peripheral, Unknown9Peripheral, Unknown10Peripheral, Unknown11Peripheral
from .MsiPeripheral import MsiPeripheral
from .cmu_ucpu import CmuUcpuPeripheral


class GicModel(IntEnum):
    A9_MPCORE = 0,
    A15_MPCORE = 1,
