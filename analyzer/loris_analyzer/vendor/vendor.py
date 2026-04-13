import angr

from abc import ABC, abstractmethod
from typing import List, Optional, Union


class VendorRegs(object):
    def __init__(self, register_dict: Optional[dict] = None):
        if register_dict is not None:
            self.__dict__.update(register_dict)


class Vendor(ABC):
    def __init__(self, symbol_mappings: list):
        self._regs = VendorRegs()
        self._symbol_mappings = symbol_mappings
        self.NAS_EMM_MSG_ID_LIST = [
            0x42,
            0x44,
            0x45,
            0x46,
            0x49,
            0x4B,
            0x4E,
            0x4F,
            0x50,
            0x52,
            0x54,
            0x55,
            0x5D,
            0x61,
            0x62,
            0x64,
            0x68,
        ]
        self.NAS_ESM_MSG_ID_LIST = [
            0xC1,
            0xC5,
            0xC9,
            0xCD,
            0xD1,
            0xD3,
            0xD5,
            0xD7,
            0xD9,
            0xDB,
            0xDC,
            0xE8,
            0xEA,
            0xEB,
        ]
        self.SEC_HDR_TYPE_RANGE = range(4)
        self._symbols = dict()

    @property
    def symbol_mappings(self) -> list:
        return self._symbol_mappings

    @abstractmethod
    def add_input_fields(
        self,
        state: angr.SimState,
        task: str,
        protocol_disc: int = 7,
        nas_msg_id_list: Optional[Union[int, List[int]]] = None,
    ): ...

    def load_registers(self, state: angr.SimState):
        for name, value in self._regs.__dict__.items():
            if value is None:
                continue
            try:
                state.regs.__setattr__(name, value)
            except AttributeError:
                pass

    @abstractmethod
    def prepare_mapping(self, m): ...

    def add_symbols(self, symbols: List[dict]):
        if not hasattr(self, "_symbols"):
            self._symbols = dict()
        for sym in symbols:
            self._symbols[sym["name"]] = sym["address"]
