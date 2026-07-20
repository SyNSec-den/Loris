import angr
import logging

from typing import List

from loris_analyzer.globals import *
from loris_analyzer.vendor import mtk, Vendor

log = logging.getLogger(__name__)


class Mtk(Vendor):
    def __init__(self, task, regs=None):
        super().__init__(mtk.hooks.symbol_mappings)
        if regs is not None:
            for name in regs.__dict__.keys():
                if name == "_target":
                    continue
                self._regs.__setattr__(name, regs.__getattribute__(name))

    def add_input_fields(
        self,
        state: angr.SimState,
        task: str,
        protocol_disc: int = 7,
        nas_msg_id_list: List[int] = None,
    ):
        if task == MTK_EMM:
            self._add_input_fields_emm(state)

    def prepare_mapping(self, m):
        return m

    def _add_input_fields_emm(self, state: angr.SimState):
        pass
