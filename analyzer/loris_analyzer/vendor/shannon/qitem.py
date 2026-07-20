from collections import OrderedDict
from dataclasses import dataclass, field

PAYLOAD_BY_MSG = OrderedDict()


@dataclass
class Payload:
    _id: int
    size: int


@dataclass
class LteRrcDataInd(Payload):
    _id: int = 0x3C7B
    size: int = 0xC


@dataclass
class QItem:
    header_size: int = 8
    payload: Payload = field(default=LteRrcDataInd)


def get_payload(msg_id: int):
    global PAYLOAD_BY_MSG
    return PAYLOAD_BY_MSG.get(msg_id)


def register_payload(cls):
    global PAYLOAD_BY_MSG

    assert issubclass(cls, Payload), "Payload must be derived from `Payload`"

    assert (
        cls._id not in PAYLOAD_BY_MSG
    ), f"Payload registered twice or with duplicate id {cls._id}"

    PAYLOAD_BY_MSG[cls._id] = cls


register_payload(LteRrcDataInd)
