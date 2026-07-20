import intervaltree

from loris_analyzer.vendor.hooks import (
    SimError,
    SimMemcmp,
    SimMemcpy,
    SimMemzero,
    SimReturnOne,
    SimReturnZero,
    SimSkipFunction,
)
from loris_analyzer.vendor.shannon.hooks import (
    SimMemequal,
    SimMemsetBSV,
    SimSendMsg,
)

const_variables = [
    intervaltree.Interval(
        0x4826CBD6, 0x4826CBE8
    ),  # SAEMM_OngoingProcTypeByProc (SAEMM_state_tables)
    intervaltree.Interval(
        0x4826CBE8, 0x4826CC78
    ),  # SAEMM_StateByProc (SAEMM_state_tables)
    intervaltree.Interval(
        0x48A5DA9C, 0x48A5DAB8
    ),  # SAEMM_StateMainNames (SAEMM_state_tables)
    intervaltree.Interval(
        0x48A5DAB8, 0x48A5DAE4
    ),  # SAEMM_StateServiceNames (SAEMM_state_tables)
    intervaltree.Interval(
        0x4826CA64, 0x4826CA80
    ),  # gEmmAsStateStr (SAEMM_emm_as_tables)
    intervaltree.Interval(
        0x4826CA80, 0x4826CBAD
    ),  # SAEMM_EmmAsMap (SAEMM_emm_as_tables)
]

additional_constraints = [
    {
        "address": 0x48E031BD,
        "size": 1,
        "min": 0,
        "max": 17,
    },  # EmmProc.curr (SAEMM_state_constraints)
    {
        "address": 0x48E031BE,
        "size": 1,
        "min": 0,
        "max": 17,
    },  # EmmProc.next (SAEMM_state_constraints)
    {
        "address": 0x48E031C0,
        "size": 1,
        "min": 0,
        "max": 6,
    },  # EmmAs.curr (SAEMM_state_constraints)
    {
        "address": 0x48E031C1,
        "size": 1,
        "min": 0,
        "max": 6,
    },  # EmmAs.next (SAEMM_state_constraints)
]

symbol_mappings = [
    {
        "name": "skip",
        "address": [
            # SAEL3
            0x429FD4F8,  # SAEL3_MSG_LOG
            0x429DE8BE,  # SAECOMM_separator
            0x429FD730,  # SAECOMM_section_header
            0x429BEC38,  # SAECOMM_hex_dump
            0x429DD958,  # SAECOMM_hex_dump
            0x429C0B20,  # SAECOMM_hex_dump
            0x424E3244,  # modem_uart_printf
            0x438CB934,  # OS_Schedule_Task
            0x42627D1C,  # OS_Change_Preemption
            0x42B33B88,  # FlushUplinkBuffer
            0x429BC62A,  # FlushUplinkBuffer
        ],
        "simproc": SimSkipFunction,
    },
    {
        "name": "ret_zero",
        "address": [
            0x4224DC42,  # SAECOMM_GetCurrentStack
            0x426ADA94,  # OS_Obtain_Semaphore
            0x41FD2948,  # OS_Release_Semaphore
            0x430F96D8,  # SAEMM_Radio_Decode
        ],
        "simproc": SimReturnZero,
    },
    {
        "name": "ret_one",
        "address": [
            0x42880FB8,  # disableIRQinterrupts
            0x42AF5478,  # SAEMM_SendEmmRadioMessage
            0x42A3C9C8,  # SAEMM_decode_error_caller
            0x42AC3146,  # SAEMM_length_empty_codec
        ],
        "simproc": SimReturnOne,
    },
    {"name": "memequal", "address": 0x424EAD5E, "simproc": SimMemequal},
    {
        "name": "memcpy",
        "address": [
            0x42A7F130,  # memcpy_byte
            0x42880878,  # memcpy_unrolled
            0x4287FF74,  # memcpy_aligned
        ],
        "simproc": SimMemcpy,
    },
    {
        "name": "memcmp",
        "address": 0x4287EA28,
        "simproc": SimMemcmp,
    },
    {
        "name": "pal_MsgRtkSend",
        "address": 0x429294A2,
        "simproc": SimSendMsg,
    },
    {
        "name": "Fatal_error",
        "address": 0x4287FE40,
        "simproc": SimError,
    },
    {
        "name": "memset",
        "address": 0x4287CBCC,
        "simproc": SimMemsetBSV,
    },
    {
        "name": "memzero",
        "address": 0x4287EAF0,
        "simproc": SimMemzero,
    },
]
