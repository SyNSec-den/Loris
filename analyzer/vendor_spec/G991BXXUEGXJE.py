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
        0x451E0FB8, 0x451E0FCA
    ),  # SAEMM_OngoingProcTypeByProc (SAEMM_state_tables)
    intervaltree.Interval(
        0x451E0FCC, 0x451E105C
    ),  # SAEMM_StateByProc (SAEMM_state_tables)
    intervaltree.Interval(
        0x4552FF9C, 0x4552FFB8
    ),  # SAEMM_StateMainNames (SAEMM_state_tables)
    intervaltree.Interval(
        0x4552FFB8, 0x4552FFE4
    ),  # SAEMM_StateServiceNames (SAEMM_state_tables)
    intervaltree.Interval(
        0x451E0E64, 0x451E0E80
    ),  # gEmmAsStateStr (SAEMM_emm_as_tables)
    intervaltree.Interval(
        0x451E0E80, 0x451E0F91
    ),  # SAEMM_EmmAsMap (SAEMM_emm_as_tables)
]

additional_constraints = [
    {
        "address": 0x463D7705,
        "size": 1,
        "min": 0,
        "max": 17,
    },  # EmmProc.curr (SAEMM_state_constraints)
    {
        "address": 0x463D7706,
        "size": 1,
        "min": 0,
        "max": 17,
    },  # EmmProc.next (SAEMM_state_constraints)
    {
        "address": 0x463D7708,
        "size": 1,
        "min": 0,
        "max": 6,
    },  # EmmAs.curr (SAEMM_state_constraints)
    {
        "address": 0x463D7709,
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
            0x4189DEE4,  # SAEL3_MSG_LOG
            0x41A4DA96,  # --  %s  --
            0x4189E246,  # [][][ %s Start: 0x%x ][][]
            0x41A5AA2C,  # Hex-> %02x %02x %02x %02x %02x %02x %02x
            0x41A5FCA4,  # Hex-> %02x %02x %02x %02x %02x %02x %02x
            0x41A5C780,  # Hex-> %02x %02x %02x %02x %02x %02x %02x
            0x4128452A,  # modem_uart_printf
            0x429F9BF8,  # OS_Schedule_Task
            0x416AB05C,  # OS_Change_Preemption
            0x419877A4,  # FlushUplinkBuffer
            0x41ACA32C,  # FlushUplinkBuffer
        ],
        "simproc": SimSkipFunction,
    },
    {
        "name": "ret_zero",
        "address": [
            0x41341B96,  # SAECOMM_GetCurrentStack
            0x416B4E10,  # OS_Obtain_Semaphore
            0x412B19AC,  # OS_Release_Semaphore
            0x422A675C,  # SAEMM_Radio_Decode
        ],
        "simproc": SimReturnZero,
    },
    {
        "name": "ret_one",
        "address": [
            0x41ACEBD0,  # disableIRQinterrupts
            0x4194AC3C,  # SAEMM_SendEmmRadioMessage
            0x418C91D0,  # Warn>Decode Error: 0x%x
            0x41917CB2,  # "%s (Length:%d)" & "%s (Empty)"
        ],
        "simproc": SimReturnOne,
    },
    {"name": "memequal", "address": 0x41517722, "simproc": SimMemequal},
    {
        "name": "memcpy",
        "address": [
            0x41A4E192,
            0x41ABCB64,
            0x41ACC284,
        ],
        "simproc": SimMemcpy,
    },
    {
        "name": "memcmp",
        "address": 0x41ABE398,
        "simproc": SimMemcmp,
    },
    {
        "name": "pal_MsgRtkSend",
        "address": 0x41B08154,
        "simproc": SimSendMsg,
    },
    {
        "name": "Fatal_error",
        "address": 0x412BD5F0,
        "simproc": SimError,
    },
    {
        "name": "memset",
        "address": 0x41AB81A8,
        "simproc": SimMemsetBSV,
    },
    {
        "name": "memzero",
        "address": 0x41ACE9E0,
        "simproc": SimMemzero,
    },
]
