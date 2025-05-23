## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging
import time

import firmwire.vendor.shannon.pattern_handlers as handlers

log = logging.getLogger(__name__)

PATTERNS = {
    "boot_mpu_table": {
        "pattern": "00000000 00000000 1c000000"
        + "????????" * 6
        + "01000000 01000000 00000004 20",
        "required": True,
    },
    "boot_setup_memory": {
        "pattern": [
            "00008004 200c0000",
            "00000004 ????0100",  # S335
        ],
        "offset": -0x14,
        "align": 4,
        "post_lookup": handlers.parse_memory_table,
        "required": True,
    },
    "boot_key_check": {
        "pattern": [
            "?? 49 00 22 ?? 48 ?? a3 ?? ?? ?? ?? 80 21 68 46 ?? ?? ?? ?? 10 22 20 a9 68 46 ?? ?? ?? ??"
        ],
        "offset_end": 0x0,
        "soc_match": ["S5000AP"],
        "required": True,
    },
    "OS_fatal_error": {
        "pattern": "70 b5 05 46 ???????? ?? 48 ?? 24",
    },
    "pal_MemAlloc": {
        "pattern": "2d e9 f0 4f  0d 00  83 b0  99 46  92 46  80 46",
        "post_lookup": handlers.fixup_bios_symbol,
    },
    "pal_MemAlloc_Wrapper": {
        "pattern": "???????? 10 b5 dc f8 04 c0 bc f1 00 0f ???? bd e8 10 40 60 47 00 22 43 21 25 20",
        "post_lookup": handlers.fixup_bios_symbol,
    },
    "pal_MemFree": {
        "pattern": "???? 10 b5 9b 68 ???? bd e8 10 40 18 47 02 46 43 21 25 20",
        # "post_lookup": handlers.fixup_bios_symbol,
    },
    "pal_MsgSendTo": {
        "pattern": [
            "70 b5 ?+ 04 46 15 46 0e 46 ?? ?? 01 df ?* 88 60 08 46 ?+ ?? 48 ???? ???? 20 46 98 47",  # G973F
            "???????? b0f5fa7f 0446 ??46",  # S337AP
        ]
    },
    "pal_memcpy": {
        "pattern": "03 00 52 e3 ???????? 03 c0 10 e2 08 00 00 0a ???????? 02 00 5c e3",
        "align": 4,
        "post_lookup": handlers.fixup_bios_symbol,
    },
    "pal_memset": {
        "pattern": "04 29 ???????? 10 f0 03 0c ?+ 5f ea c1 7c 24 bf 00 f8 01 2b 00 f8 01 2b 48 bf 00 f8 01 2b 70 47",
        "post_lookup": handlers.fixup_bios_symbol,
        "align": 2,
    },
    "disableIRQinterrupts": {
        "pattern": "00 00 0f e1 80 00 00 e2 80 00 0c f1 1e ff 2f e1",
        "align": 4,
    },
    "enableIRQinterrupts": {
        "pattern": "80 00 10 e3 ?? 00 00 1a 80 00 08 f1 1e ff 2f e1",
        "align": 4,
    },
    "disableIRQinterrupts_trap": {
        "pattern": "00 00 0f e1 80 00 10 e2 ?+ 80 00 0c f1",
        "align": 4,
    },
    "enableIRQinterrupts_trap": {
        "pattern": "80 00 10 e3 ?? 00 00 1a ?+ 80 00 08 f1 1e ff 2f e1",
        "align": 4,
    },
    "pal_Sleep": {
        "pattern": "30 b5 ?+ 98 ?+  ??98 ??22 ??23 11 46 ?? 94",
        # 30 b5 00 25 83 b0 04 46 2a 46 29 46 01 a8 d9 f6 2a e9 01 98 78 b1 29 46 d9 f6 90 e8 01 98 01 22 00 23 11 46 00 94 d9 f6 36 e9 01 98 d8 f6 5e ee 01 98 d9 f6 28 e9 5c f7 09 d8 00 28 02 d0 02 a8 ff f7 42 fe 03 b0 30 bd
        # 30 b5 04 46 85 b0 df 4b 40 f2 02 30 00 22 00 90 11 46 01 a8 0e f1 54 ee dd f8 04 c0 bc f1 00 0f 1c d0 00 25 01 21 03 ab 2a 46 0c f1 38 00 00 95 65 f4 1a f1 01 98 29 46 8b f1 a8 ed 01 98 01 22 00 23 11 46 00 94 5b f1 58 ed 01 98 8b f1 2e ec cd 49 40 f2 13 32 01 98 8b f1 a0 ed f0 f4 a1 f0 00 28 02 d0 02 a8 ff f7 1a fe 05 b0 30 bd
    },
    "log_printf": {
        "pattern": "0fb4 2de9f047 ???? ??98 d0e90060 c0f34815",
        "required": True,
    },
    # log_printf_debug
    "log_printf2": {
        "pattern": "0fb4 2de9f04f ???? ???? ??b0??98 4068",
    },
    "pal_SmSetEvent": {
        "pattern": [
            "10b5 ???? ???????? 04 b2",  # thumb G973F, no NULL check
            "10b5 0068 0028 ???? ???????? 04 b2",  # thumb S337AP, NULL check
        ],
    },
    # OS_Delete_Event_Group is the function (based off string name). It is in the baseband (2017+) otherwise search for string
    # "LTE_RRC_EVENT_GRP_NAME" to find the creation function and explore from there.
    "SYM_EVENT_GROUP_LIST": {
        "pattern": [
            "70 40 2d e9 00 40 a0 e1 ?? ?? 00 eb 00 50 a0 e1 20 00 9f e5 04 10 a0 e1 ?? 05 00 eb ?? 00 94 e5 00 00 50 e3 30 ff 2f 11 05 00 a0 e1 ?? ?? 00 eb 00 00 a0 e3 70 80 bd e8"
        ],
        "offset_end": 0x0,
        "post_lookup": handlers.dereference,
    },
    "SYM_TASK_LIST": {
        "lookup": handlers.find_task_table,
        "post_lookup": handlers.fixup_set_task_layout,
    },
    "SYM_SCHEDULABLE_TASK_LIST": {"lookup": handlers.find_schedulable_task_table},
    "SYM_CUR_TASK_ID": {"lookup": handlers.find_current_task_ptr},
    "SYM_FN_EXCEPTION_SWITCH": {"lookup": handlers.find_exception_switch},
    "SYM_QUEUE_LIST": {"lookup": handlers.find_queue_table},
    "QUIRK_SXXXAP_DVFS_HACK": {
        "pattern": [
            "??f8???? 00f01f01 ??48 d0 f8 ????  c0 f3 ????  ????????  ????  00 ?? ?* ??f1???? ??82 ??eb??11 0988",
            "????  00 ?? ?* ??f1???? ??82 ??eb??11 0988",  # S335AP alternate
        ],
        "offset_end": 0x0,
        "soc_match": ["S335AP", "S355AP", "S360AP"],
        # Thumb alignment
        "align": 2,
        "required": True,
    },
    "SYM_LTERRC_INT_MOB_CMD_HO_FROM_IRAT_MSG_ID": {
        "lookup": handlers.find_lterrc_int_mob_cmd_ho_from_irat_msgid
    },
    "DSP_SYNC_WORD_0": {
        "pattern": [
            "??21??68 4ff4??72 884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ???????? ???????? ???????? ??b0bde8 f0 ??",
        ],
        "post_lookup": handlers.get_dsp_sync0,
        "required": False,
    },
    "DSP_SYNC_WORD_1": {
        "pattern": [
            "4ff4??72 884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ???????? ???????? ???????? ??b0bde8 f0 ??",
        ],
        "offset": 2,
        "offset_end": 3,
        "post_lookup": handlers.get_dsp_sync1,
        "required": False,
    },
    "LteRrm_Task__ReceivedLteRrc": {
        "lookup": handlers.find_LteRrm_Task__ReceivedLteRrc,
        "required": True,
    },
    "LteRrm_Task__Handler": {
        "lookup": handlers.find_debug_handler_func,
        "required": True,
    },
    "LteRrm_Task__Handler2": {
        "lookup": handlers.find_debug_handler_func2,
        "required": True,
    },
    "pal_MsgReceiveMbx": {
        "pattern": [
            "38 b5 14 00 4f f0 00 02 0a 60 18 bf 22 70 00 eb 80 0c 40 4a 02 eb 8c 0c 9c f8 08 c0 bc f1 04 0f 0d d1",
        ],
        "required": True,
    },
    "LTERRM_Init_Event_Group": {
        "lookup": handlers.find_LTERRM_Init_Event_Group,
        "required": True,
    },
    "LTERRM_RetrieveEvent": {
        "lookup": handlers.find_LTERRM_RetrieveEvent,
        "requried": True,
    },
    "SIM_Task__Handler": {
        "lookup": handlers.find_SIM_Task__Handler,
        "required": True,
    },
    "SIM_ContextDef": {
        "lookup": handlers.find_SIM_ContextDef,
        "required": True,
    },
    "SIM_Registration": {
        "lookup": handlers.find_SIM_Registration,
        "required": True,
    },
    "SAEMM_DelieverPduForEstRequest": {
        "lookup": handlers.find_SAEMM_DelieverPduForEstRequest,
        "required": True,
    },
}
