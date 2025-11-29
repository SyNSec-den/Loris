import logging
import time

import firmwire.vendor.shannon.pattern_handlers as handlers

log = logging.getLogger(__name__)

PATTERNS = {
    "main_mmu_table": {
        "pattern": "01000000 00000000 00000000 0c940100",
        "required": True,
    },
    "boot_key_check": {
        "pattern": [
            "0880 1af091f9 e2a0 29f287f0 06f03efd 05f0d4f8 3aac 8021 2046 c1f3b4dd 1aa9 2046 1022 62f21ed1",  # G991BXXSCGXF5
            "0880 19f0a5fe e2a0 25f2f5f3 06f026fd 05f0bcf8 3aac 8021 2046 b8f3dddb 1aa9 2046 1022 56f2f4d3",  # G991BXXU5CVF3
        ],
        "offset_end": 0x0,
        "soc_match": ["S5123AP"],
        "required": True,
    },
    "set_task_affinity": {
        # Search for == Task(%d) ==
        "pattern": [
            "2de9f047 86b0 4bf6882a 0446 9846 9146 0e46 0021 0122 0827 c4f2b62a 04f10803 2546 daf80000 0590 3c20 07c3 c4e90517 e161 43f64c51 2820 3c22 c4f27f01 0023 45f8041f",  # G991BXXSCGXF5
            "2de9f043 85b0 0546 9846 9146 0e46 3c20 0021 0122 0827 05f10803 2c46 07c3 c5e90517 e961 ???????? 2820 3c22 c4f2???? 0023 44f8041f",  # oriole
        ],
        "required": True,
    },
    "log_printf": {
        "pattern": [
            "83b0 2de9f0?? ??b0 0df14c0c 0024",  # oriole-sq3a.220705.004
            "83b0 2de9f0?? ??b0 4af29018 0df14c0c 0024",  # G981BXXSKHXEA
            "83b0 2de9f0?? ??b0 4bf68828 0df14c0c 0024",  # G991BXXSCGXF5
            "83b0 2de9f04f 8ab0 45f2ec68 0df14c0c 0024",  # G991BXXU5CVF3
        ],
        "required": True,
    },
    "OS_fatal_error": {
        "pattern": [
            "f0b5 81b0 0446 fff7ecea 0546 fff7eaea 49f28036 c4f23046 7179 8842",  # G981BXXSKHXEA
            "f0b5 81b0 0446 00f0d8e8 0546 00f0d4e8 4bf60056 c4f21256 7179 8842",  # G991BXXSCGXF5
            "f0b5 81b0 0446 00f0dae8 0546 00f0d6e8 41f24066 c4f21056 7179 8842",  # G991BXXU5CVF3
            "f0b5 81b0 0446 fff7???? 0546 fff7???? ???????? c4f6???? 7179 8842",  # oriole
        ],
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
    "pal_MemAlloc": {
        "pattern": [
            "2de9f04f 85b0 9a46 9146 0c46 8046 29b1 14f00305 18bf c5f10405 11e0",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "2de9f04f 85b0 0c46 9a46 9146 8046 2cb1 14f00305 18bf c5f10405 11e0",  # G981BXXSKHXEA
            "2de9f04f 85b0 4bf68825 8046 0c46 9a46 9146 c4f2b625 002c 2868 0490 05d0 14f00307 18bf c7f10407 11e0",  # G991BXXSCGXF5
            "2de9f04f 85b0 45f2ec65 8046 0c46 9a46 9146 c4f2b525 002c 2868 0490 05d0 14f00307 18bf c7f10407 11e0",  # G991BXXU5CVF3
        ],
    },
    "pal_MemFree": {
        "pattern": [
            "2de9f04f 87b0 1546 0491 0646 43f2d6c7 8346 3df246c6 43f2c059 c4f20d59 99f80510 8842",  # G981BXXSKHXEA
            "2de9f04f 89b0 4bf6882a cde90421 0746 c4f2b62a daf80000 0890 6af2f0c5 0646 63f2f0c0 4ef6800b c4f2cb5b 9bf80510 8842",  # G991BXXSCGXF5
            "2de9f04f 89b0 45f2ec6a cde90421 0746 c4f2b52a daf80000 0890 5ff268c7 0646 58f2eec1 4ff6005b c4f2c85b 9bf80510 8842",  # G991BXXU5CVF3
            "2de9f04f 87b0 cde90312 8146 ???????? 8246 ???????? ???????? c4f6???? 6979 8842",  # oriole
        ],
    },
    "pal_Sleep": {
        "lookup": handlers.find_pal_sleep,
    },
    "pal_MsgReceiveMbx": {
        "pattern": [
            "10b5 82b0 8c46 0021 1446 002a ccf80010 00d0 2170",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "10b5 82b0 8c46 0021 1446 002c ccf80010 00d0 2170",  # G981BXXSKHXEA
            "70b5 82b0 4bf68826 1446 0a46 c4f2b626 3168 0191 0021 002c 1160 00d0 2170",  # G991BXXSCGXF5
            "70b5 82b0 45f2ec66 1446 0a46 c4f2b526 3168 0191 0021 002c 1160 00d0 2170",  # G991BXXU5CVF3
            "f0b5 81b0 0e46 0021 1d46 1446 002a 3160 00d0 2170",  # oriole-bp2a.250605.031.a5
        ],
        "soc_match": ["S5123", "S5123AP"],
        "required": True,
    },
    "pal_MsgSendTo": {
        "pattern": [
            "2de9f041 1546 0c46 0646 b0f57a7f ?+ 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "f0b5 81b0 0646 1546 0c46 b6f57a7f ?+ 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # G981BXXSKHXEA
            "2de9f043 81b0 0646 9046 8946 b6f57a7f 13db 44f67070 44f61d61 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # G991BXXSCGXF5
            "2de9f047 82b0 0646 9146 8a46 b6f57a7f 15db 4ef6e420 42f26521 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # G991BXXU5CVF3
        ]
    },
    "pal_SmSetEvent": {
        "pattern": [
            "10b5 0068 80b1 57f6c6d1 0446 4ff6ff70 0442 0ad0 45f6b801 20b2",  # G981BXXSKHXEA
            "10b5 0068 80b1 bff7f9d2 0446 4ff6ff70 0442 0ad0 44f67a51 20b2",  # G991BXXSCGXF5
            "10b5 0068 80b1 c5f715d1 0446 4ff6ff70 0442 0ad0 42f2c211 20b2",  # G991BXXU5CVF3
            "10b5 0068 80b1 ???????? 0446 4ff6ff70 0442 0ad0 ???????? 20b2",  # oriole
        ],
    },
    "SYM_LTERRC_INT_MOB_CMD_HO_FROM_IRAT_MSG_ID": {
        "lookup": lambda data, offset: 0xc3a5,
    },
    "SYM_EVENT_GROUP_LIST": {
        "lookup": handlers.find_event_group_list,
    },
    "SYM_QUEUE_LIST": {"lookup": handlers.find_queue_table},
    "SYM_CUR_TASK_PTR": {"lookup": handlers.find_current_task_ptr_a},
    "SYM_TASK_LIST": {
        "lookup": handlers.find_task_table,
        "post_lookup": handlers.fixup_set_task_layout,
    },
    "DSP_SYNC_WORD_0": {
        "pattern": "80b5 82b0 0368 ???????? 4ff48f70 ???????? ???????? cde90010 ??a0 c121 ???????? 02b0 80bd",
        "offset": 28,
        "post_lookup": handlers.s5123_get_dsp_sync0,
        "required": False,
        "soc_match": ["S5123"],
    },
    "DSP_SYNC_WORD_1": {
        "pattern": "80b5 82b0 0368 ???????? 4ff48f70 ???????? ???????? cde90010 ??a0 c121 ???????? 02b0 80bd",
        "offset": 14,
        "post_lookup": handlers.s5123_get_dsp_sync1,
        "required": False,
        "soc_match": ["S5123"],
    },
    "rf_hwid": {
        "lookup": handlers.find_rf_hwid,
        "soc_match": ["S5123"],
    },
    "board_rf_config": {
        "lookup": handlers.find_board_rf_config,
        "soc_match": ["S5123"],
    },
    "trng_init": {
        "lookup": handlers.find_trng_init,
        "soc_match": ["S5123"],
    }
}
