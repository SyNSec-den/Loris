// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#ifndef _SHANNON_H
#define _SHANNON_H

#include <common.h>
#include <modkit.h>

#define TARGET_S5000AP

struct qitem_header {
  union {
    struct {
      uint16_t op1; // mbox1
      uint16_t op2; // mbox2
    };
    uint32_t op;
  };
  uint16_t size; // size of the payload following end of header
  uint16_t msgGroup; // [msgGroup][msgNumber]
} PACKED;

struct qitem_ati {
  struct qitem_header header;
  void* payload;
} PACKED;

struct qitem_mm {
  struct qitem_header header;
  char payload[0]; // payload is inline with the header
} PACKED;

struct qitem_cc {
  struct qitem_header header;
  char payload[0]; // payload is inline with the header
} PACKED;

struct qitem_lte_tcpip {
  struct qitem_header header;
  char *data;
  uint32_t unkown;
  uint32_t data_len;
  uint32_t context_id;
} PACKED;

struct qitem_gmm {
  struct qitem_header header;
  char * pdu;
} PACKED;

struct qitem_sm {
  struct qitem_header header;
  char *pdu; // payload is inline with the header
} PACKED;

struct pal_queue {
  char * name;
  void * taskStruct;
  uint8_t queueType; // compiler should pad out 3 bytes
  uint32_t queueAliasOrCallback;
  uint32_t queueID;
};

#ifdef TARGET_S5000AP
struct pal_event_group {
    struct pal_event_group *next;
    struct pal_event_group *prev;
    struct pal_event_group *unk1;
    uint32_t curr_task_id;
    void *field_0x10;
    uint8_t field_0x14[8];
    void *field_0x1c;
    uint8_t *field14_0x20;
    uint8_t field15_0x24;
    uint8_t field_0x25[7];
    uint32_t field_0x2c;
    char name[8];
    int field25_0x38;
    uint8_t field_0x3c[16];
};

#else
struct pal_event_group {
  struct pal_event_group * next;
  struct pal_event_group * prev;
  unsigned char unk1;
  void * unk2;
  void * unk3;
  char name[8];
  void * unk4;
  void * unk5;
};
#endif

typedef struct {
    uint32_t magic;
    uint32_t unk1;
    uint32_t unk2;
    uint32_t unk_magic;
    char *message;
    uint32_t linenum;
    char *file;
} TraceEntry;

typedef struct {
    TraceEntry *te;
    uint32_t flags;
} LogContext;

int32_t queuename2id(const char * name);
struct pal_event_group *eventname2addr(const char *name);
struct pal_event_group *eventid2addr(int32_t event_id);
void uart_dump_hex(uint8_t * str, unsigned int sz);
void uart_putc(char c);
void uart_puts(char * str);

MODKIT_FUNCTION_SYMBOL(void, pal_MsgSendTo, int qid, void * item, unsigned int itemType)
MODKIT_FUNCTION_SYMBOL(int, pal_MsgReceiveMbx, int qid, void * item, uint8_t * itemType, int blocking)
MODKIT_FUNCTION_SYMBOL(void *, pal_MemAlloc, int type, uint32_t size, const char * szFile, unsigned int line)
MODKIT_FUNCTION_SYMBOL(void, pal_Sleep, int time)
MODKIT_FUNCTION_SYMBOL(void, pal_SmSetEvent, struct pal_event_group ** event, uint32_t code)
MODKIT_FUNCTION_SYMBOL(void, log_printf, LogContext *, ...)
MODKIT_DATA_SYMBOL(struct pal_queue *, SYM_QUEUE_LIST)
MODKIT_DATA_SYMBOL(struct pal_event_group **, SYM_EVENT_GROUP_LIST)

// We need this symbol only for LTE RRC fuzzing. However, Symbol addition seem
// only be working from here.
MODKIT_DATA_SYMBOL(uint16_t, SYM_LTERRC_INT_MOB_CMD_HO_FROM_IRAT_MSG_ID)

#define MODEM_LOG(fmt, ...)           \
do {                                  \
    TraceEntry _te;                   \
    LogContext _ctx;                  \
    _te.message = fmt;                \
    _te.linenum = __LINE__;           \
    _te.file = __FILE__;              \
    _ctx.te = &_te;                   \
    log_printf(&_ctx, ##__VA_ARGS__); \
} while(0)

#define MALLOC(__size) pal_MemAlloc(4, __size, __FILE__, __LINE__);

#endif // _SHANNON_H
