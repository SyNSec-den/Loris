// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#ifndef _AFL_H
#define _AFL_H

#define AFL_MAX_INPUT 4 * 1024
#define LORIS_MAX_INPUT 10 * 1024

// let the linker decide which fuzzer we're using
extern void fuzz_single();
extern int fuzz_single_setup();

char * getWork(unsigned int *sizep);
unsigned char *getPreVariables(unsigned int *num);
unsigned char *getVariables(unsigned int *num);
unsigned int sendVariables(void);
int startWork(unsigned int start, unsigned int end);
int doneWork(int val);
int startForkserver(int ticks);

#endif // _AFL_H
