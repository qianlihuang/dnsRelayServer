#pragma once
#include "defs.h"

void debug(int level, const char *fmt, ...);
void debugTime(int level);
void debugQname(int level, char* qname);
void debugIp(int level, uint32_t rdata);
unsigned int get_ms();
