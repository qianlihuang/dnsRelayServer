#pragma once
#include "defs.h"


#define MAX_DOMAIN_LENGTH 100
#define MAX_IP_LENGTH 16
#define MAX_ENTRIES 1000
#define MAX_LINE_LENGTH 256






struct DNSRecord {
    uint32_t ip;
    char domain[MAX_DOMAIN_LENGTH];
};

struct DNSTable {
    struct DNSRecord records[MAX_ENTRIES];
    int count;
};

void parseTable(const char* fpath);
int find_table(struct QUESTION*, struct RR*);
void debug_table(int level);
