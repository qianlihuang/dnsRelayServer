#pragma once
#include "defs.h"
//

// 双向链表节点结构体
struct Node {
    char qname[NAME_SIZE_LIMIT];
    uint32_t ip;
    time_t expire_time;
    struct Node* prev;
    struct Node* next;
};
struct Node* createNode(char qname[], uint32_t ip, time_t expire_time);
void cache(struct QUESTION*, struct RR*);
int find_cache(struct QUESTION*, struct RR*);
