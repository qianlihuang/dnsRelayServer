#include "cache.h"
#include "debug.h"

// 创建新节点
struct Node *createNode(char qname[], uint32_t ip, time_t expire_time)
{
    struct Node *newNode = (struct Node *)malloc(sizeof(struct Node));
    if (newNode == NULL)
    {
        debug(1, "内存分配失败。\n");
        exit(1);
    }

    strcpy(newNode->qname, qname);
    newNode->ip = ip;
    newNode->expire_time = expire_time;
    newNode->prev = NULL;
    newNode->next = NULL;

    return newNode;
}

// 在链表尾部插入节点
void insertNode(struct Node **head, char qname[], uint32_t ip, time_t expire_time)
{
    struct Node *newNode = createNode(qname, ip, expire_time);

    if (*head == NULL)
    {
        *head = newNode;
    }
    else
    {
        struct Node *curr = *head;
        while (curr->next != NULL)
        {
            curr = curr->next;
        }
        curr->next = newNode;
        newNode->prev = curr;
    }
}

// 删除链表的第一个节点
void deleteFirstNode(struct Node **head)
{
    if (*head == NULL)
    {
        return;
    }

    struct Node *firstNode = *head;
    *head = firstNode->next;

    if (*head != NULL)
    {
        (*head)->prev = NULL;
    }

    free(firstNode);
}

// 删除指定节点
void deleteNode(struct Node **head, struct Node *targetNode)
{
    if (*head == NULL || targetNode == NULL)
    {
        return;
    }

    if (targetNode == *head)
    {
        *head = targetNode->next;
    }
    if (targetNode->prev != NULL)
    {
        targetNode->prev->next = targetNode->next;
    }

    if (targetNode->next != NULL)
    {
        targetNode->next->prev = targetNode->prev;
    }

    free(targetNode);
}

// 打印链表节点
void printList(struct Node *head)
{
    struct Node *curr = head;
    while (curr != NULL)
    {
        debug(1, "qname: %s, ip: %u, expire_time: %ld\n", curr->qname, curr->ip, curr->expire_time);
        curr = curr->next;
    }
}

// 释放链表内存
void freeList(struct Node **head)
{
    struct Node *curr = *head;
    struct Node *next;
    while (curr != NULL)
    {
        next = curr->next;
        free(curr);
        curr = next;
    }
    *head = NULL;
}

//
int cache_size;
// struct list_head cache_list;
struct Node *head = NULL;
extern char buffer[DNS_MSG_SIZE_LIMIT];
extern char *rrpos;

void cache(struct QUESTION *q, struct RR *rr)
{

    cache_size++;
    while (cache_size > MAX_CACHE_ENTRY)
    {

        deleteFirstNode(&head);
        cache_size--;
    }
    insertNode(&head, q->qname, ntohl(rr->rdata), ntohl(*(uint32_t *)&rr->ttl) + time(NULL));
}

int find_cache(struct QUESTION *q, struct RR *rr)
{
    if (q->qtype != TYPE_A && q->qtype != TYPE_AAAA)
        return 0;
    struct Node *temp;
begin:
    temp = head;
    // 找到对应的节点
    while (temp != NULL)
    {
        if (temp->expire_time <= time(NULL))
        {
            // debug(2, "\nentry out\n");
            deleteNode(&head, temp);
            cache_size--;
            goto begin;
            continue;
        }
        if (!strcmp(q->qname, temp->qname))
        {
            // found
            rr->type = htons(q->qtype);
            rr->class = htons(q->qclass);
            *(uint32_t *)&rr->ttl = htonl(temp->expire_time - time(NULL));
            rr->name = htons(0xc00c);
            rr->rdata = htonl(temp->ip);
            rr->rdlength = htons(4);
            // 将该节点移动到链表头部
            insertNode(&head, temp->qname, temp->ip, temp->expire_time);
            deleteNode(&head, temp);
            return 1;
        }
        temp = temp->next;
    }
    return 0;
}
