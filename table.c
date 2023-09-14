#include "table.h"

struct DNSTable *table;
int cmp(const void *a, const void *b) {
    const struct DNSRecord *recordA = (const struct DNSRecord *)a;
    const struct DNSRecord *recordB = (const struct DNSRecord *)b;
    return strcmp(recordA->domain, recordB->domain);
}




void to_qname(char* name) {
    size_t length = strlen(name);
    memmove(name + 1, name, length + 1); // 移动字符串，给空格腾出位置
    *name = ' '; // 在开头添加空格

    char* pos;
    *name = '.';
    while (*name) {
        if (*name == '.') {
            pos = name;
            *pos = 0;
            name++;
        }
        (*pos)++;
        name++;
    }

    //name[length + 1] = 0; // 在字符串末尾加上空字符
}



void parseTable( const char *fpath) {
    table = (struct DNSTable *)malloc(sizeof(struct DNSTable));
    table->count = 0;
    FILE *file = fopen(fpath, "r");
    if (file == NULL) {
        debug(0,"fail to open \"%s\"\n", fpath);
        exit(1);
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        if (table->count >= MAX_ENTRIES) {
            debug(2,"DNS table is full. Skipping remaining entries.\n");
            break;
        }

        char ip_str[MAX_IP_LENGTH];
        char domain_str[MAX_DOMAIN_LENGTH];

        if (sscanf(line, "%s %s", ip_str, domain_str) != 2) {
            debug(2,"Invalid line: %s\n", line);
            continue;
        }

        uint32_t ip = inet_addr(ip_str);
        table->records[table->count].ip = ntohl(ip);

        to_qname(domain_str);
  
        strcpy(table->records[table->count].domain, domain_str);

        table->count++;
        debug(2, "Added entry: %s\n",line );
    }

    fclose(file);

    qsort(table->records, table->count, sizeof(struct DNSRecord), cmp);
}

int find_table( struct QUESTION* q, struct RR* rr) {
    if (q->qtype != TYPE_A && q->qtype != TYPE_AAAA) return 0;
    //if (q->qtype != TYPE_A) return 0;


    int left = 0;
    int right = table->count - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        int cmpResult = strcmp(table->records[mid].domain, q->qname);

        if (cmpResult == 0) {
            rr->type = htons(TYPE_A);
            rr->class = htons(q->qclass);
            rr->ttl = htons(3600);
            rr->name = htons(0xc00c);
            rr->rdata = htonl(table->records[mid].ip);
            rr->rdlength = htons(4);
            return 1;
        } else if (cmpResult < 0) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    return 0;
}
