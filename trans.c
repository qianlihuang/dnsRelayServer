#include "trans.h"

struct requset_info requests[MAX_REQUEST];

// save request at the next useable slot
// return transfered id
uint16_t saveRequest(struct sockaddr_in* src, uint16_t ori_id) {
    uint16_t trans_id;//用一个类似线性探测的哈希表来存储数据
    for (trans_id = ori_id; requests[trans_id].used;
         trans_id++, trans_id %= MAX_REQUEST) {
        if (time(NULL) - requests[trans_id].begin_time > REQ_OUT_TIME)
            requests[trans_id].used = 0;
        if (!requests[trans_id].used) break;
        if (trans_id == ori_id - 1) {
            printf("id used up\n");
            exit(1);
        }
    }

    requests[trans_id].used = 1;
    requests[trans_id].begin_time = time(NULL);
    requests[trans_id].ip = ntohl(src->sin_addr.s_addr);
    requests[trans_id].port = ntohs(src->sin_port);
    requests[trans_id].origin_id = ori_id;

    return trans_id;
}


uint16_t acquireRequest(struct sockaddr_in* dst, uint16_t trans_id) {
    if (!requests[trans_id].used) {  //如果没有使用过，那么就返回0
        dst->sin_addr.s_addr = 0;
        return 0;
    }

    memset(dst, 0, sizeof(dst));
    dst->sin_family = AF_INET;
    dst->sin_addr.s_addr = htonl(requests[trans_id].ip);
    dst->sin_port = htons(requests[trans_id].port);
    requests[trans_id].used = 0;//把标志位设成0，表示还没用过
    return requests[trans_id].origin_id;
}
