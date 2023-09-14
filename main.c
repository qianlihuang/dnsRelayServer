#include "cache.h"
#include "debug.h"
#include "defs.h"
#include "table.h"
#include "trans.h"

char buffer[DNS_MSG_SIZE_LIMIT];

struct sockaddr_in any_in_adr, dns_addr;
char dns_server[16] = DNS_IP;
char table_file[256] = TABLE_FILE;

extern struct requset_info requests[1 << 16];

int debug_level = 0;
time_t epoch;


char *questionInit(struct QUESTION *, char *);
void argumentResolve(int argc, char *argv[]);
void dnsBegin();



char *questionInit(struct QUESTION *q, char *buf) {
    strcpy(q->qname, buf); //将buf中的内容复制到q->qname中
    char *pos = buf + strlen(buf) + 1;
    uint16_t val;
    memcpy(&val, pos, 2);
    q->qtype = ntohs(val);/*TCP、UDP通信的字节集合要求是Big Edian而计算机的处理可能是Little Edian所以这里直接复制而不需要循环*/
    memcpy(&val, pos + 2, 2);
    q->qclass = ntohs(val);
    return pos + 2 + 2;
}
void argumentResolve(int argc, char *argv[]) {

    
    // Check command line arguments
    if (argc >= 2) {
        if (argv[1][0] == '-' && argv[1][1] == 'd' && argv[1][2] == 'd') {
            debug_level = 2;
        } else if (argv[1][0] == '-' && argv[1][1] == 'd' ) {
            debug_level = 1;
        }
    }

    if (argc >= 3) {
        strcpy(dns_server, argv[2]);
        
    }

    if (argc >= 4) {
        strcpy(table_file, argv[3]);
    }
    debug(1, "DNS server: %s\n", dns_server);
    debug(1, "Table file: %s\n", table_file);
    debug(1, "Debug level: %d\n", debug_level);
}

/*TCP 中，套接字是一对一的关系。如要向 10 个客户端提供服务，那么除了负责监听的套接字外，还需要创建 10 套接字。
但在 UDP 中，不管是服务器端还是客户端都只需要 1 个套接字。之前解释 UDP 原理的时候举了邮寄包裹的例子，负责邮寄包裹的快递公司可以比喻为 UDP 套接字，只要有 1 个快递公司，就可以通过它向任意地址邮寄包裹。同样，只需 1 个 UDP 套接字就可以向任意主机传送数据。
基于UDP的接收和发送函数
UDP 套接字不会保持连接状态，每次传输数据都要添加目标地址信息，这相当于在邮寄包裹前填写收件人地址。
*/
void dnsBegin()
{
    debug(2, "Request table initialized.\n");
    debug(2, "DNS relay initialized.\n");
    debug(2, "----------------------------------------\n");
    debug(1, "Waiting for query...\n");
    while (1) {
        int any_in_adr_len = sizeof(any_in_adr);
        int msg_len = recvfrom(sock, buffer, DNS_MSG_SIZE_LIMIT, 0,
                               (struct sockaddr *)&any_in_adr, &any_in_adr_len);
        if (msg_len <= 0) continue;

        
        struct HEADER *header = (struct HEADER *)buffer;
        struct QUESTION question;
        char *rrpos = questionInit(&question, buffer + sizeof(struct HEADER));

        debugTime(1);
        if(header->qr == 0) debug(2, "Query   ");
        else debug(2, "Response");
        
        debug(2, " from ");
        debug(2, "%-16s", inet_ntoa(any_in_adr.sin_addr));/*TCP、UDP通信的字节集合要求是Big Edian而计算机的处理可能是Little Edian*/

        if (header->qr == 0) {  // question from client                
            // if(question.qtype == TYPE_AAAA){
            //     continue;
            // }
            struct RR rr;
            int found = 0;//found:0,1,10 两位用于记录两个标志位，第一位表示是否在cache中找到，第二位表示是否在table中找到
            if (!(found = found + find_cache(&question, &rr)))
                found = found + find_table(&question, &rr)*2;

            if (found) {
                header->qr = 1;
                if (rr.rdata == 0)
                    header->rcode = 3;// 值为0没有差错,值为3表示名字差错。从权威名字服务器返回，表示在查询中指定域名不存在
                else
                    header->rcode = 0;
                header->ancount = htons(1);
                msg_len += sizeof(struct RR);
                memcpy(rrpos, (char *)&rr, sizeof(struct RR));
                sendto(sock, buffer, msg_len, 0, (struct sockaddr *)&any_in_adr,
                       sizeof(any_in_adr));

                //向cache中添加
                if (found & 2) cache(&question, &rr);// & 1 << 1
            } else {

                // 向DNS服务器发送请求
                int originId = header->id;
                header->id = saveRequest(&any_in_adr, header->id);//每次线性探测哈希找到一个可用的id
                //然后把这个地址作为ID的值，这样就可以通过ID找到对应的地址了
                sendto(sock, buffer, msg_len, 0, (struct sockaddr *)&dns_addr,
                       sizeof(dns_addr));
                
                debug(2, "ID: %04x -> %04x\tType: ", htons(originId), htons(header->id));
               
                if (question.qtype == TYPE_A){
                    debug(2, "A\t\t");
                }    
                else if(question.qtype == TYPE_AAAA){
                    debug(2, "AAAA\t");
                }
                else{
                    debug(2, "%-3d\t", question.qtype);
                }
            }

            if (!found) {
                debugQname(1, question.qname);debug(1, " -> ?");
            } else if (found & 1) {
                if (question.qtype == TYPE_A){
                    debug(2, "Found in cache\t\tType: A\t\t");debugQname(1, question.qname);debug(1, " -> ? <- ");debugIp(1, rr.rdata);
                }    
                else if(question.qtype == TYPE_AAAA){
                    debug(2, "Found in cache\t\tType: AAAA\t");debugQname(1, question.qname);debug(1, " -> ? <- ");debugIp(1, rr.rdata);
                }
                //debug(2, "Found in cache\t\tType: A\t\t");debugQname(1, question.qname);debug(1, " -> ? <- ");debugIp(1, rr.rdata);
            } else if (found & 2) {
                if (question.qtype == TYPE_A){
                    debug(2, "Found in table\t\tType: A\t\t");debugQname(1, question.qname);debug(1, " -> ? <- ");debugIp(1, rr.rdata);
                }    
                else if(question.qtype == TYPE_AAAA){
                    debug(2, "Found in table\t\tType: AAAA\t");debugQname(1, question.qname);debug(1, " -> ? <- ");debugIp(1, rr.rdata);
                }
                //debug(2, "Found in table\t\tType: A\t\t");debugQname(1, question.qname);debug(1, " -> ? <- ");debugIp(1, rr.rdata);
            }
        } else {  // answer from DNS server
            struct sockaddr_in local_adr;
            int serv_id = header->id;
            header->id = acquireRequest(&local_adr, header->id);
            if (local_adr.sin_addr.s_addr == 0) {  // answer is late
                debug(1, "\n");
                continue;
            }
            sendto(sock, buffer, msg_len, 0, (struct sockaddr *)&local_adr,
                   sizeof(local_adr));

            // OPCODE通常值为0（标准查询），其他值为1（反向查询）和2（服务器状态请求）。
            // QDCOUNT must be 1
            if (ntohs(header->opcode) != 0 || ntohs(header->qdcount) != 1) {
                debug(1, "\n");
                continue;
            }
            struct RR *rr = (struct RR *)rrpos;
            if (ntohs(rr->type) == TYPE_A) cache(&question, rr);
            
            debug(2, "ID: %04x <- %04x\t", htons(header->id), htons(serv_id));
            if (header->rcode != 0) {
                debug(2, "Type: Null\t");
                debugQname(1, question.qname);
                debug(1, " <- ");
                debug(1, "No such domain"); // header->rcode == 3
            } else {
                switch (ntohs(rr->type)) {
                    case TYPE_A:
                        debug(1, "Type: A\t\t");
                        break;
                    case TYPE_CNAME:
                        debug(1, "Type: CNAME\t");
                        break;
                    case TYPE_NS:
                        debug(1, "Type: NS\t");
                        break;
                    case TYPE_MX:
                        debug(1, "Type: MX\t");
                        break;
                    case TYPE_PTR:
                        debug(1, "Type: PTR\t");
                        break;
                    case TYPE_AAAA:
                        debug(1, "Type: AAAA\t");
                        break;
                    default:
                        debug(1, "Type: %-3d\t", ntohs(rr->type));
                        break;
                }
                debugQname(1, question.qname);
                debug(1, " <- ");
                if (ntohs(rr->type) == TYPE_A)
                    debugIp(1, rr->rdata);
                else
                    debug(1, "notA");  //the first RR is not A, 这里每个RR长度不一样，所以我们只读了第一个判断是不是A，是A就存入cache
            }
        }
        debug(1, "\n");

    }
    socket_close(sock);
}
int main(int argc, char *argv[]) {
    argumentResolve(argc, argv);
    socketInit();
    parseTable(table_file);
    time(&epoch);
    memset(requests, 0, sizeof(requests));
    dnsBegin();
    return 0;
}