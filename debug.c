#include "debug.h"


extern int debug_level;
extern time_t epoch;

void debug(int level, const char *fmt, ...) {
    if (debug_level < level) return;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void debugTime(int level) {
    if (debug_level < level) return;
    unsigned int ms = get_ms();
    char timestamp[16];
    sprintf(timestamp, "%04ds%03dms", ms / 1000, ms % 1000);
    debug(level, "%s ", timestamp);
}

void debugQname(int level, char *qname) {
    if (debug_level < level) return;
    // assuming that there is only one question
    int nbytes;
    while (1) {
        nbytes = (int)*qname;
        qname++;
        while (nbytes--) {
            printf("%c", *qname);
            qname++;
        }
        if (*qname != '\0')
            printf(".");
        else
            break;
    }
}

void debugIp(int level, uint32_t rdata) {
    if (debug_level < level) return;
    if(rdata == 0) {
        debug(level, "no such domain");
        return;
    }
    struct in_addr a;
    a.s_addr = rdata;
    debug(level, "%s", (char *)inet_ntoa(a));
}

unsigned int get_ms() {
    struct timeval tm;
    gettimeofday(&tm, NULL);
    return (unsigned int)((tm.tv_sec - epoch) * 1000 + tm.tv_usec / 1000);
}
