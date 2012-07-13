/*
 * l2filter dump.c
 * author: lo <lodevil@live.cn>
 * 
 */

#include "dump.h"

static const int printable[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

inline void hex(unsigned char c, char *cur) {
    static const char chs[] = "0123456789ABCDEF";

    int hi = c>>4;
    int low = c&0x0F;
    cur[0] = '\\';
    cur[1] = 'x';
    cur[2] = chs[hi];
    cur[3] = chs[low];
}

const char* dump(void* bytes, int size) {
    static char buf[51200];
    if (size > 10240) {
        return "<err: too long>";
    } else {
        int i = 0, buf_i = 0;
        for (;i < size; ++i) {
            unsigned char c = ((unsigned char*)bytes)[i];
            if (printable[c]) {
                buf[buf_i++] = c;
            } else if (c == '\\') {
                buf[buf_i++] = '\\';
                buf[buf_i++] = '\\';
            } else {
                hex(c, buf + buf_i);
                buf_i += 4;
            }
        }
        buf[buf_i] = '\x00';
        return buf;
    }
}