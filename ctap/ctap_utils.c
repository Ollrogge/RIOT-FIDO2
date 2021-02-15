#ifdef CONFIG_CTAP_NATIVE
#include <sys/time.h>
#endif
#include <string.h>

#include "xtimer.h"

#include "ctap_utils.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

void print_hex(const uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        DEBUG("%02x", data[i]);
    }

    DEBUG("\n");
}

int timestamp(void)
{
#ifndef CONFIG_CTAP_NATIVE
    static xtimer_ticks64_t t1 = {0};
    xtimer_ticks64_t t2 = xtimer_now64();
    xtimer_ticks64_t delta = xtimer_diff64(t2, t1);

    t1 = t2;

    return (uint32_t)xtimer_usec_from_ticks64(delta);
#else
    static struct timeval t1 = {0};
    struct timeval t2;

    gettimeofday(&t2, NULL);

    uint64_t delta = (t2.tv_sec*(uint64_t)1000000 + t2.tv_usec) -
                     (t1.tv_sec*(uint64_t)1000000 + t1.tv_usec);

    t1 = t2;

    return (uint32_t)delta;
#endif
}

bool hexstr_to_array(const char* str, uint8_t* arr, size_t len)
{
    if (str == NULL) {
        return false;
    }

    size_t s_length = strlen(str);

    if ((s_length % 2) != 0) {
        return false;
    }

    if (len < s_length / 2) {
        return false;
    }

    memset(arr, 0, len);

    size_t index = 0;
    while (index < s_length) {
        char c = str[index];
        int value = 0;
        if(c >= '0' && c <= '9') {
            value = (c - '0');
        }
        else if (c >= 'A' && c <= 'F') {
            value = (10 + (c - 'A'));
        }
        else if (c >= 'a' && c <= 'f') {
            value = (10 + (c - 'a'));
        }
        else {
            return false;
        }

        arr[(index / 2)] += value << (((index + 1) % 2) * 4);
        index++;
    }

    return true;
}