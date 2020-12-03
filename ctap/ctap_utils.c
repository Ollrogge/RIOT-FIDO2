#ifdef CONFIG_CTAP_NATIVE
#include <sys/time.h>
#endif

#include "xtimer.h"

#include "ctap_utils.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

void print_hex(uint8_t* data, size_t size)
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