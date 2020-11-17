#include "ctap_utils.h"

void print_hex(uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        DEBUG("%02x", data[i]);
    }

    DEBUG("\n");
}

uint32_t timestamp(void)
{
    static xtimer_ticks32_t t1 = {0};
    xtimer_ticks32_t t2 = xtimer_now();
    xtimer_ticks32_t delta = xtimer_diff(t2, t1);

    t1 = t2;

    return xtimer_usec_from_ticks(delta);
}
