#include "periph/flashpage.h"
#include "assert.h"

#include "xtimer.h"
#define ENABLE_DEBUG    (1)
#include "debug.h"

#include "ctap_mem.h"

static void ctap_flash_write_raw(int page, const void *data, size_t len);
static int ctap_flash_verify(int page, const void *data, size_t len);

int ctap_flash_write_and_verify(int page, const void *data, size_t len)
{
    ctap_flash_write_raw(page, data, len);
    if (ctap_flash_verify(page, data, len) != FLASHPAGE_OK) {
        ctap_flash_write(page, data, len);
        return ctap_flash_verify(page, data, len);
    }

    return FLASHPAGE_OK;
}

static void ctap_flash_write_raw(int page, const void *data, size_t len)
{
    uint32_t *page_addr = (uint32_t *)flashpage_addr(page);
    if (data != NULL) {
        flashpage_write_raw(page_addr, data, len);
    }
}

static int ctap_flash_verify(int page, const void *data, size_t len)
{
    assert(page < (int)FLASHPAGE_NUMOF);

    if (memcmp(flashpage_addr(page), data, len) == 0) {
        return FLASHPAGE_OK;
    }
    else {
        return FLASHPAGE_NOMATCH;
    }
}

void ctap_flash_write(int page, const void *data, size_t len)
{
    assert(page < (int)FLASHPAGE_NUMOF);

    uint32_t *page_addr = (uint32_t *)flashpage_addr(page);

    uint32_t start, end;

    start = xtimer_now_usec();
    /* erase given page */
    NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Een;
    NRF_NVMC->ERASEPAGE = (uint32_t)page_addr;
    while (NRF_NVMC->READY == 0) {}
    end = xtimer_now_usec();
    DEBUG("Erase2 took: %lu \n", end - start);

    start = xtimer_now_usec();

    /* write data to page */
    if (data != NULL) {
        flashpage_write_raw(page_addr, data, len);
    }

    end = xtimer_now_usec();
    DEBUG("Write2 raw took: %lu \n", end - start);

}