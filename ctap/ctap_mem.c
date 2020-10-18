#include "periph/flashpage.h"
#include "assert.h"

#include "xtimer.h"
#define ENABLE_DEBUG    (0)
#include "debug.h"

#include "ctap_mem.h"

static void ctap_flash_write_raw(int page, int offset,
                                const void *data, size_t len);
static int ctap_flash_verify(int page, int offset, const void *data, size_t len);
static void ctap_flash_write(int page, const void *data, size_t len);

/*
static void print_hex(uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        DEBUG("%02x", data[i]);
    }

    DEBUG("\n");
}
*/


/**
 * write_raw should fail once for every page => erase page
 * afterwards we should be able to selectively write to page with write_raw,
 * which is way faster than erasing and writing whole pages.
 *
*/
int ctap_flash_write_and_verify(int page, int offset,
                                const void *data, size_t len)
{
    assert(!(len % FLASHPAGE_RAW_BLOCKSIZE));

    ctap_flash_write_raw(page, offset, data, len);

    if (ctap_flash_verify(page, offset, data, len) != FLASHPAGE_OK) {
        ctap_flash_write(page, data, len);
        return ctap_flash_verify(page, offset, data, len);
    }

    return FLASHPAGE_OK;
}

static void ctap_flash_write_raw(int page, int offset,
                                const void *data, size_t len)
{
    uint32_t *addr = (uint32_t *)((uint8_t *)flashpage_addr(page) + offset);
    flashpage_write_raw(addr, data, len);
}

static int ctap_flash_verify(int page, int offset, const void *data, size_t len)
{
    assert(page < (int)FLASHPAGE_NUMOF);

    uint8_t* addr = (uint8_t *)flashpage_addr(page) + offset;

    if (memcmp(addr, data, len) == 0) {
        return FLASHPAGE_OK;
    }
    else {
        DEBUG("Flash does not match \n");
        return FLASHPAGE_NOMATCH;
    }
}

static void ctap_flash_write(int page, const void *data, size_t len)
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