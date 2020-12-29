/*
 * Copyright (C) 2020 Nils Ollrogge
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    CTAP2 implementation
 * @ingroup     FIDO2
 * @brief       Crypto helper implementation
 *
 * @{
 *
 * @file
 * @brief       CTAP crypto helper interface
 *
 * @author      Nils Ollrogge <nils-ollrogge@outlook.de>
 */


#ifndef CTAP_MEM_H
#define CTAP_MEM_H

#include <stdint.h>

#ifndef CONFIG_CTAP_NATIVE
#include "periph/flashpage.h"
#else
#define FLASHPAGE_SIZE 4096
#define FLASHPAGE_NUMOF 256
#define FLASHPAGE_OK 0
#endif

#include "ctap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Write to flash memory and verify the given page against the given data
 *
 * @param[in] page       page to write to
 * @param[in] offset     offset into the page
 * @param[in] data     data to write and compare against
 *
 * @return CTAP status code
 */
int ctap_mem_write_and_verify(int page, int offset, const void *data, size_t len);

/**
 * @brief Read the given page into the given memory location.
 *
 * @param[in] page       page to write to
 * @param[in] data       memory to write the page to
 *
 */
void ctap_mem_read(int page, void *data);


#ifdef __cplusplus
}
#endif
#endif