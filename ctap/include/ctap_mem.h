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

#include "ctap.h"

#ifdef __cplusplus
extern "C" {
#endif


int ctap_flash_write_and_verify(int page, int offset, const void *data, size_t len);


#ifdef __cplusplus
}
#endif
#endif