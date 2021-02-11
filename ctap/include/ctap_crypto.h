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


#ifndef CTAP_CRYPTO_H
#define CTAP_CRYPTO_H

#include <stdint.h>

#include "ctap.h"

#include "relic.h"

#include "rijndael-api-fst.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CTAP_CRYPTO_P256_P_SIZE FP_BYTES

struct ctap_crypto_pub_key {
    uint8_t comp_flag;
    uint8_t x[FP_BYTES];
    uint8_t y[FP_BYTES];
};

typedef struct
{
    struct ctap_crypto_pub_key pub;
    uint8_t priv[FP_BYTES];
} ctap_crypto_key_agreement_key_t;

uint8_t ctap_crypto_init(void);

void ctap_crypto_prng(uint8_t *dst, size_t len);

int ctap_crypto_reset_key_agreement(void);

void ctap_crypto_get_key_agreement(ctap_cose_key_t *key);

uint8_t ctap_crypto_ecdh(uint8_t *out, size_t len, ctap_cose_key_t *cose);

uint8_t ctap_crypto_aes_dec(uint8_t *out, int *out_len, uint8_t *in,
		int in_len, const uint8_t *key, int key_len);

uint8_t ctap_crypto_aes_enc(uint8_t *out, int *out_len, uint8_t *in,
		int in_len, const uint8_t *key, int key_len);

uint8_t ctap_crypto_gen_keypair(ctap_cose_key_t *key, uint8_t *priv_key);

uint8_t ctap_crypto_get_sig(uint8_t *data, size_t data_len, uint8_t *sig,
                            size_t *sig_len, const uint8_t *key, size_t key_len);

uint8_t ctap_crypto_aes_ccm_enc(uint8_t *out, const uint8_t *in,
                                size_t in_len, uint8_t *a, size_t a_len,
                                uint8_t mac_len, uint8_t l, const uint8_t *nonce,
                                const uint8_t *key);

uint8_t ctap_crypto_aes_ccm_dec(uint8_t *out, const uint8_t *in,
                                size_t in_len, uint8_t *a, size_t a_len,
                                uint8_t mac_len, uint8_t l, const uint8_t *nonce,
                                const uint8_t *key);

#ifdef __cplusplus
}
#endif
#endif