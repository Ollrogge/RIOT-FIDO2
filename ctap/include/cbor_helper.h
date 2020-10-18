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
 * @brief       CBOR helper implementation
 *
 * @{
 *
 * @file
 * @brief       CTAP CBOR helper interface
 *
 * @author      Nils Ollrogge <nils-ollrogge@outlook.de>
 */

#ifndef CTAP_PARSE_H
#define CTAP_PARSE_H

#include "cbor.h"
#include "ctap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encode CBOR info map
 *
 * @param[in] encoder   CBOR encoder
 * @param[in] info      information about capabilities
 *
 * @return CTAP status code
 */
uint8_t cbor_helper_encode_info(CborEncoder *encoder, ctap_info_t *info);

/**
 * @brief Parse raw MakeCredential request into struct
 *
 * @param[in] req       struct to parse into
 * @param[in] size      size of raw request
 * @param[in] req_raw   raw request
 *
 * @return CTAP status code
 */
uint8_t cbor_helper_parse_make_credential_req(ctap_make_credential_req_t *req, size_t size,
                                              uint8_t* req_raw);

/**
 * @brief Parse raw GetAssertion request into struct
 *
 * @param[in] req       struct to parse into
 * @param[in] size      size of raw request
 * @param[in] req_raw   raw request
 *
 * @return CTAP status code
 */
uint8_t cbor_helper_parse_get_assertion_req(ctap_get_assertion_req_t *req, size_t size,
                                              uint8_t *req_raw);


/**
 * @brief Parse raw ClientPIN request into struct
 *
 * @param[in] req       struct to parse into
 * @param[in] size      size of raw request
 * @param[in] req_raw   raw request
 *
 * @return CTAP status code
 */
uint8_t cbor_helper_parse_client_pin_req(ctap_client_pin_req_t *req, size_t size,
                                         uint8_t *req_raw);

/**
 * @brief Encode attestation object
 *
 * @param[in] encoder           CBOR encoder
 * @param[in] auth_data         authenticator data
 * @param[in] client_data_hash  SHA-256 hash of JSON serialized client data
 * @param[in] rk                resident key
 *
 * @return CTAP status code
 */
uint8_t cbor_helper_encode_attestation_object(CborEncoder *encoder, ctap_auth_data_t *auth_data,
                                              uint8_t *client_data_hash, ctap_resident_key_t *rk);

/**
 * @brief Encode assertion object
 *
 * @param[in] encoder           CBOR encoder
 * @param[in] auth_data         authenticator data header
 * @param[in] client_data_hash  SHA-256 hash of JSON serialized client data
 * @param[in] rk                resident key
 * @param[in] valid_cred_count  amount of valid credentials found in allow list
 *
 * @return CTAP status code
 */
uint8_t cbor_helper_encode_assertion_object(CborEncoder *encoder, ctap_auth_data_header_t *auth_data,
                                            uint8_t *client_data_hash,
                                            ctap_resident_key_t *rk,
                                            uint8_t valid_cred_count);

/**
 * @brief Encode key agreement
 *
 * @param[in] encoder           CBOR encoder
 * @param[in] key               ECDH pub key
 *
 * @return CTAP status code
 */
uint8_t cbor_helper_encode_key_agreement(CborEncoder *encoder, ctap_cose_key_t *key);

/**
 * @brief Encode encrypted pin token
 *
 * @param[in] encoder           CBOR encoder
 * @param[in] token             encrypted pin token
 * @param[in] size              size of encrypted pin token
 *
 * @return CTAP status code
 */
uint8_t cbor_helper_encode_pin_token(CborEncoder *encoder, uint8_t *token, size_t size);

/**
 * @brief Encode PIN tries left
 *
 * @param[in] encoder           CBOR encoder
 * @param[in] token             amount of tries left
 *
 * @return CTAP status code
 */
uint8_t cbor_helper_encode_retries(CborEncoder *encoder, uint8_t tries_left);

/**
 * @brief Parse credential description
 *
 * @param[in] arr   CBOR array
 * @param[in] cred  struct to parse into
 *
 * @return CTAP status code
 */
uint8_t parse_cred_desc(CborValue *arr, ctap_cred_desc_alt_t *cred);

#ifdef __cplusplus
}
#endif
#endif