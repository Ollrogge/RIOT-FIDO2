#ifndef CTAP_PARSE_H
#define CTAP_PARSE_H

#include "cbor.h"
#include "ctap.h"

uint8_t cbor_helper_get_info(CborEncoder* encoder);
uint8_t cbor_helper_parse_make_credential_req(ctap_make_credential_req_t *req, size_t size,
                                              uint8_t* req_raw);
uint8_t cbor_helper_parse_get_assertion_req(ctap_get_assertion_req_t *req, size_t size,
                                              uint8_t *req_raw);
uint8_t cbor_helper_encode_attestation_object(CborEncoder *encoder, ctap_auth_data_t *auth_data,
                                              uint8_t *client_data_hash, ctap_resident_key_t *rk);
uint8_t cbor_helper_encode_assertion_object(CborEncoder *encoder, ctap_auth_data_header_t *auth_data,
                                            uint8_t *client_data_hash, ctap_resident_key_t *rk);
uint8_t parse_cred_desc(CborValue *arr, ctap_cred_desc_t *cred);
#endif