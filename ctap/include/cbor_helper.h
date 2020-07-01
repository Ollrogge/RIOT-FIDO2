#ifndef CTAP_PARSE_H
#define CTAP_PARSE_H

#include "cbor.h"
#include "ctap.h"

uint8_t cbor_helper_get_info(CborEncoder* encoder);
uint8_t cbor_helper_parse_make_credential_req(ctap_make_credential_req_t *req, size_t size, uint8_t* req_raw);

#endif