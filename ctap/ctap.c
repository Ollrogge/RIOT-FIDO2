
#define ENABLE_DEBUG    (1)
#include "debug.h"

#include <string.h>

#include "ctap.h"

#include "cbor.h"

#include "cbor_helper.h"

static uint8_t make_credential(CborEncoder* encoder, size_t size, uint8_t* req_raw);

size_t ctap_handle_request(uint8_t* req, size_t size, ctap_resp_t* resp)
{
    DEBUG("ctap handle request %u \n ", size);

    CborEncoder encoder;
    memset(&encoder, 0, sizeof(CborEncoder));

    uint8_t cmd = *req;
    uint8_t* buf = resp->data;

    cbor_encoder_init(&encoder, buf, size, 0);

    switch (cmd)
    {
        case CTAP_GET_INFO:
            DEBUG("CTAP GET INFO \n");
            resp->status = cbor_helper_get_info(&encoder);
            return cbor_encoder_get_buffer_size(&encoder, buf);
        case CTAP_MAKE_CREDENTIAL:
            DEBUG("CTAP MAKE CREDENTIAL \n");
            resp->status = make_credential(&encoder, size, req);
        default:
            break;
    }

    return -1;
}

/* CTAP specification (version 20190130) section 5.1 */
static uint8_t make_credential(CborEncoder* encoder, size_t size, uint8_t* req_raw)
{
    (void)encoder;
    int ret;
    ctap_make_credential_req_t req;

    memset(&req, 0, sizeof(req));

    ret = cbor_helper_parse_make_credential_req(&req, size, req_raw);

    DEBUG("ret val: %d \n ", ret);
    (void)ret;

    return 0;
}
