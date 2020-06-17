
#define USB_H_USER_IS_RIOT_INTERNAL

#define ENABLE_DEBUG    (1)
#include "debug.h"

#include <string.h>

#include "ctap.h"

#include "cbor.h"

static uint8_t get_info(CborEncoder* encoder);

size_t ctap_handle_request(uint8_t* req, ctap_resp_t* resp)
{
    DEBUG("ctap handle request \n");

    CborEncoder encoder;
    memset(&encoder, 0, sizeof(CborEncoder));

    uint8_t cmd = *req;
    uint8_t* buf = resp->data;

    cbor_encoder_init(&encoder, buf, CTAP_MAX_MSG_SIZE, 0);

    switch (cmd)
    {
        case CTAP_GET_INFO:
            DEBUG("CTAP GET INFO \n");
            resp->status = get_info(&encoder);
            return cbor_encoder_get_buffer_size(&encoder, buf);
        default:
            break;
    }

    return -1;
}



/* CTAP specification (version 20190130) section 5.4 */

// TODO: THESE SETTINGS MIGHT DIFFER FOR EACH IOT DEVICE. WHAT TO DO ABOUT THIS ?
static uint8_t get_info(CborEncoder* encoder)
{
    int ret;

    uint8_t aaguid[] = {DEVICE_AAGUID};
    /* A map of pairs of data items. Maps are also called tables,
    dictionaries, hashes, or objects (in JSON). */
    CborEncoder map;
    CborEncoder map2;
    CborEncoder array;

    /**
     * All functions operating on a CborValue return a CborError condition,
     * with CborNoError standing for the normal situation in which no parsing error occurred.
     * All functions may return parsing errors in case the stream cannot be decoded properly,
     * be it due to corrupted data or due to reaching the end of the input buffer.
    */

    ret = cbor_encoder_create_map(encoder, &map, 4);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    /**
     *  Supported versions are: "FIDO_2_0" for CTAP2 / FIDO2 / Web Authentication authenticators
     *  and "U2F_V2" for CTAP1/U2F authenticators.
     */

    /* versions */
    ret = cbor_encode_uint(&map, CTAP_GET_INFO_RESP_VERSIONS);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encoder_create_array(&map, &array, 1);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encode_text_stringz(&array, CTAP_VERSION_STRING_FIDO);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encoder_close_container(&map, &array);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;


    /* extensions */
    /*
    ret = cbor_encode_uint(&map, CTAP_GET_INFO_RESP_EXTENSIONS);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encoder_create_array(&map, &array, 0);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encoder_close_container(&map, &array);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    */


    /* aaguid */
    ret = cbor_encode_uint(&map, CTAP_GET_INFO_RESP_AAGUID);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encode_byte_string(&map, aaguid, 16);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;


    /* order of the items is important. needs to be canonical CBOR */
    /* https://tools.ietf.org/html/rfc7049#section-3.9 (The keys in every map must be sorted lowest value to highest) */
    /* options */
    ret = cbor_encode_uint(&map, CTAP_GET_INFO_RESP_OPTIONS);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encoder_create_map(&map, &map2, 3);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encode_text_string(&map2, CTAP_GET_INFO_RESP_OPTIONS_ID_RK, 2);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encode_boolean(&map2, 1); /* capable of storing keys on the device */
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    /* clientPin: if absent, it indicates that the device is not capable of accepting a PIN from the client */
    ret = cbor_encode_text_string(&map2, CTAP_GET_INFO_RESP_OPTIONS_ID_UP, 2);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encode_boolean(&map2, 0); /* not capable of testing user presence */
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encode_text_string(&map2, CTAP_GET_INFO_RESP_OPTIONS_ID_PLAT, 4);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encode_boolean(&map2, 0); /* not attached to platform */
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    /* user verification: If absent, it indicates that the device is not capable of user verification within itself.*/
    ret = cbor_encoder_close_container(&map, &map2);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;


    /* maxMsgSize */
    ret = cbor_encode_uint(&map, CTAP_GET_INFO_RESP_MAX_MSG_SIZE);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encode_uint(&map, CTAP_MAX_MSG_SIZE);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;


    /* pinProtocols */
    /*
    ret = cbor_encode_uint(&map, CTAP_GET_INFO_RESP_PIN_PROTOCOLS);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encoder_create_array(&map, &array, 0);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    ret = cbor_encoder_close_container(&map, &array);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    */


    ret = cbor_encoder_close_container(encoder, &map);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;


    return CTAP2_OK;
}