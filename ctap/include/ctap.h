#ifndef CTAP_H
#define CTAP_H

#include <stdint.h>

/**
* CTAP specification (version 20190130) section 6:
* By default, authenticators MUST support messages of at least 1024 bytes
*/
#define CTAP_MAX_MSG_SIZE                   0x400

#define CTAP_MAKE_CREDENTIAL                0x01
#define CTAP_GET_ASSERTION                  0x02
#define CTAP_GET_INFO                       0x04
#define CTAP_CLIENT_PIN                     0x06
#define CTAP_RESET                          0x07
#define CTAP_GET_NEXT_ASSERTION             0x08
#define CTAP_VENDOR_FIRST                   0x40
#define CTAP_VENDOR_LAST                    0xBF

#define CTAP_GET_INFO_RESP_VERSIONS         0x01 /* List of supported versions */
#define CTAP_GET_INFO_RESP_EXTENSIONS       0x02 /* List of supported extensions */
#define CTAP_GET_INFO_RESP_AAGUID           0x03 /* The claimed AAGUID */
#define CTAP_GET_INFO_RESP_OPTIONS          0x04 /* List of supported options */
#define CTAP_GET_INFO_RESP_MAX_MSG_SIZE     0x05 /* Maximum message size supported by the authenticator */
#define CTAP_GET_INFO_RESP_PIN_PROTOCOLS    0x06 /* List of supported PIN Protocol versions */

/* All options are in the form key-value pairs with string IDs and boolean values */

#define CTAP_GET_INFO_RESP_OPTIONS_ID_PLAT       "plat"         /* platform device */
#define CTAP_GET_INFO_RESP_OPTIONS_ID_RK         "rk"           /* resident key */
#define CTAP_GET_INFO_RESP_OPTIONS_ID_CLIENT_PIN "clientPin"    /* client pin */
#define CTAP_GET_INFO_RESP_OPTIONS_ID_UP         "up"           /* user presence */
#define CTAP_GET_INFO_RESP_OPTIONS_ID_UV         "uv"           /* user verification */

#define CTAP_VERSION_STRING_FIDO "FIDO_2_0"

#define CTAP2_OK                            0x00
#define CTAP1_ERR_INVALID_COMMAND           0x01
#define CTAP1_ERR_INVALID_PARAMETER         0x02
#define CTAP1_ERR_INVALID_LENGTH            0x03
#define CTAP1_ERR_INVALID_SEQ               0x04
#define CTAP1_ERR_TIMEOUT                   0x05
#define CTAP1_ERR_CHANNEL_BUSY              0x06
#define CTAP1_ERR_LOCK_REQUIRED             0x0A
#define CTAP1_ERR_INVALID_CHANNEL           0x0B
#define CTAP2_ERR_CBOR_PARSING              0x10
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE      0x11
#define CTAP2_ERR_INVALID_CBOR              0x12
#define CTAP2_ERR_INVALID_CBOR_TYPE         0x13
#define CTAP2_ERR_MISSING_PARAMETER         0x14
#define CTAP2_ERR_LIMIT_EXCEEDED            0x15
#define CTAP2_ERR_UNSUPPORTED_EXTENSION     0x16
#define CTAP2_ERR_TOO_MANY_ELEMENTS         0x17
#define CTAP2_ERR_EXTENSION_NOT_SUPPORTED   0x18
#define CTAP2_ERR_CREDENTIAL_EXCLUDED       0x19
#define CTAP2_ERR_CREDENTIAL_NOT_VALID      0x20
#define CTAP2_ERR_PROCESSING                0x21
#define CTAP2_ERR_INVALID_CREDENTIAL        0x22
#define CTAP2_ERR_USER_ACTION_PENDING       0x23
#define CTAP2_ERR_OPERATION_PENDING         0x24
#define CTAP2_ERR_NO_OPERATIONS             0x25
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM     0x26
#define CTAP2_ERR_OPERATION_DENIED          0x27
#define CTAP2_ERR_KEY_STORE_FULL            0x28
#define CTAP2_ERR_NOT_BUSY                  0x29
#define CTAP2_ERR_NO_OPERATION_PENDING      0x2A
#define CTAP2_ERR_UNSUPPORTED_OPTION        0x2B
#define CTAP2_ERR_INVALID_OPTION            0x2C
#define CTAP2_ERR_KEEPALIVE_CANCEL          0x2D
#define CTAP2_ERR_NO_CREDENTIALS            0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT       0x2F
#define CTAP2_ERR_NOT_ALLOWED               0x30
#define CTAP2_ERR_PIN_INVALID               0x31
#define CTAP2_ERR_PIN_BLOCKED               0x32
#define CTAP2_ERR_PIN_AUTH_INVALID          0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED          0x34
#define CTAP2_ERR_PIN_NOT_SET               0x35
#define CTAP2_ERR_PIN_REQUIRED              0x36
#define CTAP2_ERR_PIN_POLICY_VIOLATION      0x37
#define CTAP2_ERR_PIN_TOKEN_EXPIRED         0x38
#define CTAP2_ERR_REQUEST_TOO_LARGE         0x39
#define CTAP2_ERR_ACTION_TIMEOUT            0x3A
#define CTAP1_ERR_OTHER                     0x7F
#define CTAP2_ERR_SPEC_LAST                 0xDF
#define CTAP2_ERR_EXTENSION_FIRST           0xE0
#define CTAP2_ERR_EXTENSION_LAST            0xEF
#define CTAP2_ERR_VENDOR_FIRST              0xF0
#define CTAP2_ERR_VENDOR_LAST               0xFF

/**
 * 128 bit identifier indenticating type of authenticator
 * Todo: how to set this based on being in a generic OS ?
 */
#define DEVICE_AAGUID 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00


typedef struct
{
    uint8_t status;
    uint8_t data[CTAP_MAX_MSG_SIZE];
} ctap_resp_t;

size_t ctap_handle_request(uint8_t* req, ctap_resp_t* resp);

#endif