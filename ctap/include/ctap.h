#ifndef CTAP_H
#define CTAP_H

#include <stdint.h>

#include "cbor.h"

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

#define CTAP_AUTH_DATA_FLAG_UP     (1 << 0) /* user present */
#define CTAP_AUTH_DATA_FLAG_UV     (1 << 2) /* user verified */
#define CTAP_AUTH_DATA_FLAG_AT     (1 << 6) /* attested credential data included */
#define CTAP_AUTH_DATA_FLAG_ED     (1 << 7) /* extension data included */

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


/* todo: think about these sizes */
#define CTAP_RP_MAX_NAME_SIZE 32
#define CTAP_USER_MAX_NAME_SIZE 32
#define CTAP_USER_ID_MAX_SIZE 64
#define CTAP_DOMAIN_NAME_MAX_SIZE 253

/* ctap make credential cbor map key values */
#define CTAP_MC_REQ_CLIENT_DATA_HASH    0x01
#define CTAP_MC_REQ_RP                  0x02
#define CTAP_MC_REQ_USER                0x03
#define CTAP_MC_REQ_PUB_KEY_CRED_PARAMS 0x04
#define CTAP_MC_REQ_EXCLUDE_LIST        0x05
#define CTAP_MC_REQ_EXTENSIONS          0x06
#define CTAP_MC_REQ_OPTIONS             0x07
#define CTAP_MC_REQ_PIN_AUTH            0x08
#define CTAP_MC_REQ_PIN_PROTOCOL        0x09

#define CTAP_MC_RESP_FMT                0x01
#define CTAP_MC_RESP_AUTH_DATA          0x02
#define CTAP_MC_RESP_ATT_STMT           0x03

#define CTAP_GA_REQ_RP_ID               0x01
#define CTAP_GA_REQ_CLIENT_DATA_HASH    0x02
#define CTAP_GA_REQ_ALLOW_LIST          0x03
#define CTAP_GA_REQ_EXTENSIONS          0x04
#define CTAP_GA_REQ_OPTIONS             0x05
#define CTAP_GA_REQ_PIN_AUTH            0x06
#define CTAP_GA_REQ_PIN_PROTOCOL        0x07

#define CTAP_GA_RESP_CREDENTIAL             0x01
#define CTAP_GA_RESP_AUTH_DATA              0x02
#define CTAP_GA_RESP_SIGNATURE              0x03
#define CTAP_GA_RESP_USER                   0x04
#define CTAP_GA_RESP_NUMBER_OF_CREDENTIALS  0x05

/**
 * 128 bit identifier indentifying type of authenticator
 * Todo: how to set this based on being in a generic OS ?
 */
#define DEVICE_AAGUID 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00


#define CTAP_CLIENT_DATA_HASH_SIZE 32 /* sha256 */

#define CTAP_PUB_KEY_CRED_PUB_KEY 0x01
#define CTAP_PUB_KEY_CRED_UNKNOWN 0x02

#define CTAP_COSE_KEY_LABEL_KTY      1
#define CTAP_COSE_KEY_LABEL_ALG      3
#define CTAP_COSE_KEY_LABEL_CRV      -1
#define CTAP_COSE_KEY_LABEL_X        -2
#define CTAP_COSE_KEY_LABEL_Y        -3
#define CTAP_COSE_KEY_KTY_EC2        2
#define CTAP_COSE_KEY_CRV_P256       1


#define CTAP_COSE_ALG_ES256            -7

#define CTAP_SHA256_HASH_SIZE 32

/* https://stackoverflow.com/questions/17269238/ecdsa-signature-length */
#define CTAP_ES256_DER_MAX_SIZE 72

#define CTAP_CREDENTIAL_ID_SIZE 16

/**
 * @brief Ctap resp struct forward declaration
 */
typedef struct ctap_resp ctap_resp_t;

/**
 * @brief Ctap resident key forward declaration
 */
typedef struct ctap_resident_key ctap_resident_key_t;


size_t ctap_handle_request(uint8_t* req, size_t size, ctap_resp_t* resp);
void ctap_init(void);
uint8_t ctap_get_attest_sig(uint8_t *auth_data, size_t auth_data_len, uint8_t *client_data_hash,
                            ctap_resident_key_t *rk, uint8_t* sig, size_t *sig_len);

typedef struct __attribute__((packed))
{
    uint8_t cred_type;
    int32_t alg_type;
} ctap_pub_key_cred_params_t;

typedef struct
{
    uint8_t id[CTAP_USER_ID_MAX_SIZE]; /* RP-specific user account id, byte string */
    uint8_t name[CTAP_USER_MAX_NAME_SIZE + 1]; /* user name */
    uint8_t display_name[CTAP_USER_MAX_NAME_SIZE + 1]; /* user display name */
    uint8_t icon[CTAP_DOMAIN_NAME_MAX_SIZE + 1]; /* URL referencing user icon image */
} ctap_user_ent_t; /* user entity */

struct ctap_resp
{
    uint8_t status;
    uint8_t data[CTAP_MAX_MSG_SIZE];
};

/* webauthn specification (version 20190304) section 5.8.3 */
typedef struct
{
    uint8_t cred_type;
    uint8_t cred_id[CTAP_CREDENTIAL_ID_SIZE];
} ctap_cred_desc_t;

typedef struct
{
    bool rk; /* resident key */
    bool uv; /* user verification */
    bool up; /* user presence */
} ctap_options_t;

typedef struct
{
    uint8_t id[CTAP_DOMAIN_NAME_MAX_SIZE + 1];  /* Relying party identifier (domain string) */
    size_t id_len;
    uint8_t name[CTAP_RP_MAX_NAME_SIZE + 1];        /* human friendly RP name */
    uint8_t icon[CTAP_DOMAIN_NAME_MAX_SIZE + 1]; /* URL referencing RP icon image */
} ctap_rp_ent_t; /* relying party entity */

typedef struct
{
    /* webauthn specification (version 20190304) section 5.10.1 */
    uint8_t client_data_hash[CTAP_SHA256_HASH_SIZE]; /* SHA-256 hash of JSON serialized client data */
    ctap_rp_ent_t rp; /* Relying party */
    ctap_user_ent_t user; /* user */
    ctap_pub_key_cred_params_t cred_params;
    ctap_options_t options; /* parameters to influence authenticator operation */
    CborValue exclude_list; /* cbor array holding exclude list */
    size_t exclude_list_len;
} ctap_make_credential_req_t;

typedef struct
{
    uint8_t rp_id[CTAP_DOMAIN_NAME_MAX_SIZE + 1];  /* Relying Party Identifier */
    size_t rp_id_len;
    uint8_t client_data_hash[CTAP_SHA256_HASH_SIZE]; /* SHA-256 hash of JSON serialized client data */
    ctap_options_t options; /* parameters to influence authenticator operation */
} ctap_get_assertion_req_t;

typedef struct
{
    uint8_t x[32];
    uint8_t y[32];
    ctap_pub_key_cred_params_t params;
} ctap_public_key_t;

typedef struct __attribute__((packed))
{
    uint8_t aaguid[16];
    uint8_t cred_len_h;
    uint8_t cred_len_l;
    uint8_t cred_id[CTAP_CREDENTIAL_ID_SIZE];
} ctap_attested_cred_data_header_t;

typedef struct
{
    ctap_attested_cred_data_header_t header;
    ctap_public_key_t pub_key;
} ctap_attested_cred_data_t;

/* part of attestation object  https://www.w3.org/TR/webauthn/#attestation-object */
typedef struct __attribute__((packed))
{
    uint8_t rp_id_hash[CTAP_SHA256_HASH_SIZE];
    uint8_t flags;
    uint32_t counter;
} ctap_auth_data_header_t;

typedef struct
{
    ctap_auth_data_header_t header;
    ctap_attested_cred_data_t attested_cred_data;
} ctap_auth_data_t;

/* https://www.w3.org/TR/webauthn/#client-side-resident-public-key-credential-source */
struct __attribute__((packed)) ctap_resident_key
{
    uint8_t rp_id_hash[CTAP_SHA256_HASH_SIZE];
    uint8_t priv_key[32];
};


#endif

