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
 * @brief       CTAP2 implementation
 *
 * @{
 *
 * @file
 * @brief       CTAP2 interface
 *
 * @author      Nils Ollrogge <nils-ollrogge@outlook.de>
 */

#ifndef CTAP_H
#define CTAP_H

#include <stdint.h>

#include "mutex.h"
#include "cbor.h"
#include "assert.h"
#include "hashes/sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief CTAP max message size
 *
 * CTAP specification (version 20190130) section 6:
 * By default, authenticators MUST support messages of at least 1024 bytes
 */
#define CTAP_MAX_MSG_SIZE                   0x400

/**
 * @name CTAP2 methods
 *
 * @{
 */
#define CTAP_MAKE_CREDENTIAL                0x01
#define CTAP_GET_ASSERTION                  0x02
#define CTAP_GET_INFO                       0x04
#define CTAP_CLIENT_PIN                     0x06
#define CTAP_RESET                          0x07
#define CTAP_GET_NEXT_ASSERTION             0x08
#define CTAP_VENDOR_FIRST                   0x40
#define CTAP_VENDOR_LAST                    0xBF
/** @} */

/**
 * @name CTAP authenticator data option flags
 *
 * @{
 */
#define CTAP_AUTH_DATA_FLAG_UP     (1 << 0)     /**< user present */
#define CTAP_AUTH_DATA_FLAG_UV     (1 << 2)     /**< user verified */
#define CTAP_AUTH_DATA_FLAG_AT     (1 << 6)     /**< attested credential data included */
#define CTAP_AUTH_DATA_FLAG_ED     (1 << 7)     /**< extension data included */
/** @} */

/**
 * @name CTAP2 status codes
 *
 * @{
 */
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
#define CTAP2_ERR_UP_REQUIRED               0x3B
#define CTAP1_ERR_OTHER                     0x7F
#define CTAP2_ERR_SPEC_LAST                 0xDF
#define CTAP2_ERR_EXTENSION_FIRST           0xE0
#define CTAP2_ERR_EXTENSION_LAST            0xEF
#define CTAP2_ERR_VENDOR_FIRST              0xF0
#define CTAP2_ERR_VENDOR_LAST               0xFF
/** @} */

/* todo: think about these sizes */

/**
 * @brief max size of reyling party name
 */
#define CTAP_RP_MAX_NAME_SIZE 32

/**
 * @brief max size of username
 */
#define CTAP_USER_MAX_NAME_SIZE 32

/**
 * @brief max size of user id
 */
#define CTAP_USER_ID_MAX_SIZE 64

/**
 * @brief max size of a domain name
 */
#define CTAP_DOMAIN_NAME_MAX_SIZE 253

/**
 * @brief PIN min size
 */
#define CTAP_PIN_MIN_SIZE   4

/**
 * @brief PIN max size
 */
#define CTAP_PIN_MAX_SIZE   64

/**
 * @brief PIN salt size
 */
#define CTAP_PIN_SALT_SIZE 32

/**
 * @brief max total consecutive incorrect PIN attempts
 */
#define CTAP_PIN_MAX_ATTS 8

/**
 * @brief max consecutive incorrect PIN attempts for 1 boot cycle
 */
#define CTAP_PIN_MAX_ATTS_BOOT 3

/**
 * @brief PIN protocol version
 */
#define CTAP_PIN_PROT_VER 1

/**
 * @brief Size of pin token
 */
#define CTAP_PIN_TOKEN_SIZE 16

/**
 * @brief Size of cryptographic keys used
 */
#define CTAP_KEY_LEN 32

/**
 * @brief Size of key used to encrypt credential
 *
 * @note Needed if authenticator is unable to store resident keys.
 * See webauthn specification (version 20190304) section 4 (Credential ID)
 * for details
 */
#define CTAP_CRED_KEY_LEN 16

/**
 * @brief AES_CCM_L parameter
 *
 * @note L has to be between 2 and 8. Value of 2 means that message has to be
 * in the range 0 <= l(m) < 2^(16) = 65536.
 * This should always be sufficient to send an encrypted resident key.
 */
#define CTAP_AES_CCM_L 2

/**
 * @brief AES CCM nonce size
 */
#define CTAP_AES_CCM_NONCE_SIZE (15 - CTAP_AES_CCM_L)

/**
 * @brief AES CCM MAC size
 */
#define CTAP_AES_CCM_MAC_SIZE 16

/**
 * @brief total size of AES CCM credential id
 *
 * @note size of encrypted resident key - cred id - has_nonce - sign_count
 */
#define CTAP_CREDENTIAL_ID_ENC_SIZE (sizeof(struct ctap_resident_key) - \
                    sizeof(((struct ctap_resident_key*)0)->cred_desc.cred_id) - \
                    sizeof(((struct ctap_resident_key*)0)->cred_desc.has_nonce) - \
                    sizeof(((struct ctap_resident_key*)0)->sign_count))

/**
 * @brief Start page for storing resident keys
 */
#define CTAP_RK_START_PAGE 32U

#define CTAP_FLASH_ALIGN_PAD (4 - sizeof(struct ctap_resident_key) % 4)

#define CTAP_PAD_RK_SZ (sizeof(struct ctap_resident_key) + CTAP_FLASH_ALIGN_PAD)

/**
 * @brief Max amount of resident keys we can store
 */
#define CTAP_MAX_RK (((FLASHPAGE_NUMOF - CTAP_RK_START_PAGE) * FLASHPAGE_SIZE) /  \
                    CTAP_PAD_RK_SZ)

/**
 * @brief Timeout for user presence test
 */
#define CTAP_UP_TIMEOUT (15 * US_PER_SEC)

/**
 * @brief Max time between call to get_assertion or
 * get_next_assertion
 */
#define CTAP_GET_NEXT_ASSERTION_TIMEOUT (30 * US_PER_SEC)

/**
 * @name CTAP version strings
 *
 * @{
 */
#define CTAP_VERSION_STRING_FIDO_PRE "FIDO_2_1_PRE"
#define CTAP_VERSION_STRING_FIDO     "FIDO_2_0"
#define CTAP_VERSION_STRING_U2F_V2   "U2F_V2"
/** @} */

/**
 * @name CTAP version flags
 *
 * @{
 */
#define CTAP_VERSION_FLAG_FIDO_PRE  0x01
#define CTAP_VERSION_FLAG_FIDO      0x02
#define CTAP_VERSION_FLAG_U2F_V2    0x04
/** @} */

/**
 * @name CTAP get info response options map CBOR key values
 *
 * All options are in the form key-value pairs with string IDs and boolean values
 * @{
 */
#define CTAP_GET_INFO_RESP_OPTIONS_ID_PLAT       "plat"
#define CTAP_GET_INFO_RESP_OPTIONS_ID_RK         "rk"
#define CTAP_GET_INFO_RESP_OPTIONS_ID_CLIENT_PIN "clientPin"
#define CTAP_GET_INFO_RESP_OPTIONS_ID_UP         "up"
#define CTAP_GET_INFO_RESP_OPTIONS_ID_UV         "uv"
/** @} */

/**
 * @name CTAP get info options flags
 *
 */
#define CTAP_INFO_OPTIONS_FLAG_PLAT         (1 << 0)
#define CTAP_INFO_OPTIONS_FLAG_RK           (1 << 1)
#define CTAP_INFO_OPTIONS_FLAG_CLIENT_PIN   (1 << 2)
#define CTAP_INFO_OPTIONS_FLAG_UP           (1 << 3)
#define CTAP_INFO_OPTIONS_FLAG_UV           (1 << 4)
/** @} */

/**
 * @name CTAP get info response CBOR key values
 *
 * @{
 */
#define CTAP_GET_INFO_RESP_VERSIONS         0x01
#define CTAP_GET_INFO_RESP_EXTENSIONS       0x02
#define CTAP_GET_INFO_RESP_AAGUID           0x03
#define CTAP_GET_INFO_RESP_OPTIONS          0x04
#define CTAP_GET_INFO_RESP_MAX_MSG_SIZE     0x05
#define CTAP_GET_INFO_RESP_PIN_PROTOCOLS    0x06
/** @} */

/**
 * @name CTAP make credential request CBOR key values
 *
 * @{
 */
#define CTAP_MC_REQ_CLIENT_DATA_HASH    0x01
#define CTAP_MC_REQ_RP                  0x02
#define CTAP_MC_REQ_USER                0x03
#define CTAP_MC_REQ_PUB_KEY_CRED_PARAMS 0x04
#define CTAP_MC_REQ_EXCLUDE_LIST        0x05
#define CTAP_MC_REQ_EXTENSIONS          0x06
#define CTAP_MC_REQ_OPTIONS             0x07
#define CTAP_MC_REQ_PIN_AUTH            0x08
#define CTAP_MC_REQ_PIN_PROTOCOL        0x09
/** @} */

/**
 * @name CTAP make credential response CBOR key values
 *
 * @{
 */
#define CTAP_MC_RESP_FMT                0x01
#define CTAP_MC_RESP_AUTH_DATA          0x02
#define CTAP_MC_RESP_ATT_STMT           0x03
/** @} */

/**
 * @name CTAP get assertion request CBOR key values
 *
 * @{
 */
#define CTAP_GA_REQ_RP_ID               0x01
#define CTAP_GA_REQ_CLIENT_DATA_HASH    0x02
#define CTAP_GA_REQ_ALLOW_LIST          0x03
#define CTAP_GA_REQ_EXTENSIONS          0x04
#define CTAP_GA_REQ_OPTIONS             0x05
#define CTAP_GA_REQ_PIN_AUTH            0x06
#define CTAP_GA_REQ_PIN_PROTOCOL        0x07
/** @} */

/**
 * @name CTAP get assertion response CBOR key values
 *
 * @{
 */
#define CTAP_GA_RESP_CREDENTIAL             0x01
#define CTAP_GA_RESP_AUTH_DATA              0x02
#define CTAP_GA_RESP_SIGNATURE              0x03
#define CTAP_GA_RESP_USER                   0x04
#define CTAP_GA_RESP_NUMBER_OF_CREDENTIALS  0x05
/** @} */

/**
 * @name CTAP Client PIN request CBOR key values
 *
 * @{
 */
#define CTAP_CP_REQ_PIN_PROTOCOL    0x01
#define CTAP_CP_REQ_SUB_COMMAND     0x02
#define CTAP_CP_REQ_KEY_AGREEMENT   0x03
#define CTAP_CP_REQ_PIN_AUTH        0x04
#define CTAP_CP_REQ_NEW_PIN_ENC     0x05
#define CTAP_CP_REQ_PIN_HASH_ENC    0x06
/** @} */

/**
 * @name CTAP Client PIN request subcommand CBOR key values
 *
 * @{
 */
#define CTAP_CP_REQ_SUB_COMMAND_GET_RETRIES         0x01
#define CTAP_CP_REQ_SUB_COMMAND_GET_KEY_AGREEMENT   0x02
#define CTAP_CP_REQ_SUB_COMMAND_SET_PIN             0x03
#define CTAP_CP_REQ_SUB_COMMAND_CHANGE_PIN          0x04
#define CTAP_CP_REQ_SUB_COMMAND_GET_PIN_TOKEN       0x05
/** @} */

/**
 * @name CTAP Client PIN resp CBOR key values
 *
 * @{
 */
#define CTAP_CP_RESP_KEY_AGREEMENT  0x01
#define CTAP_CP_RESP_PIN_TOKEN      0x02
#define CTAP_CP_RESP_RETRIES        0x03
/** @} */

/**
 * 128 bit identifier indentifying type of authenticator
 */
#ifdef CONFIG_CTAP_AAGUID
#define CTAP_AAGUID CONFIG_CTAP_AAGUID
#else
#error Please configure ctap device AAGUID. For development you may \
        set CONFIG_CTAP_AAGUID=${CTAP_AAGUID_TESTING}
#endif

/**
 * @name CTAP credential types
 *
 * @{
 */
#define CTAP_PUB_KEY_CRED_PUB_KEY 0x01
#define CTAP_PUB_KEY_CRED_UNKNOWN 0x02
/** @} */

/**
 * @name CTAP COSE key CBOR map key values
 *
 * @{
 */
#define CTAP_COSE_KEY_LABEL_KTY      1
#define CTAP_COSE_KEY_LABEL_ALG      3
#define CTAP_COSE_KEY_LABEL_CRV      -1
#define CTAP_COSE_KEY_LABEL_X        -2
#define CTAP_COSE_KEY_LABEL_Y        -3
#define CTAP_COSE_KEY_KTY_EC2        2
#define CTAP_COSE_KEY_CRV_P256       1
/** @} */

/**
 * @brief CTAP COSE Algorithms registry identifier for ES256
 */
#define CTAP_COSE_ALG_ES256           -7

/**
 * @brief CTAP COSE Algorithms registry identifier for ECDH ES HKDF 256
 * (Elliptic Curve Diffie Hellman ephemeral static + HMAC-SHA256 Key Derivation function)
 */
#define CTAP_COSE_ALG_ECDH_ES_HKDF_256 -25

/**
 * @brief max size of ES256 signature
 *
 * https://stackoverflow.com/questions/17269238/ecdsa-signature-length
 */
#define CTAP_ES256_DER_MAX_SIZE 72

/**
 * @brief CTAP size of credential id
 *
 */
#define CTAP_CREDENTIAL_ID_SIZE 16U

/**
 * @brief CTAP size of authenticator AAGUID
 */
#define CTAP_AAGUID_SIZE 16

/**
 * @brief CTAP state initialized marker
 */
#define CTAP_INITIALIZED_MARKER 0x4e

/**
 * @brief max size of allow list
 */
#define CTAP_MAX_ALLOW_LIST_SIZE 0x10

/**
 * @brief max size of allow list
 */
#define CTAP_MAX_EXCLUDE_LIST_SIZE 0x10

/**
 * @brief CTAP resp struct forward declaration
 */
typedef struct ctap_resp ctap_resp_t;
typedef struct ctap_cred_desc ctap_cred_desc_t;
typedef struct ctap_cred_desc_alt ctap_cred_desc_alt_t;

typedef struct ctap_resident_key ctap_resident_key_t;


/**
 * @brief CTAP public key credential parameter
 *
 */
typedef struct __attribute__((packed))
{
    uint8_t cred_type;  /**< type of credential */
    int32_t alg_type;   /**< cryptographic algorithm identifier */
} ctap_pub_key_cred_params_t;

/**
 * @brief CTAP user entity struct
 *
 * todo: remove name, display_name and icon as they are not needed when no screen and they take up stack memory
 */
typedef struct
{
    uint8_t id[CTAP_USER_ID_MAX_SIZE];                  /**< RP-specific user account id */
    uint8_t id_len;                                     /**< actual length of user id */
    uint8_t name[CTAP_USER_MAX_NAME_SIZE + 1];          /**< user name */
    uint8_t display_name[CTAP_USER_MAX_NAME_SIZE + 1];  /**< user display name */
    uint8_t icon[CTAP_DOMAIN_NAME_MAX_SIZE + 1];        /**< URL referencing user icon image */
} ctap_user_ent_t;

/**
 * @brief CTAP response struct
 *
 */
struct ctap_resp
{
    uint8_t status;                     /**< status indicating if request could be processed successfully */
    uint8_t data[CTAP_MAX_MSG_SIZE];    /**< response data */
};

/**
 * @brief CTAP credential description struct
 *
 * webauthn specification (version 20190304) section 5.8.3
 */
struct ctap_cred_desc
{
    uint8_t cred_type;                          /**< type of credential */
    union {
        uint8_t cred_id[CTAP_CREDENTIAL_ID_SIZE];   /**< credential identifier */
        uint8_t nonce[CTAP_AES_CCM_NONCE_SIZE];    /**< CTAP AES CCM nonce */
    };
    bool has_nonce;  /**< Indicate if AES CCM nonce is stored instead of id  */
};

/**
 * @brief CTAP options struct
 *
 */
typedef struct
{
    bool rk; /**< resident key */
    bool uv; /**< user verification */
    bool up; /**< user presence */
} ctap_options_t;

/**
 * @brief CTAP relying party entity struct
 *
 * todo: remove name and icon as they are not needed when no screen and they take up stack memory
 */
typedef struct
{
    uint8_t id[CTAP_DOMAIN_NAME_MAX_SIZE + 1];          /**< relying party identifier */
    uint8_t id_len;                                      /**< actual length of relying party identifier */
    uint8_t name[CTAP_RP_MAX_NAME_SIZE + 1];            /**< human friendly relying party name */
    uint8_t icon[CTAP_DOMAIN_NAME_MAX_SIZE + 1];        /**< URL referencing relying party icon image */
} ctap_rp_ent_t;

/**
 * @brief CTAP cose key struct
 *
 * https://www.iana.org/assignments/cose/cose.xhtml
 */
typedef struct
{
    struct {
        uint8_t x[32];
        uint8_t y[32];
    } pubkey;

    int kty;             /**< identification of key type */
    int crv;             /**< EC identifier */
    int32_t alg_type;    /**< COSEAlgorithmIdentifier */
    uint8_t cred_type;  /**< type of credential */
} ctap_cose_key_t;

/**
 * @brief CTAP resident key struct
 *
 */
struct __attribute__((packed)) ctap_resident_key
{
    uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
    uint8_t user_id[CTAP_USER_ID_MAX_SIZE];
    uint8_t user_id_len;
    uint8_t priv_key[32];
    ctap_cred_desc_t cred_desc;
    uint32_t sign_count;
};

/**
 * @brief CTAP credential ID
 *
 * @note credential ID can either be 16 rand bytes, or the encrypted resident
 * key. (AES CCM cipher + mac + nonce used)
 */
typedef struct __attribute__((packed))
{
    uint8_t id[CTAP_CREDENTIAL_ID_ENC_SIZE];
    uint8_t mac[CTAP_AES_CCM_MAC_SIZE];
    uint8_t nonce[CTAP_AES_CCM_NONCE_SIZE];
} ctap_cred_id_t;

/**
 * @brief CTAP credential description alternative struct
 *
 * @note This struct is used when parsing allow or exclude list, since the
 * credential ID can either be 16 rand bytes, or the encrypted resident key.
 */
struct ctap_cred_desc_alt
{
    uint8_t cred_type;
    ctap_cred_id_t cred_id;
};

/**
 * @brief CTAP make credential request struct
 *
 */
typedef struct
{
    uint8_t client_data_hash[SHA256_DIGEST_LENGTH];     /**< SHA-256 hash of JSON serialized client data */
    ctap_rp_ent_t rp;                                   /**< relying party */
    ctap_user_ent_t user;                               /**< user */
    ctap_pub_key_cred_params_t cred_params;             /**< public key credential parameters */
    ctap_options_t options;                             /**< parameters to influence authenticator operation */
    CborValue exclude_list;                             /**< cbor array holding exclude list */
    size_t exclude_list_len;                            /**< length of CBOR exclude list array */
    uint8_t pin_auth[16];                               /**< pin_auth if PIN is set */
    bool pin_auth_present;                              /**< pin_auth present ? */
    uint8_t pin_protocol;                               /**< PIN protocol version */

} ctap_make_credential_req_t;

/**
 * @brief CTAP get assertion request struct
 *
 */
typedef struct
{
    uint8_t rp_id[CTAP_DOMAIN_NAME_MAX_SIZE + 1];       /**< Relying Party Identifier */
    uint8_t rp_id_len;                                  /**< Actual Length of Relying Party Identifier */
    uint8_t client_data_hash[SHA256_DIGEST_LENGTH];     /**< SHA-256 hash of JSON serialized client data */
    ctap_options_t options;                             /**< parameters to influence authenticator operation */
    CborValue allow_list;                               /**< cbor array holding allow list */
    uint8_t allow_list_len;                             /**< length of CBOR allow list array */
    uint8_t pin_auth[16];                               /**< pin_auth if PIN is set */
    bool pin_auth_present;                              /**< pin_auth present ? */
    uint8_t pin_protocol;                               /**< PIN protocol version */
} ctap_get_assertion_req_t;

/**
 * @brief CTAP client pin request struct
 *
 */
typedef struct
{
    uint8_t pin_protocol; /**< PIN protocol version chosen by the client */
    uint8_t sub_command; /**< authenticator Client PIN sub command */
    ctap_cose_key_t key_agreement; /**< public key of platform_key_agreement_key*/
    bool key_agreement_present;
    uint8_t pin_auth[16]; /**< first 16 bytes of HMAC-SHA-256 of encrypted contents  */
    bool pin_auth_present;
    uint8_t new_pin_enc[256]; /**< Encrypted new PIN using sharedSecret. */
    uint16_t new_pin_enc_size;
    uint8_t pin_hash_enc[16]; /**< Encrypted first 16 bytes of SHA-256 of PIN using sharedSecret. */
    bool pin_hash_enc_present;
} ctap_client_pin_req_t;

/**
 * @brief CTAP get_assertion state
 *
 */
typedef struct
{
    ctap_resident_key_t rks[CTAP_MAX_ALLOW_LIST_SIZE];
    uint8_t count; /**< number of rks found  */
    uint8_t cred_counter; /**< amount of creds sent to host */
    uint32_t timer; /**< time gap between get_next_assertion calls  */
    bool uv; /**< user verified */
    bool up; /**< user present */
    uint8_t client_data_hash[SHA256_DIGEST_LENGTH]; /**< SHA-256 hash of JSON serialized client data */
} ctap_get_assertion_state_t;

/**
 * @brief CTAP attested credential data header struct
 *
 * defined for easier serialization
 */
typedef struct __attribute__((packed))
{
    uint8_t aaguid[CTAP_AAGUID_SIZE];
    uint8_t cred_len_h;
    uint8_t cred_len_l;
    ctap_cred_id_t cred_id;
} ctap_attested_cred_data_header_t;

/**
 * @brief CTAP attested credential data struct
 *
 */
typedef struct
{
    ctap_attested_cred_data_header_t header;
    ctap_cose_key_t key;
} ctap_attested_cred_data_t;

/**
 * @brief CTAP authenticator data header struct
 *
 * defined for easier serialization
 */
typedef struct __attribute__((packed))
{
    uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
    uint8_t flags;
    uint32_t sign_count;
} ctap_auth_data_header_t;

/**
 * @brief CTAP authenticator data struct
 */
typedef struct
{
    ctap_auth_data_header_t header;
    ctap_attested_cred_data_t attested_cred_data;
} ctap_auth_data_t;

typedef struct
{
    uint8_t options;  /*< options */
    uint8_t aaguid[CTAP_AAGUID_SIZE]; /*< AAGUID of device */
} ctap_config_t;

/**
 * @brief General state of CTAP stored in flash memory
 *
 */
typedef struct
{
    uint8_t initialized;    /**< CTAP is initialized or not */
    bool pin_is_set;            /**< PIN is set or not */
    uint8_t rem_pin_att; /**< remaining PIN tries */
    uint8_t rem_pin_att_boot; /**< remaining PIN attempts for this power cycle */
    uint8_t pin_hash[SHA256_DIGEST_LENGTH]; /**< SHA256 of PIN + salt */
    uint8_t pin_salt[CTAP_PIN_SALT_SIZE];  /**< PIN salt */
    ctap_config_t config;
    uint16_t rk_amount_stored; /**< total number of resident keys stored on device */
    uint32_t sign_count;  /**< global sign counter */
    uint8_t cred_key[CTAP_CRED_KEY_LEN]; /**< AES CCM encryption key for cred */
} ctap_state_t;

typedef struct
{
    uint8_t versions;   /**< supported versions of FIDO */
    uint8_t aaguid[CTAP_AAGUID_SIZE]; /**< AAGUID */
    uint8_t options;    /**< supported options */
    uint16_t max_msg_size; /**< max message size */
    uint8_t pin_protocol; /**< supported PIN protocol versions */
    bool pin_is_set;  /**< PIN is set or not */
} ctap_info_t;

/**
 * @brief Handle CBOR encoded ctap request.
 *
 * @param[in] req   request
 * @param[in] size  size of request in bytes
 * @param[in] resp  response struct
 *
 * @return size of cbor encoded response data
 */
size_t ctap_handle_request(uint8_t* req, size_t size, ctap_resp_t* resp,
                           bool (*should_cancel)(void));

/**
 * @brief Create attestation signature
 *
 * @param[in] auth_data         authenticator data
 * @param[in] auth_data_len     length of authenticator data
 * @param[in] client_data_hash  hash of client data sent by relying party in request
 * @param[in] rk                resident key used to sign the data
 * @param[in] sig               signature buffer
 * @param[in] sig_len           length of signature buffer
 *
 * @return CTAP status code
 */
uint8_t ctap_get_attest_sig(uint8_t *auth_data, size_t auth_data_len,
                            uint8_t *client_data_hash, ctap_resident_key_t *rk,
                            uint8_t* sig, size_t *sig_len);

/**
 * @brief Check if requested algorithm is supported
 *
 * @param[in] cred_type    type of credential
 * @param[in] alg_type     cryptographic algorithm identifier
 *
 * @return CTAP status code
 */
bool ctap_cred_params_supported(uint8_t cred_type, int32_t alg_type);

uint8_t ctap_encrypt_rk(ctap_resident_key_t *rk, uint8_t* n, ctap_cred_id_t* id);

/**
 * @brief Create threads needed for ctap
 */
void ctap_create(void);

/**
 * @brief Initialize ctap
 */
void ctap_init(void);

#ifdef __cplusplus
}
#endif
#endif
