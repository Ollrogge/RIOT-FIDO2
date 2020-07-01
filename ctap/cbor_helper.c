
#include "cbor_helper.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

static uint8_t parse_rp(CborValue *it, ctap_rp_ent_t* rp);
static uint8_t parse_user(CborValue *it, ctap_user_ent_t *user);
static uint8_t parse_pub_key_cred_params(CborValue *it, ctap_pub_key_cred_params_t* params);
static uint8_t parse_pub_key_cred_param(CborValue *it, uint8_t* cred_type, int32_t* alg_type);
static uint8_t parse_exclude_list(CborValue *it);

static uint8_t parse_fixed_size_byte_array(CborValue *map, uint8_t* dst, size_t len);
static uint8_t parse_byte_array(CborValue *it, uint8_t* dst, size_t len);
static uint8_t parse_text_string(CborValue *it, char* dst, size_t len);

static uint8_t cred_params_supported(uint8_t cred_type, int32_t alg_type);

static uint8_t cred_params_supported(uint8_t cred_type, int32_t alg_type)
{
    (void)cred_type;
    (void)alg_type;
    DEBUG("cred_params_supported cred_type: %u alg_type: %lu \n", cred_type, alg_type);
    return 1;
}

/* CTAP specification (version 20190130) section 5.4 */
// TODO: THESE SETTINGS MIGHT DIFFER FOR EACH IOT DEVICE. WHAT TO DO ABOUT THIS ?
uint8_t cbor_helper_get_info(CborEncoder* encoder)
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

uint8_t cbor_helper_parse_make_credential_req(ctap_make_credential_req_t *req, size_t size, uint8_t* req_raw)
{
    int ret;
    int key;
    CborParser parser;
    CborValue it;
    CborValue map;
    size_t map_len;
    CborType type;

    DEBUG("cbor_helper_parse_make_credential_req size: %u \n", size);

    ret = cbor_parser_init(req_raw, size, CborValidateCanonicalFormat, &parser, &it);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    type = cbor_value_get_type(&it);
    if (type != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

    DEBUG("test1 \n");

    ret = cbor_value_enter_container(&it, &map);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    ret = cbor_value_get_map_length(&it, &map_len);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    for (size_t i = 0; i < map_len; i++) {
        type = cbor_value_get_type(&map);
        if (type != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

        ret = cbor_value_get_int_checked(&map, &key);
        if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

        ret = cbor_value_advance(&map);
        if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

        switch(key)
        {
            case CTAP_MC_REQ_CLIENT_DATA_HASH:
                DEBUG("CTAP_make_credential parse clientDataHash \n");
                ret = parse_fixed_size_byte_array(&map, req->client_data_hash, CTAP_CLIENT_DATA_HASH_SIZE);
                break;
            case CTAP_MC_REQ_RP:
                DEBUG("CTAP_make_credential parse rp \n");
                ret = parse_rp(&map, &req->rp);
                break;
            case CTAP_MC_REQ_USER:
                DEBUG("CTAP_make_credential parse user \n");
                ret = parse_user(&map, &req->user);
                break;
            case CTAP_MC_REQ_PUB_KEY_CRED_PARAMS:
                DEBUG("CTAP make_credential parse key_cred params \n");
                ret = parse_pub_key_cred_params(&map, &req->cred_params);
                break;
            case CTAP_MC_REQ_EXCLUDE_LIST:
                DEBUG("CTAP_make_credential parse excludeList \n");
                ret = parse_exclude_list(&map);
                break;
            case CTAP_MC_REQ_EXTENSIONS:
                DEBUG("CTAP make_credential parse exclude_list \n");
                break;
            case CTAP_MC_REQ_OPTIONS:
                DEBUG("CTAP make_credential parse options \n");
                break;
            case CTAP_MC_REQ_PIN_AUTH:
                DEBUG("CTAP make_credential parse pin_auth \n");
                break;
            case CTAP_MC_REQ_PIN_PROTOCOL:
                DEBUG("CTAP make_credential parse pin_protocol \n");
                break;
            default:
                break;
        }
    }

    return CTAP2_OK;
}

/* parse PublicKeyCredentialRpEntity dictionary */
static uint8_t parse_rp(CborValue *it, ctap_rp_ent_t* rp)
{
    int ret;
    int type;
    CborValue map;
    size_t map_len;
    char key[8];
    size_t key_len = sizeof(key);

    type = cbor_value_get_type(it);
    if (type != CborMapType) return CTAP2_ERR_INVALID_CBOR_TYPE;

    ret = cbor_value_enter_container(it, &map);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    ret = cbor_value_get_map_length(&map, &map_len);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    for (size_t i = 0; i < map_len; i++) {

        type = cbor_value_get_type(&map);
        if (type != CborTextStringType) return CTAP2_ERR_INVALID_CBOR_TYPE;

        ret = cbor_value_copy_text_string(&map, key, &key_len, NULL);
        if (ret == CborErrorOutOfMemory) return CTAP2_ERR_LIMIT_EXCEEDED;

        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

        type = cbor_value_get_type(&map);
        if (type != CborTextStringType) return CTAP2_ERR_INVALID_CBOR_TYPE;

        /* todo: make sure we have id key, because it is not optional */
        if (strcmp(key, "id") == 0) {
            ret = parse_text_string(&map, (char*)rp->id, CTAP_DOMAIN_NAME_MAX_SIZE);
            if (ret != 0) {
                return ret;
            }
        }
        else if (strcmp(key, "name") == 0) {
            ret = parse_text_string(&map, (char*)rp->name, CTAP_RP_MAX_NAME_SIZE);
            if (ret != 0) {
                return ret;
            }
        }
        else if (strcmp(key, "icon") == 0) {
            ret = parse_text_string(&map, (char*)rp->icon, CTAP_DOMAIN_NAME_MAX_SIZE);
            if (ret != 0) {
                return ret;
            }
        }
        else {
            DEBUG("CTAP_parse_rp: ignoring unknown key: %s \n", key);
        }

        ret = cbor_value_advance(&map);
        if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    }

    return CTAP2_OK;
}

/* parse PublicKeyCredentialUserEntity dictionary */
static uint8_t parse_user(CborValue *it, ctap_user_ent_t *user)
{
    char key[16];
    size_t key_len = sizeof(key);
    int type;
    int ret;
    CborValue map;
    size_t map_len;

    type = cbor_value_get_type(it);
    if (type != CborMapType) return CTAP2_ERR_INVALID_CBOR_TYPE;

    ret = cbor_value_enter_container(it, &map);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    ret = cbor_value_get_map_length(&map, &map_len);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    for (size_t i = 0; i < map_len; i++) {
        type = cbor_value_get_type(&map);
        if (type != CborTextStringType) return CTAP2_ERR_INVALID_CBOR_TYPE;

        ret = cbor_value_copy_text_string(&map, key, &key_len, NULL);
        if (ret == CborErrorOutOfMemory) return CTAP2_ERR_LIMIT_EXCEEDED;

        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

        /* todo: make sure we have id key, because it is not optional */
        if (strcmp(key, "id") == 0) {
            ret = parse_byte_array(&map, user->id, CTAP_USER_ID_MAX_SIZE);
            if (ret != 0) {
                return ret;
            }
        }
        else if (strcmp(key, "name") == 0) {
            ret = parse_text_string(it, (char*)user->name, CTAP_USER_MAX_NAME_SIZE);
            if (ret != 0) {
                return ret;
            }
        }
        else if (strcmp(key, "displayName") == 0) {
            ret = parse_text_string(it, (char*)user->display_name, CTAP_USER_MAX_NAME_SIZE);
            if (ret != 0) {
                return ret;
            }
        }
        else if (strcmp(key, "icon") == 0) {
            ret = parse_text_string(it, (char*)user->icon, CTAP_DOMAIN_NAME_MAX_SIZE);
        }
        else {
            DEBUG("CTAP_parse_rp: ignoring unknown key: %s \n", key);
        }

        ret = cbor_value_advance(&map);
        if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    }

    return CTAP2_OK;
}

/* parse pubKeyCredParams array */
static uint8_t parse_pub_key_cred_params(CborValue *it, ctap_pub_key_cred_params_t* params)
{
    int type;
    int ret;
    CborValue arr;
    size_t arr_len;

    uint8_t cred_type;
    int32_t alg_type;

    type = cbor_value_get_type(it);
    if (type != CborArrayType) return CTAP2_ERR_INVALID_CBOR_TYPE;

    ret = cbor_value_enter_container(it, &arr);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    ret = cbor_value_get_array_length(it, &arr_len);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    /* params ordered from most preferred (by the RP) to least */
    for (size_t i = 0; i < arr_len; i++) {
        ret = parse_pub_key_cred_param(&arr, &cred_type, &alg_type);
        if (ret != CTAP2_OK) {
            return ret;
        }

        if (cred_params_supported(cred_type, alg_type)) {
            params->cred_type = cred_type;
            params->alg_type = alg_type;
            return CTAP2_OK;
        }

        ret = cbor_value_advance(&arr);
        if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    }

    return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
}

/* parse pubKeyCredParam dictionary */
static uint8_t parse_pub_key_cred_param(CborValue *it, uint8_t* cred_type, int32_t* alg_type)
{
    CborValue cred;
    CborValue alg;
    char type_str[16];
    size_t type_str_len = sizeof(type_str);
    int ret;
    int type;

    type = cbor_value_get_type(it);
    if (type != CborMapType) return CTAP2_ERR_INVALID_CBOR_TYPE;

    ret = cbor_value_map_find_value(it, "type", &cred);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    type = cbor_value_get_type(&cred);
    if (type != CborTextStringType) return CTAP2_ERR_MISSING_PARAMETER;

    ret = cbor_value_map_find_value(it, "alg", &alg);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    type = cbor_value_get_type(&alg);
    if (type != CborTextStringType) return CTAP2_ERR_MISSING_PARAMETER;

    ret = cbor_value_copy_text_string(&cred, type_str, &type_str_len, NULL);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    type_str[sizeof(type_str) - 1] = 0;

    if (strcmp(type_str, "public-key") == 0) {
        *cred_type = CTAP_PUB_KEY_CRED_PUB_KEY;
    }
    else {
        *cred_type = CTAP_PUB_KEY_CRED_UNKNOWN;
    }

    ret = cbor_value_get_int_checked(&alg, (int*)alg_type);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    return 0;
}

static uint8_t parse_exclude_list(CborValue *it)
{
    (void)it;
    return CTAP2_OK;
}

static uint8_t parse_fixed_size_byte_array(CborValue *it, uint8_t* dst, size_t len)
{
    int ret;
    int type;
    size_t len_copied;

    type = cbor_value_get_type(it);
    if (type != CborByteStringType) return CTAP2_ERR_INVALID_CBOR_TYPE;

    ret = cbor_value_copy_byte_string(it, dst, &len_copied, NULL);
    if (ret != CborNoError) return CTAP2_ERR_CBOR_PARSING;

    if (len_copied != len) {
        return CTAP1_ERR_INVALID_LENGTH;
    }

    return 0;
}

static uint8_t parse_byte_array(CborValue *it, uint8_t* dst, size_t len)
{
    int type;
    int ret;

    type = cbor_value_get_type(it);
    if (type != CborByteStringType) return CTAP2_ERR_INVALID_CBOR_TYPE;

    ret = cbor_value_copy_byte_string(it, dst, &len, NULL);
    if (ret == CborErrorOutOfMemory) return CTAP2_ERR_LIMIT_EXCEEDED;

    return 0;
}

static uint8_t parse_text_string(CborValue *it, char* dst, size_t len)
{
    int type;
    int ret;

    type = cbor_value_get_type(it);
    if (type != CborTextStringType) return CTAP2_ERR_INVALID_CBOR_TYPE;

    ret = cbor_value_copy_text_string(it, dst, &len, NULL);
    if (ret == CborErrorOutOfMemory) return CTAP2_ERR_LIMIT_EXCEEDED;

    dst[len] = 0;

    return 0;
}
