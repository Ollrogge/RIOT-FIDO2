
#define ENABLE_DEBUG    (1)
#include "debug.h"

#include <string.h>

#include "fmt.h"

#include "ctap.h"

#include "ctap_hid.h"

#include "cbor_helper.h"

#include "ctap_crypto.h"

#include "xtimer.h"

#include "periph/flashpage.h"

#include "relic.h"

#include "rijndael-api-fst.h"

#define CTAP_TESTING 1

static uint8_t get_info(CborEncoder *encoder);
static uint8_t make_credential(CborEncoder* encoder, size_t size, uint8_t* req_raw,
                                bool *should_cancel, mutex_t *should_cancel_mutex);
static uint8_t make_auth_data_attest(ctap_rp_ent_t *rp, ctap_user_ent_t *user,
                                     ctap_pub_key_cred_params_t *cred_params,
                              ctap_auth_data_t* auth_data, ctap_resident_key_t *rk
                              ,bool uv);
static uint8_t make_auth_data_assert(uint8_t * rp_id, size_t rp_id_len,
                                    ctap_auth_data_header_t *auth_data, bool uv);
static uint8_t get_assertion(CborEncoder *encoder, size_t size, uint8_t *req_raw,
                             bool *should_cancel, mutex_t *should_cancel_mutex);
static uint8_t client_pin(CborEncoder *encoder, size_t size, uint8_t *req_raw,
                          bool *should_cancel, mutex_t *should_cancel_mutex);
static uint8_t set_pin(ctap_client_pin_req_t *req, bool *should_cancel, mutex_t *should_cancel_mutex);
static uint8_t change_pin(ctap_client_pin_req_t *req, bool *should_cancel, mutex_t *should_cancel_mutex);
static uint8_t get_retries(CborEncoder *encoder);
static uint8_t get_pin_token(CborEncoder *encoder, ctap_client_pin_req_t *req);
static uint32_t get_auth_data_sign_count(uint32_t* auth_data_counter);
static uint8_t key_agreement(CborEncoder *encoder);
static void save_rk(ctap_resident_key_t *rk);
static void load_rk(ctap_resident_key_t *rk);
static uint8_t save_pin(uint8_t *pin, size_t len);
static void save_state(ctap_state_t *state);
static void load_state(ctap_state_t *state);
static uint8_t is_valid_credential(ctap_cred_desc_t *cred_desc, ctap_resident_key_t *rk);
static bool pin_is_set(void);
static uint8_t get_remaining_pin_attempts(void);
static uint8_t decrement_pin_attempts(void);
static void reset_pin_attempts(void);
static void reset(void);
static uint8_t verify_pin_auth(uint8_t *auth, uint8_t *hash, size_t len);

static ctap_state_t g_state;
static uint8_t g_pin_token[CTAP_PIN_TOKEN_SIZE];
static uint8_t g_rem_pin_att_boot;

void ctap_init(void)
{
    int ret;
    (void)ret;

    load_state(&g_state);

    if (g_state.initialized != CTAP_INITIALIZED_MARKER) {
        g_state.initialized = CTAP_INITIALIZED_MARKER;
        g_state.rem_pin_att = CTAP_PIN_MAX_ATTS;
        g_state.pin_is_set = false;

        ctap_crypto_prng(g_state.pin_salt, sizeof(g_state.pin_salt));

        save_state(&g_state);
    }

    g_rem_pin_att_boot = CTAP_PIN_MAX_ATTS_BOOT;

    /* todo: what to do if init fails? */
    ret = ctap_crypto_init();

     /* initialize pin_token */
    ctap_crypto_prng(g_pin_token, sizeof(g_pin_token));
}

static void reset(void)
{
    g_state.initialized = CTAP_INITIALIZED_MARKER;
    g_state.rem_pin_att = CTAP_PIN_MAX_ATTS;
    g_state.rem_pin_att_boot = CTAP_PIN_MAX_ATTS_BOOT;
    g_state.pin_is_set = false;
    ctap_crypto_prng(g_state.pin_salt, sizeof(g_state.pin_salt));

    save_state(&g_state);
}

static bool pin_is_set(void)
{
    return g_state.pin_is_set;
}

static uint8_t decrement_pin_attempts(void)
{
    g_state.rem_pin_att--;
    g_rem_pin_att_boot--;

    if (g_state.rem_pin_att == 0) {
        return CTAP2_ERR_PIN_BLOCKED;
    }

    if (g_rem_pin_att_boot == 0) {
        return CTAP2_ERR_PIN_AUTH_BLOCKED;
    }

    return CTAP2_OK;
}

static uint8_t get_remaining_pin_attempts(void)
{
    return g_state.rem_pin_att;
}

static void reset_pin_attempts(void)
{
    g_state.rem_pin_att = CTAP_PIN_MAX_ATTS;
    g_rem_pin_att_boot = CTAP_PIN_MAX_ATTS_BOOT;
}

static uint8_t verify_pin_auth(uint8_t *auth, uint8_t *hash, size_t len)
{
    uint8_t hmac[SHA256_DIGEST_LENGTH];

    hmac_sha256(g_pin_token, sizeof(g_pin_token), hash, len, hmac);

    if (memcmp(auth, hmac, 16) != 0) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    return CTAP2_OK;
}

/* webauthn specification (version 20190304) section 6.1.1 */
static uint32_t get_auth_data_sign_count(uint32_t* auth_data_counter)
{
    static uint32_t counter = 0;
    counter++;

    /*
    webauthn specification (version 20190304) section 6.1
    sign counter is big endian
    todo: check for endianess of system?
    */
    uint8_t *byte = (uint8_t*)auth_data_counter;
    *byte++ = (counter >> 24) & 0xff;
    *byte++ = (counter >> 16) & 0xff;
    *byte++ = (counter >> 8) & 0xff;
    *byte++ = (counter >> 0) & 0xff;

    return counter;
}

static void print_hex(uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        DEBUG("%02x", data[i]);
    }

    DEBUG("\n");
}

size_t ctap_handle_request(uint8_t* req, size_t size, ctap_resp_t* resp,
                           bool *should_cancel, mutex_t *should_cancel_mutex)
{
    DEBUG("ctap handle request %u \n ", size);

    CborEncoder encoder;
    memset(&encoder, 0, sizeof(CborEncoder));

    uint8_t cmd = *req;
    req++;
    size--;

    uint8_t* buf = resp->data;

    cbor_encoder_init(&encoder, buf, CTAP_MAX_MSG_SIZE, 0);

    switch (cmd)
    {
        case CTAP_GET_INFO:
            DEBUG("CTAP GET INFO \n");
            resp->status = get_info(&encoder);
            return cbor_encoder_get_buffer_size(&encoder, buf);
            break;
        case CTAP_MAKE_CREDENTIAL:
            DEBUG("CTAP MAKE CREDENTIAL \n");
            resp->status = make_credential(&encoder, size, req,
                                           should_cancel, should_cancel_mutex);
            DEBUG("make cred resp: ");
            print_hex(buf, cbor_encoder_get_buffer_size(&encoder, buf));
            return cbor_encoder_get_buffer_size(&encoder, buf);
            break;
        case CTAP_GET_ASSERTION:
            DEBUG("CTAP GET_ASSERTION \n");
            resp->status = get_assertion(&encoder, size, req, should_cancel,
                                         should_cancel_mutex);
            DEBUG("get assertion resp: ");
            print_hex(buf, cbor_encoder_get_buffer_size(&encoder, buf));
            return cbor_encoder_get_buffer_size(&encoder, buf);
            break;
        case CTAP_GET_NEXT_ASSERTION:
            DEBUG("CTAP GET NEXT ASSERTION \n");
            break;
        case CTAP_CLIENT_PIN:
            DEBUG("CTAP CLIENT PIN \n");
            resp->status = client_pin(&encoder, size,req, should_cancel,
                                      should_cancel_mutex);
            return cbor_encoder_get_buffer_size(&encoder, buf);
            break;
#ifdef CTAP_TESTING
        case CTAP_RESET:
            DEBUG("CTAP RESET \n");
            reset();
            break;
#endif
        default:
            DEBUG("CTAP UNKNOWN PACKET: %u \n", cmd);
            break;
    }

    return 0;
}

static uint8_t get_info(CborEncoder *encoder)
{
    ctap_info_t info;
    memset(&info, 0, sizeof(info));

    info.versions |= CTAP_VERSION_FLAG_FIDO;

    uint8_t aaguid[] = {DEVICE_AAGUID};

    info.aaguid = aaguid;
    info.len = sizeof(aaguid);

    info.options |= CTAP_INFO_OPTIONS_FLAG_PLAT;
    info.options |= CTAP_INFO_OPTIONS_FLAG_RK;
    info.options |= CTAP_INFO_OPTIONS_FLAG_CLIENT_PIN;
    info.options |= CTAP_INFO_OPTIONS_FLAG_UP;

    info.max_msg_size = CTAP_MAX_MSG_SIZE;

    info.pin_protocol = CTAP_PIN_PROT_VER;

    info.pin_is_set = pin_is_set();

    return cbor_helper_encode_info(encoder, &info);
}

/* CTAP specification (version 20190130) section 5.1 */
static uint8_t make_credential(CborEncoder* encoder, size_t size, uint8_t* req_raw,
                              bool *should_cancel, mutex_t *should_cancel_mutex)
{
    int ret;
    ctap_make_credential_req_t req;
    ctap_auth_data_t auth_data;
    ctap_resident_key_t rk;
    bool uv = false;

    memset(&req, 0, sizeof(req));

    ret = cbor_helper_parse_make_credential_req(&req, size, req_raw);

    if (ret != CTAP2_OK) {
        return ret;
    }

    if (pin_is_set() && !req.pin_auth_present) {
        return CTAP2_ERR_PIN_REQUIRED;
    }

    if (pin_is_set() && req.pin_auth_present) {
        ret = verify_pin_auth(req.pin_auth, req.client_data_hash,
                              sizeof(req.client_data_hash));

        if (ret != CTAP2_OK) {
            return ret;
        }

        uv = true;
    }

    DEBUG("Make credential options: %d %d %d \n", req.options.rk,
            req.options.up, req.options.uv);

    /* last moment where transaction can be cancelled */
    mutex_lock(should_cancel_mutex);
    if (*should_cancel) {
        ret = CTAP2_ERR_KEEPALIVE_CANCEL;
    }
    mutex_unlock(should_cancel_mutex);

    if (ret != CTAP2_OK) {
        return ret;
    }

    ret = make_auth_data_attest(&req.rp, &req.user, &req.cred_params, &auth_data, &rk, uv);

    if (ret != CTAP2_OK) {
        return ret;
    }

    ret = cbor_helper_encode_attestation_object(encoder, &auth_data, req.client_data_hash, &rk);

    if (ret != CTAP2_OK) {
        return ret;
    }

    save_rk(&rk);

    return CTAP2_OK;
}

/* CTAP specification (version 20190130) section 5.2 */
static uint8_t get_assertion(CborEncoder *encoder, size_t size, uint8_t *req_raw,
                             bool *should_cancel, mutex_t *should_cancel_mutex)
{
    int ret;
    bool valid_found = false;
    bool uv = false;
    uint8_t valid_count = 0;
    ctap_get_assertion_req_t req;
    ctap_resident_key_t rk;
    ctap_auth_data_header_t auth_data;
    ctap_cred_desc_t cred_desc;

    memset(&req, 0, sizeof(req));

    ret = cbor_helper_parse_get_assertion_req(&req, size, req_raw);

    if (ret != CTAP2_OK) {
        return ret;
    }

    for (size_t i = 0; i < req.allow_list_len; i++) {
        ret = parse_cred_desc(&req.allow_list, &cred_desc);

        if (ret != CTAP2_OK) {
            return ret;
        }

        if (is_valid_credential(&cred_desc, &rk)) {
            valid_found = true;
            valid_count++;
        }
    }

    if (!valid_found) {
        return CTAP2_ERR_NO_CREDENTIALS;
    }

    if (pin_is_set() && !req.pin_auth_present) {
        uv = false;
    }

    if (pin_is_set() && req.pin_auth_present) {
        ret = verify_pin_auth(req.pin_auth, req.client_data_hash,
                              sizeof(req.client_data_hash));

        if (ret != CTAP2_OK) {
            return ret;
        }

        uv = true;
    }

    /* last moment where transaction can be cancelled */
    mutex_lock(should_cancel_mutex);
    if (*should_cancel) {
        ret = CTAP2_ERR_KEEPALIVE_CANCEL;
    }
    mutex_unlock(should_cancel_mutex);

    if (ret != CTAP2_OK) {
        return ret;
    }

    ret = make_auth_data_assert(req.rp_id, req.rp_id_len, &auth_data, uv);

    if (ret != CTAP2_OK) {
        return ret;
    }

    ret = cbor_helper_encode_assertion_object(encoder, &auth_data, req.client_data_hash,
                                              &rk, valid_count);

    if (ret != CTAP2_OK) {
        return ret;
    }

    return CTAP2_OK;
}

/* CTAP specification (version 20190130) section 5.5 */
static uint8_t client_pin(CborEncoder *encoder, size_t size, uint8_t *req_raw,
                          bool *should_cancel, mutex_t *should_cancel_mutex)
{
    int ret;
    ctap_client_pin_req_t req;
    (void)should_cancel;
    (void)should_cancel_mutex;

    memset(&req, 0, sizeof(req));

    ret = cbor_helper_parse_client_pin_req(&req, size, req_raw);

    if (ret != CTAP2_OK) {
        DEBUG("Error parsing client_pin request: %d \n", ret);
        return ret;
    }

    if (req.pin_protocol != 1 || req.sub_command == 0) {
        return CTAP1_ERR_OTHER;
    }

    switch (req.sub_command) {
        case CTAP_CP_REQ_SUB_COMMAND_GET_RETRIES:
            ret = get_retries(encoder);
            break;
        case CTAP_CP_REQ_SUB_COMMAND_GET_KEY_AGREEMENT:
            ret = key_agreement(encoder);
            break;
        case CTAP_CP_REQ_SUB_COMMAND_SET_PIN:
            ret = set_pin(&req);
            break;
        case CTAP_CP_REQ_SUB_COMMAND_CHANGE_PIN:
            ret = change_pin(&req);
            break;
        case CTAP_CP_REQ_SUB_COMMAND_GET_PIN_TOKEN:
            ret = get_pin_token(encoder, &req);
            break;
        default:
            DEBUG("Clientpin subcommand unknown command: %u \n", req.sub_command);
    }

    return ret;
}

static uint8_t get_retries(CborEncoder *encoder)
{
    return cbor_helper_encode_retries(encoder, get_remaining_pin_attempts());
}

static uint8_t change_pin(ctap_client_pin_req_t *req, bool *should_cancel, mutex_t *should_cancel_mutex)
{
    sha256_context_t ctx;
    hmac_context_t ctx2;
    int ret, len;
    uint8_t shared_key[CTAP_KEY_LEN];
    uint8_t pin_hash_dec[CTAP_PIN_TOKEN_SIZE];
    uint8_t pin_hash_dec_final[SHA256_DIGEST_LENGTH];
    uint8_t hmac[SHA256_DIGEST_LENGTH];
    uint8_t new_pin_dec[CTAP_PIN_MAX_SIZE];

    if (!pin_is_set()) {
        return CTAP2_ERR_PIN_NOT_SET;
    }

    if (get_remaining_pin_attempts() <= 0) {
        return CTAP2_ERR_PIN_BLOCKED;
    }

    if (!req->pin_auth_present || !req->key_agreement_present || !req->pin_hash_enc_present) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    if (req->new_pin_enc_size < 64) {
        return CTAP1_ERR_OTHER;
    }

    ctap_crypto_derive_key(shared_key, sizeof(shared_key), &req->key_agreement);

    hmac_sha256_init(&ctx2, shared_key, sizeof(shared_key));
    hmac_sha256_update(&ctx2, req->new_pin_enc, req->new_pin_enc_size);
    hmac_sha256_update(&ctx2, req->pin_hash_enc, sizeof(req->pin_hash_enc));
    hmac_sha256_final(&ctx2, hmac);

    if (memcmp(hmac, req->pin_auth, 16) != 0) {
        DEBUG("Err: pin hmac and pin_auth differ \n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    len = sizeof(pin_hash_dec);
    ret = ctap_crypto_aes_dec(pin_hash_dec, &len, req->pin_hash_enc,
            sizeof(req->pin_hash_enc), shared_key, sizeof(shared_key));

    if (ret != CTAP2_OK) {
        DEBUG("set pin: error while decrypting pin hash \n");
        return ret;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, pin_hash_dec, 16);
    sha256_update(&ctx, g_state.pin_salt, sizeof(g_state.pin_salt));
    sha256_final(&ctx, pin_hash_dec_final);

    if (memcmp(pin_hash_dec_final, g_state.pin_hash, 16) != 0) {
        DEBUG("get_pin_token: invalid pin \n");
        ctap_crypto_reset_key_agreement();
        save_state(&g_state);

        ret = decrement_pin_attempts();

        if (ret != CTAP2_OK) {
            return ret;
        }

        return CTAP2_ERR_PIN_INVALID;
    }

    reset_pin_attempts();

    len = sizeof(new_pin_dec);
    ret = ctap_crypto_aes_dec(new_pin_dec, &len, req->new_pin_enc,
                         req->new_pin_enc_size, shared_key, sizeof(shared_key));

    if (ret != CTAP2_OK) {
        DEBUG("set pin: error while decrypting PIN \n");
        return ret;
    }

    DEBUG("BIN DEC: %s \n", (char*)new_pin_dec);

    len = fmt_strnlen((char*)new_pin_dec, CTAP_PIN_MAX_SIZE);
    if (len < CTAP_PIN_MIN_SIZE) {
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }

     /* last moment where transaction can be cancelled */
    mutex_lock(should_cancel_mutex);
    if (*should_cancel) {
        ret = CTAP2_ERR_KEEPALIVE_CANCEL;
    }
    mutex_unlock(should_cancel_mutex);

    ret = save_pin(new_pin_dec, (size_t)len);

    return CTAP2_OK;
}

static uint8_t set_pin(ctap_client_pin_req_t *req, bool *should_cancel, mutex_t *should_cancel_mutex)
{
    uint8_t shared_key[CTAP_KEY_LEN];
    uint8_t hmac[SHA256_DIGEST_LENGTH];
    uint8_t new_pin_dec[CTAP_PIN_MAX_SIZE];
    int new_pin_dec_len = sizeof(new_pin_dec);
    int ret;
    //todo: check if pin is already set, error if it is.

    if (pin_is_set()) {
        return CTAP2_ERR_NOT_ALLOWED;
    }

    if (req->new_pin_enc_size < 64) {
        return CTAP1_ERR_OTHER;
    }

    if (!req->new_pin_enc_size || !req->pin_auth_present ||
        !req->key_agreement_present) {
            return CTAP2_ERR_NOT_ALLOWED;
    }

    ctap_crypto_derive_key(shared_key, sizeof(shared_key), &req->key_agreement);

    hmac_sha256(shared_key, sizeof(shared_key), req->new_pin_enc,
                req->new_pin_enc_size, hmac);

    if (memcmp(hmac, req->pin_auth, 16) != 0) {
        DEBUG("Err: Set pin hmac and pin_auth differ \n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    ret = ctap_crypto_aes_dec(new_pin_dec, &new_pin_dec_len, req->new_pin_enc,
                         req->new_pin_enc_size, shared_key, sizeof(shared_key));

    if (ret != CTAP2_OK) {
        DEBUG("set pin: error while decrypting PIN \n");
        return ret;
    }

    DEBUG("BIN DEC: %s \n", (char*)new_pin_dec);

    new_pin_dec_len = fmt_strnlen((char*)new_pin_dec, CTAP_PIN_MAX_SIZE);
    if (new_pin_dec_len < CTAP_PIN_MIN_SIZE) {
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }

     /* last moment where transaction can be cancelled */
    mutex_lock(should_cancel_mutex);
    if (*should_cancel) {
        ret = CTAP2_ERR_KEEPALIVE_CANCEL;
    }
    mutex_unlock(should_cancel_mutex);

    ret = save_pin(new_pin_dec, (size_t)new_pin_dec_len);

    return CTAP2_OK;
}

static uint8_t get_pin_token(CborEncoder *encoder, ctap_client_pin_req_t *req)
{
    sha256_context_t ctx;
    uint8_t shared_key[CTAP_KEY_LEN];
    uint8_t pin_hash_dec[CTAP_PIN_TOKEN_SIZE];
    uint8_t pin_hash_dec_final[SHA256_DIGEST_LENGTH];
    uint8_t pin_token_enc[CTAP_PIN_TOKEN_SIZE];
    int len, ret;

    if (!pin_is_set()) {
        return CTAP2_ERR_PIN_NOT_SET;
    }

    if (!req->key_agreement_present || !req->pin_hash_enc_present) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    if (get_remaining_pin_attempts() == 0) {
        return CTAP2_ERR_PIN_BLOCKED;
    }

    ctap_crypto_derive_key(shared_key, sizeof(shared_key), &req->key_agreement);

    len = sizeof(pin_hash_dec);
    ret = ctap_crypto_aes_dec(pin_hash_dec, &len, req->pin_hash_enc,
            sizeof(req->pin_hash_enc), shared_key, sizeof(shared_key));

    if (ret != CTAP2_OK) {
        DEBUG("set pin: error while decrypting pin hash \n");
        return ret;
    }

    DEBUG("Pin hash: ");
    print_hex(pin_hash_dec, sizeof(pin_hash_dec));

    sha256_init(&ctx),
    sha256_update(&ctx, pin_hash_dec, 16);
    sha256_update(&ctx, g_state.pin_salt, sizeof(g_state.pin_salt));
    sha256_final(&ctx, pin_hash_dec_final);

    if (memcmp(pin_hash_dec_final, g_state.pin_hash, 16) != 0) {
        DEBUG("get_pin_token: invalid pin \n");
        ctap_crypto_reset_key_agreement();
        save_state(&g_state);

        ret = decrement_pin_attempts();

        if (ret != CTAP2_OK) {
            return ret;
        }

        return CTAP2_ERR_PIN_INVALID;
    }

    reset_pin_attempts();
    save_state(&g_state);

    len = sizeof(pin_token_enc);
    ret = ctap_crypto_aes_enc(pin_token_enc, &len, g_pin_token,
                   sizeof(g_pin_token), shared_key, sizeof(shared_key));

    if (ret != CTAP2_OK) {
        DEBUG("get pin token: error encrypting pin token \n");
        return ret;
    }

    return cbor_helper_encode_pin_token(encoder, pin_token_enc, sizeof(pin_token_enc));
}

static uint8_t save_pin(uint8_t *pin, size_t len)
{
    uint8_t temp_hash[SHA256_DIGEST_LENGTH];
    sha256_context_t ctx;

    sha256(pin, len, temp_hash);

    sha256_init(&ctx),
    sha256_update(&ctx, temp_hash, 16);
    sha256_update(&ctx, g_state.pin_salt, sizeof(g_state.pin_salt));
    sha256_final(&ctx, g_state.pin_hash);

    g_state.pin_is_set = true;

    save_state(&g_state);

    return CTAP2_OK;
}

static uint8_t key_agreement(CborEncoder *encoder)
{
    ctap_cose_key_t key;

    ctap_crypto_get_key_agreement(&key);

    key.alg_type = CTAP_COSE_ALG_ECDH_ES_HKDF_256;
    key.cred_type = CTAP_PUB_KEY_CRED_PUB_KEY;
    key.crv = CTAP_COSE_KEY_CRV_P256;
    key.kty = CTAP_COSE_KEY_KTY_EC2;

    return cbor_helper_encode_key_agreement(encoder, &key);
}

static uint8_t is_valid_credential(ctap_cred_desc_t *cred_desc, ctap_resident_key_t *rk)
{
    // todo: implement proper handling of rk
    memset(rk, 0, sizeof(ctap_resident_key_t));

    load_rk(rk);

    return  memcmp(cred_desc->cred_id, rk->cred_desc.cred_id,
            sizeof(cred_desc->cred_id)) == 0;

}

/* todo: properly handle all kind of flash memory access */
static void save_rk(ctap_resident_key_t *rk)
{
    int ret;
    uint8_t page[FLASHPAGE_SIZE];

    memmove(page, rk, sizeof(*rk));

    ret = flashpage_write_and_verify(20, page);

    (void)ret;
}

static void load_rk(ctap_resident_key_t *rk)
{
    uint8_t page[FLASHPAGE_SIZE];

    flashpage_read(20, page);

    memmove(rk, page, sizeof(*rk));
}

static void save_state(ctap_state_t * state)
{
    int ret;
    uint8_t page[FLASHPAGE_SIZE];

    memmove(page, state, sizeof(*state));

    ret = flashpage_write_and_verify(19, page);

    (void)ret;
}

/**
 * todo: implement memory corruption detection by checking a (backup?) value
 * somewhere else in flash. If this value exists but state->is_intialized
 * does not equal the initialization marker, memory is probably corrupted.
 * (because backup value will only exist if has been initialized)
 */
static void load_state(ctap_state_t *state)
{
    uint8_t page[FLASHPAGE_SIZE];

    flashpage_read(19, page);

    memmove(state, page, sizeof(*state));
}

static uint8_t make_auth_data_assert(uint8_t *rp_id, size_t rp_id_len, ctap_auth_data_header_t *auth_data, bool uv)
{
    memset(auth_data, 0, sizeof(*auth_data));

    /* sha256 of relying party id */
    sha256(rp_id, rp_id_len, auth_data->rp_id_hash);

    /* get sign counter */
    uint32_t counter = 0;
    get_auth_data_sign_count(&counter);
    auth_data->counter = counter;

    /* todo: faking user presence for now */
    auth_data->flags |= CTAP_AUTH_DATA_FLAG_UP;

    if (uv) {
        auth_data->flags |= CTAP_AUTH_DATA_FLAG_UV;
    }

    return CTAP2_OK;
}

static uint8_t make_auth_data_attest(ctap_rp_ent_t *rp, ctap_user_ent_t *user, ctap_pub_key_cred_params_t *cred_params,
                              ctap_auth_data_t* auth_data, ctap_resident_key_t *rk, bool uv)
{
    int ret;
    uint32_t counter = 0;
     /* device aaguid */
    uint8_t aaguid[] = {DEVICE_AAGUID};

    memset(auth_data, 0, sizeof(*auth_data));
    ctap_auth_data_header_t *auth_header = &auth_data->header;
    ctap_attested_cred_data_t *cred_data = &auth_data->attested_cred_data;
    ctap_attested_cred_data_header_t *cred_header = &cred_data->header;

    /* sha256 of relying party id */
    sha256(rp->id, rp->id_len, auth_header->rp_id_hash);
    /* set flag indicating that attested credential data included */
    auth_header->flags |= CTAP_AUTH_DATA_FLAG_AT;

    /* todo: faking user presence because it is necessary for registration */
    auth_header->flags |= CTAP_AUTH_DATA_FLAG_UP;

    if (uv) {
        auth_header->flags |= CTAP_AUTH_DATA_FLAG_UV;
    }

    /* get sign counter */
    get_auth_data_sign_count(&counter);
    auth_header->counter = counter;

    memmove(cred_header->aaguid, &aaguid, sizeof(cred_header->aaguid));

    /* generate credential id */
    ctap_crypto_prng(cred_header->cred_id, sizeof(cred_header->cred_id));
    cred_header->cred_len_h = (sizeof(cred_header->cred_id) & 0xff00) >> 8;
    cred_header->cred_len_l = sizeof(cred_header->cred_id) & 0x00ff;

    ret = ctap_crypto_gen_keypair(&cred_data->key, rk->priv_key);

    if (ret != CTAP2_OK) {
        return ret;
    }

    cred_data->key.alg_type = cred_params->alg_type;
    cred_data->key.cred_type = cred_params->cred_type;
    cred_data->key.crv = CTAP_COSE_KEY_CRV_P256;
    cred_data->key.kty = CTAP_COSE_KEY_KTY_EC2;

    /* init resident key struct */
    memmove(rk->rp_id_hash, auth_header->rp_id_hash, sizeof(rk->rp_id_hash));
    memmove(rk->cred_desc.cred_id, cred_header->cred_id, sizeof(rk->cred_desc.cred_id));
    memmove(rk->user_id, user->id, user->id_len);
    rk->cred_desc.cred_type = cred_params->cred_type;
    rk->user_id_len = user->id_len;

    return CTAP2_OK;
}

// https://wiki.openssl.org/index.php/DER
// http://luca.ntop.org/Teaching/Appunti/asn1.html
// https://www.w3.org/TR/webauthn/#packed-attestation
uint8_t ctap_get_attest_sig(uint8_t *auth_data, size_t auth_data_len, uint8_t *client_data_hash,
                            ctap_resident_key_t *rk, uint8_t* sig, size_t *sig_len)
{
    sha256_context_t ctx;
    uint8_t hash[SHA256_DIGEST_LENGTH];

    sha256_init(&ctx);
    sha256_update(&ctx, auth_data, auth_data_len);
    sha256_update(&ctx, client_data_hash, SHA256_DIGEST_LENGTH);
    sha256_final(&ctx, hash);

    return ctap_crypto_get_sig(hash, sizeof(hash), sig, sig_len, rk->priv_key,
                        sizeof(rk->priv_key));

}
