
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

#include "byteorder.h"

#include "periph/gpio.h"

#define CTAP_TESTING 1

static uint8_t get_info(CborEncoder *encoder);
static uint8_t make_credential(CborEncoder* encoder, size_t size, uint8_t* req_raw,
                               bool (*should_cancel)(void));
static uint8_t make_auth_data_attest(ctap_rp_ent_t *rp, ctap_user_ent_t *user,
                                     ctap_pub_key_cred_params_t *cred_params,
                                     ctap_auth_data_t* auth_data,
                                     ctap_resident_key_t *rk ,bool uv);
static uint8_t make_auth_data_assert(uint8_t * rp_id, size_t rp_id_len,
                                    ctap_auth_data_header_t *auth_data, bool uv,
                                    bool up, uint32_t sign_count);
static uint8_t get_assertion(CborEncoder *encoder, size_t size, uint8_t *req_raw,
                             bool (*should_cancel)(void));
static uint8_t client_pin(CborEncoder *encoder, size_t size, uint8_t *req_raw,
                          bool (*should_cancel)(void));
static uint8_t set_pin(ctap_client_pin_req_t *req, bool (*should_cancel)(void));
static uint8_t change_pin(ctap_client_pin_req_t *req, bool (*should_cancel)(void));
static uint8_t get_retries(CborEncoder *encoder);
static uint8_t get_pin_token(CborEncoder *encoder, ctap_client_pin_req_t *req,
                             bool (*should_cancel)(void));
static uint8_t key_agreement(CborEncoder *encoder);
static uint8_t save_rk(ctap_resident_key_t *rk);
static uint8_t load_rk(uint16_t index, ctap_resident_key_t *rk);
static uint8_t save_pin(uint8_t *pin, size_t len);
static void save_state(ctap_state_t *state);
static void load_state(ctap_state_t *state);
static bool pin_is_set(void);
static uint8_t get_remaining_pin_attempts(void);
static uint8_t decrement_pin_attempts(void);
static void reset_pin_attempts(void);
static void reset(void);
static uint8_t verify_pin_auth(uint8_t *auth, uint8_t *hash, size_t len);
static bool locked(void);
static bool boot_locked(void);
static uint8_t user_presence_test(void);
static void gpio_cb(void *arg);
static uint16_t find_matching_rk(ctap_resident_key_t *rk, ctap_cred_desc_t *allow_list,
                          size_t allow_list_len, uint8_t* rp_id, size_t rp_id_len);
static bool rks_are_equal(ctap_resident_key_t *rk1, ctap_resident_key_t *rk2);

static ctap_state_t g_state;
static uint8_t g_pin_token[CTAP_PIN_TOKEN_SIZE];
static uint8_t g_rem_pin_att_boot = CTAP_PIN_MAX_ATTS_BOOT;
static bool g_user_present = false;

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
    g_state.rk_amount_stored = 0;

    save_state(&g_state);
}

static void gpio_cb(void *arg)
{
    (void)arg;

    g_user_present = true;
}

static uint8_t user_presence_test(void)
{
#ifdef BTN0_PIN
    uint8_t ret;
    uint32_t start;
    uint32_t diff = 0;
    uint32_t delay = (500 * US_PER_MS);

    ctap_hid_send_keepalive(CTAP_HID_STATUS_UPNEEDED);

    if (gpio_init_int(BTN0_PIN, BTN0_MODE, GPIO_FALLING, gpio_cb, NULL) < 0) {
        return CTAP1_ERR_OTHER;
    }

    start = xtimer_now_usec();

    while (!g_user_present && diff < CTAP_UP_TIMEOUT) {
#ifdef LED0_TOGGLE
        LED0_TOGGLE;
#endif
#ifdef LED1_TOGGLE
        LED1_TOGGLE;
#endif
#ifdef LED3_TOGGLE
        LED3_TOGGLE;
#endif
#ifdef LED2_TOGGLE
        LED2_TOGGLE;
#endif
        xtimer_usleep(delay);

        diff = xtimer_now_usec() - start;
    }

#ifdef LED0_TOGGLE
        LED0_OFF;
#endif
#ifdef LED1_TOGGLE
        LED1_OFF;
#endif
#ifdef LED3_TOGGLE
        LED3_OFF;
#endif
#ifdef LED2_TOGGLE
        LED2_OFF;
#endif

    ret = g_user_present ? CTAP2_OK : CTAP2_ERR_ACTION_TIMEOUT;
    gpio_irq_disable(BTN0_PIN);
    g_user_present = false;
    return ret;
#else
    return CTAP1_ERR_OTHER;
#endif
}

bool ctap_cred_params_supported(uint8_t cred_type, int32_t alg_type)
{
    if (cred_type == CTAP_PUB_KEY_CRED_PUB_KEY) {
        if (alg_type == CTAP_COSE_ALG_ES256) {
            return true;
        }
    }

    return false;
}

static bool pin_is_set(void)
{
    return g_state.pin_is_set;
}

static bool locked(void)
{
    return g_state.rem_pin_att == 0;
}

static bool boot_locked(void)
{
    return g_state.rem_pin_att_boot == 0;
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

static void print_hex(uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        DEBUG("%02x", data[i]);
    }

    DEBUG("\n");
}

size_t ctap_handle_request(uint8_t* req, size_t size, ctap_resp_t* resp,
                           bool (*should_cancel)(void))
{
    DEBUG("ctap handle request %u \n ", size);

    CborEncoder encoder;
    uint8_t cmd = *req;
    uint8_t* buf = resp->data;
    req++;
    size--;

    memset(&encoder, 0, sizeof(CborEncoder));

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
            resp->status = make_credential(&encoder, size, req, should_cancel);
            print_hex(buf, cbor_encoder_get_buffer_size(&encoder, buf));
            return cbor_encoder_get_buffer_size(&encoder, buf);
            break;
        case CTAP_GET_ASSERTION:
            DEBUG("CTAP GET_ASSERTION \n");
            resp->status = get_assertion(&encoder, size, req, should_cancel);
            DEBUG("get assertion resp: ");
            print_hex(buf, cbor_encoder_get_buffer_size(&encoder, buf));
            return cbor_encoder_get_buffer_size(&encoder, buf);
            break;
        case CTAP_GET_NEXT_ASSERTION:
            DEBUG("CTAP GET NEXT ASSERTION \n");
            break;
        case CTAP_CLIENT_PIN:
            DEBUG("CTAP CLIENT PIN \n");
            resp->status = client_pin(&encoder, size,req, should_cancel);
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
            resp->status = CTAP1_ERR_INVALID_COMMAND;
            return 0;
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
                              bool (*should_cancel)(void))
{
    int ret;
    ctap_make_credential_req_t req;
    ctap_auth_data_t auth_data;
    ctap_resident_key_t rk;
    bool uv = false;

    if (locked()) {
        return  CTAP2_ERR_PIN_BLOCKED;
    }

    if (boot_locked()) {
        return CTAP2_ERR_PIN_AUTH_BLOCKED;
    }

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
    if (should_cancel()) {
        return CTAP2_ERR_KEEPALIVE_CANCEL;
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

/* find most recent rk matching rp_id_hash and present in allow_list */
static uint16_t find_matching_rk(ctap_resident_key_t *rk, ctap_cred_desc_t *allow_list,
                          size_t allow_list_len, uint8_t* rp_id, size_t rp_id_len)
{
    uint16_t found = 0;
    uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
    ctap_resident_key_t rk_temp;

    size_t index_min_count = 0;
    uint32_t min_count = 0xffffffff;

    sha256(rp_id, rp_id_len, rp_id_hash);

    for (uint16_t i = 0; i < g_state.rk_amount_stored; i++) {
        memset(&rk_temp, 0, sizeof(rk_temp));
        load_rk(i, &rk_temp);

        /* search for rk's matching rp_id_hash */
        if (memcmp(rk_temp.rp_id_hash, rp_id_hash, SHA256_DIGEST_LENGTH) == 0) {

            /* if allow list, also check that cred_id matches */
            if (allow_list_len > 0) {
                for (size_t j = 0; j < allow_list_len; j++) {
                    if (memcmp(allow_list[j].cred_id, rk_temp.cred_desc.cred_id,
                        sizeof(allow_list[j].cred_id)) == 0) {

                            if (rk_temp.sign_count < min_count) {
                                index_min_count = i;
                                min_count = rk_temp.sign_count;
                            }
                            found++;
                            break;
                    }
                }
            }
            else {
                if (rk_temp.sign_count < min_count) {
                    index_min_count = i;
                    min_count = rk_temp.sign_count;
                }
                found++;
            }
        }
    }

    if (found) {
        load_rk(index_min_count, rk);
    }

    DEBUG("FIND MATCHING RK: %u %lu\n", found, min_count);

    return found;
}

/* CTAP specification (version 20190130) section 5.2 */
static uint8_t get_assertion(CborEncoder *encoder, size_t size, uint8_t *req_raw,
                             bool (*should_cancel)(void))
{
    int ret;
    bool uv = false, up = false;
    uint16_t valid_count = 0;
    ctap_get_assertion_req_t req;
    ctap_resident_key_t rk;
    ctap_auth_data_header_t auth_data;
    ctap_cred_desc_t allow_list[CTAP_MAX_ALLOW_LIST_SIZE];

    if (locked()) {
        return  CTAP2_ERR_PIN_BLOCKED;
    }

    if (boot_locked()) {
        return CTAP2_ERR_PIN_AUTH_BLOCKED;
    }

    memset(&req, 0, sizeof(req));

    ret = cbor_helper_parse_get_assertion_req(&req, size, req_raw);

    if (ret != CTAP2_OK) {
        return ret;
    }

    if (req.allow_list_len > CTAP_MAX_ALLOW_LIST_SIZE) {
        req.allow_list_len = CTAP_MAX_ALLOW_LIST_SIZE;
    }

    for (uint8_t i = 0; i < req.allow_list_len; i++) {
        ret = parse_cred_desc(&req.allow_list, &allow_list[i]);

        if (ret != CTAP2_OK) {
            return ret;
        }
    }

    valid_count = find_matching_rk(&rk, allow_list, req.allow_list_len,
                                    req.rp_id, req.rp_id_len);


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

     /* todo: add macro to disable user presence test */
    if (user_presence_test() == CTAP2_OK) {
        up = true;
    }

    if (!valid_count) {
        return CTAP2_ERR_NO_CREDENTIALS;
    }

    if (req.options.uv) {
        return CTAP2_ERR_UNSUPPORTED_OPTION;
    }

    /* last moment where transaction can be cancelled */
    if (should_cancel()) {
        return CTAP2_ERR_KEEPALIVE_CANCEL;
    }

    ret = make_auth_data_assert(req.rp_id, req.rp_id_len, &auth_data, uv, up,
                                rk.sign_count);

    if (ret != CTAP2_OK) {
        return ret;
    }

    ret = cbor_helper_encode_assertion_object(encoder, &auth_data, req.client_data_hash,
                                              &rk, valid_count);

    if (ret != CTAP2_OK) {
        return ret;
    }

    /* webauthn specification (version 20190304) section 6.1.1 */
    rk.sign_count++;

    return CTAP2_OK;
}

/* CTAP specification (version 20190130) section 5.5 */
static uint8_t client_pin(CborEncoder *encoder, size_t size, uint8_t *req_raw,
                          bool (*should_cancel)(void))
{
    int ret;
    ctap_client_pin_req_t req;

    if (locked()) {
        return CTAP2_ERR_PIN_BLOCKED;
    }

    if (boot_locked()) {
        return CTAP2_ERR_PIN_AUTH_BLOCKED;
    }

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
            ret = set_pin(&req, should_cancel);
            break;
        case CTAP_CP_REQ_SUB_COMMAND_CHANGE_PIN:
            ret = change_pin(&req, should_cancel);
            break;
        case CTAP_CP_REQ_SUB_COMMAND_GET_PIN_TOKEN:
            ret = get_pin_token(encoder, &req, should_cancel);
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

static uint8_t change_pin(ctap_client_pin_req_t *req, bool (*should_cancel)(void))
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

    /* last moment where transaction can be cancelled */
    if (should_cancel()) {
        return CTAP2_ERR_KEEPALIVE_CANCEL;
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

    ret = save_pin(new_pin_dec, (size_t)len);

    return CTAP2_OK;
}

static uint8_t set_pin(ctap_client_pin_req_t *req, bool (*should_cancel)(void))
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

    /* last moment where transaction can be cancelled */
    if (should_cancel()) {
        DEBUG("Client pin: cancelling request \n");
        return CTAP2_ERR_KEEPALIVE_CANCEL;
    }

    DEBUG("BIN DEC: %s \n", (char*)new_pin_dec);

    new_pin_dec_len = fmt_strnlen((char*)new_pin_dec, CTAP_PIN_MAX_SIZE);
    if (new_pin_dec_len < CTAP_PIN_MIN_SIZE) {
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }

    ret = save_pin(new_pin_dec, (size_t)new_pin_dec_len);

    return CTAP2_OK;
}

static uint8_t get_pin_token(CborEncoder *encoder, ctap_client_pin_req_t *req,
                             bool (*should_cancel)(void))
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

    /* last moment where transaction can be cancelled */
    if (should_cancel()) {
        return CTAP2_ERR_KEEPALIVE_CANCEL;
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

static bool rks_are_equal(ctap_resident_key_t *rk1, ctap_resident_key_t *rk2)
{
    return memcmp(rk1->rp_id_hash, rk2->rp_id_hash, sizeof(rk1->rp_id_hash)) == 0 &&
           memcmp(rk1->user_id, rk2->user_id, sizeof(rk1->user_id)) == 0;
}

/**
 * overwrite existing key if equal, else find free space.
 *
 * CTAP2 does not have credential management yet, so rk's can't be deleted,
 * only overwritten. Therefore we can be sure, that rk's are stored
 * sequentially.
 */
static uint8_t save_rk(ctap_resident_key_t *rk)
{
    uint16_t page_offset, page_offset_into_page;
    uint8_t page[FLASHPAGE_SIZE];
    ctap_resident_key_t rk_temp;

    DEBUG("MAX AMOUNT WE CAN STORE %u %u \n", CTAP_MAX_RK, sizeof(*rk));

    if (g_state.rk_amount_stored >= CTAP_MAX_RK) {
        return CTAP2_ERR_KEY_STORE_FULL;
    }

    for (uint16_t i = 0; i <= g_state.rk_amount_stored; i++) {
        page_offset = i / (FLASHPAGE_SIZE / sizeof(ctap_resident_key_t));
        page_offset_into_page = sizeof(ctap_resident_key_t) * (i % \
                                (FLASHPAGE_SIZE / sizeof(ctap_resident_key_t)));

        if (page_offset_into_page == 0) {
            memset(page, 0, sizeof(page));
            flashpage_read(CTAP_RK_START_PAGE + page_offset, page);
        }

        memmove(&rk_temp, page + page_offset_into_page, sizeof(rk_temp));

        if (rks_are_equal(&rk_temp, rk)) {
            break;
        }
    }

    memmove(page + page_offset_into_page, rk, sizeof(*rk));

    flashpage_write_and_verify(CTAP_RK_START_PAGE + page_offset, page);

    g_state.rk_amount_stored++;
    save_state(&g_state);

    return CTAP2_OK;
}

static uint8_t load_rk(uint16_t index, ctap_resident_key_t *rk)
{
    uint16_t page_offset = index / (FLASHPAGE_SIZE / sizeof(ctap_resident_key_t));
    uint16_t page_offset_into_page = sizeof(ctap_resident_key_t) * (index % \
                                (FLASHPAGE_SIZE / sizeof(ctap_resident_key_t)));
    uint8_t page[FLASHPAGE_SIZE];

    if (g_state.rk_amount_stored >= CTAP_MAX_RK) {
        return CTAP2_ERR_KEY_STORE_FULL;
    }

    memset(page, 0, sizeof(page));

    flashpage_read(CTAP_RK_START_PAGE + page_offset, page);

    memmove(rk, page + page_offset_into_page, sizeof(*rk));

    return CTAP2_OK;
}

static void save_state(ctap_state_t * state)
{
    uint8_t page[FLASHPAGE_SIZE];
    memset(page, 0, sizeof(page));

    memmove(page, state, sizeof(*state));

    flashpage_write_and_verify(CTAP_RK_START_PAGE - 1, page);
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

static uint8_t make_auth_data_assert(uint8_t *rp_id, size_t rp_id_len,
                                    ctap_auth_data_header_t *auth_data, bool uv,
                                    bool up, uint32_t sign_count)
{
    memset(auth_data, 0, sizeof(*auth_data));

    /* sha256 of relying party id */
    sha256(rp_id, rp_id_len, auth_data->rp_id_hash);

    /* sign_count to network byte order */
    auth_data->sign_count = htonl(sign_count);

    if (up) {
        auth_data->flags |= CTAP_AUTH_DATA_FLAG_UP;
    }

    if (uv) {
        auth_data->flags |= CTAP_AUTH_DATA_FLAG_UV;
    }

    return CTAP2_OK;
}

static uint8_t make_auth_data_attest(ctap_rp_ent_t *rp, ctap_user_ent_t *user,
                                    ctap_pub_key_cred_params_t *cred_params,
                                    ctap_auth_data_t* auth_data,
                                    ctap_resident_key_t *rk,
                                    bool uv)
{
    int ret;
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

    auth_header->sign_count = 0;

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
