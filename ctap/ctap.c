
#define ENABLE_DEBUG    (1)
#include "debug.h"

#include <string.h>

#include "fmt.h"

#include "ctap.h"

#include "ctap_hid.h"

#include "cbor_helper.h"

#include "xtimer.h"

#include "periph/flashpage.h"

#include "relic.h"

#include "rijndael-api-fst.h"

#define CTAP_TESTING 1

static uint8_t make_credential(CborEncoder* encoder, size_t size, uint8_t* req_raw,
                                bool *should_cancel, mutex_t *should_cancel_mutex);
static uint8_t make_auth_data_attest(ctap_rp_ent_t *rp, ctap_user_ent_t *user,
                                     ctap_pub_key_cred_params_t *cred_params,
                              ctap_auth_data_t* auth_data, ctap_resident_key_t *rk);
static uint8_t make_auth_data_assert(uint8_t * rp_id, size_t rp_id_len,
                                    ctap_auth_data_header_t *auth_data);
static uint8_t get_assertion(CborEncoder *encoder, size_t size, uint8_t *req_raw,
                             bool *should_cancel, mutex_t *should_cancel_mutex);
static uint8_t client_pin(CborEncoder *encoder, size_t size, uint8_t *req_raw,
                          bool *should_cancel, mutex_t *should_cancel_mutex);
static uint8_t set_pin(ctap_client_pin_req_t *req);
static uint8_t get_pin_token(CborEncoder *encoder, ctap_client_pin_req_t *req);
static uint32_t get_auth_data_sign_count(uint32_t* auth_data_counter);
static uint8_t key_agreement(CborEncoder *encoder);
static void generate_random_sequence(uint8_t *dst, size_t len);
static uint8_t sig_to_der_format(bn_t r, bn_t s, uint8_t* buf, size_t *sig_len);
static void save_rk(ctap_resident_key_t *rk);
static void load_rk(ctap_resident_key_t *rk);
static uint8_t save_pin(uint8_t *pin, size_t len);
static void save_state(ctap_state_t *state);
static void load_state(ctap_state_t *state);
static uint8_t is_valid_credential(ctap_cred_desc_t *cred_desc, ctap_resident_key_t *rk);
static void get_shared_key(uint8_t *secret, size_t len, ctap_cose_key_t *cose);
static bool pin_is_set(void);
static uint8_t get_remaining_pin_attempts(void);
static void decrement_pin_attempts(void);
static void reset_pin_attempts(void);
static void reset(void);
static int reset_key_agreement(void);
int aes_dec(uint8_t *out, int *out_len, uint8_t *in,
		int in_len, uint8_t *key, int key_len, uint8_t *iv);
/* typedef here because including relic.h in ctap.h results in errors */
typedef struct
{
    ec_t pub;
    bn_t priv;
} ctap_key_agreement_key_t;

static ctap_key_agreement_key_t g_ag_key;
static ctap_state_t g_state;
static uint8_t g_pin_token[CTAP_PIN_TOKEN_SIZE];

void ctap_init(void)
{
    int ret;

    load_state(&g_state);

    if (g_state.initialized != CTAP_INITIALIZED_MARKER) {
        g_state.initialized = CTAP_INITIALIZED_MARKER;
        g_state.remaining_pin_attempts = CTAP_PIN_MAX_ATTEMPTS;
        g_state.pin_is_set = false;
        generate_random_sequence(g_state.pin_salt, sizeof(g_state.pin_salt));

        save_state(&g_state);
    }

     /* init relic */
    core_init();
    rand_init();
    ep_param_set(NIST_P256);

    /**
     * configuration operations upon power up
     * CTAP specification (version 20190130) section 5.5.2
     */
    bn_null(g_ag_key.priv);
    ec_null(g_ag_key.pub);

    bn_new(g_ag_key.priv);
    ec_new(g_ag_key.pub);

    /* get key pair for ECHD key exchange */
    ret = cp_ecdh_gen(g_ag_key.priv, g_ag_key.pub);
    if (ret == STS_ERR) {
        DEBUG("ECDH key pair creation failed. Not good :( \n");
    }

    /* initialize pin_token */
    generate_random_sequence(g_pin_token, sizeof(g_pin_token));
}

static void reset(void)
{
    g_state.initialized = CTAP_INITIALIZED_MARKER;
    g_state.remaining_pin_attempts = CTAP_PIN_MAX_ATTEMPTS;
    g_state.pin_is_set = false;
    generate_random_sequence(g_state.pin_salt, sizeof(g_state.pin_salt));

    save_state(&g_state);
}

static int reset_key_agreement(void)
{
    bn_free(g_ag_key.priv);
    ec_free(g_ag_key.pub);

    bn_null(g_ag_key.priv);
    ec_null(g_ag_key.pub);

    bn_new(g_ag_key.priv);
    ec_new(g_ag_key.pub);

    return cp_ecdh_gen(g_ag_key.priv, g_ag_key.pub);
}

static void generate_random_sequence(uint8_t *dst, size_t len)
{
    /* relic random bytes func */
    rand_bytes(dst, len);
}

static bool pin_is_set(void)
{
    return g_state.pin_is_set;
}

static void decrement_pin_attempts(void)
{
    g_state.remaining_pin_attempts--;
}

static uint8_t get_remaining_pin_attempts(void)
{
    return g_state.remaining_pin_attempts;
}

static void reset_pin_attempts(void)
{
    g_state.remaining_pin_attempts = CTAP_PIN_MAX_ATTEMPTS;
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
            resp->status = cbor_helper_get_info(&encoder);
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

/* CTAP specification (version 20190130) section 5.1 */
static uint8_t make_credential(CborEncoder* encoder, size_t size, uint8_t* req_raw,
                              bool *should_cancel, mutex_t *should_cancel_mutex)
{
    int ret;
    ctap_make_credential_req_t req;
    ctap_auth_data_t auth_data;
    ctap_resident_key_t rk;

    memset(&req, 0, sizeof(req));

    ret = cbor_helper_parse_make_credential_req(&req, size, req_raw);

    if (ret != CTAP2_OK) {
        return ret;
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

    ret = make_auth_data_attest(&req.rp, &req.user, &req.cred_params, &auth_data, &rk);

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

    /* last moment where transaction can be cancelled */
    mutex_lock(should_cancel_mutex);
    if (*should_cancel) {
        ret = CTAP2_ERR_KEEPALIVE_CANCEL;
    }
    mutex_unlock(should_cancel_mutex);

    if (ret != CTAP2_OK) {
        return ret;
    }

    ret = make_auth_data_assert(req.rp_id, req.rp_id_len, &auth_data);

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

    DEBUG("client_pin subcommand: %u \n", req.sub_command);

    if (req.pin_protocol != 1 || req.sub_command == 0) {
        return CTAP1_ERR_OTHER;
    }

    switch (req.sub_command) {
        case CTAP_CP_REQ_SUB_COMMAND_GET_RETRIES:
            break;
        case CTAP_CP_REQ_SUB_COMMAND_GET_KEY_AGREEMENT:
            ret = key_agreement(encoder);
            break;
        case CTAP_CP_REQ_SUB_COMMAND_SET_PIN:
            ret = set_pin(&req);
            break;
        case CTAP_CP_REQ_SUB_COMMAND_CHANGE_PIN:
            break;
        case CTAP_CP_REQ_SUB_COMMAND_GET_PIN_TOKEN:
            ret = get_pin_token(encoder, &req);
            break;
        default:
            DEBUG("Clientpin subcommand unknown command: %u \n", req.sub_command);
    }

    DEBUG("Client_pin resp: %d \n", ret);
    return ret;
}

static void get_shared_key(uint8_t *key, size_t len, ctap_cose_key_t *cose)
{
    /* translate pub_key into relic internal structure */
    uint8_t *x = cose->pubkey.x;
    uint8_t *y = cose->pubkey.y;
    uint8_t sz = sizeof(cose->pubkey.x);
    uint8_t temp[sz * 2 + 1];
    uint8_t temp2[len];
    ec_t pub;
    ec_t sec;

    ec_null(sec);
    ec_null(pub);

    ec_new(sec);
    ec_new(pub);

     /* point is not compressed */
    temp[0] = 0x04;
    memcpy(temp + 1, x, sz);
    memcpy(temp + 1 + sz, y, sz);

    ep_read_bin(pub, temp, sizeof(temp));

    /* multiply local private key with remote public key to obtain shared secret */
    ec_mul(sec, pub, g_ag_key.priv);

    fp_write_bin(temp2, len, sec->x);

    /* sha256 of shared secret x point to obtain shared key */
    sha256(temp2, len, key);

    ec_free(sec);
    ec_free(pub);
}

/* needed because enc pin is not padded but relic's default func expects it to be */
int aes_dec(uint8_t *out, int *out_len, uint8_t *in,
		int in_len, uint8_t *key, int key_len, uint8_t *iv)
{

	keyInstance key_inst;
	cipherInstance cipher_inst;

	if (*out_len < in_len) {
		return STS_ERR;
	}

	if (makeKey2(&key_inst, DIR_DECRYPT, key_len, (char *)key) != TRUE) {
		return STS_ERR;
	}

	if (cipherInit(&cipher_inst, MODE_CBC, NULL) != TRUE) {
		return STS_ERR;
	}

    /* min 1 block */
    if (in_len < 128) {
        in_len = 128;
    }

	memcpy(cipher_inst.IV, iv, BC_LEN);
	*out_len = blockDecrypt(&cipher_inst, &key_inst, in, in_len, out);

	if (*out_len <= 0) {
		return STS_ERR;
	}
	return STS_OK;
}

//todo: could combine set_pin and update_pin into 1 function if it is worth it.
static uint8_t set_pin(ctap_client_pin_req_t *req)
{
    uint8_t shared_key[MD_LEN];
    uint8_t hmac[32];
    uint8_t new_pin_dec[CTAP_PIN_MAX_SIZE];
    int new_pin_dec_len = sizeof(new_pin_dec);
    uint8_t iv[BC_LEN] = {0};
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

    get_shared_key(shared_key, sizeof(shared_key), &req->key_agreement);

    hmac_sha256(shared_key, sizeof(shared_key), req->new_pin_enc,
                req->new_pin_enc_size, hmac);

    if (memcmp(hmac, req->pin_auth, 16) != 0) {
        DEBUG("Err: Set pin hmac and pin_auth differ \n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    ret = aes_dec(new_pin_dec, &new_pin_dec_len, req->new_pin_enc,
                         req->new_pin_enc_size, shared_key, sizeof(shared_key) * 8, iv);


    if (ret == STS_ERR) {
        DEBUG("set pin: error while decrypting PIN \n");
        return CTAP1_ERR_OTHER;
    }

    DEBUG("BIN DEC: %s \n", (char*)new_pin_dec);

    new_pin_dec_len = fmt_strnlen((char*)new_pin_dec, CTAP_PIN_MAX_SIZE);
    if (new_pin_dec_len < CTAP_PIN_MIN_SIZE) {
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }

    ret = save_pin(new_pin_dec, (size_t)new_pin_dec_len);

    return CTAP2_OK;
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
    ctap_public_key_t key;

    fp_write_bin(key.x, sizeof(key.x), g_ag_key.pub->x);
    fp_write_bin(key.y, sizeof(key.y), g_ag_key.pub->y);

    key.params.alg_type = CTAP_COSE_ALG_ECDH_ES_HKDF_256;
    key.params.cred_type = CTAP_PUB_KEY_CRED_PUB_KEY;

    return cbor_helper_encode_key_agreement(encoder, &key);
}

static uint8_t get_pin_token(CborEncoder *encoder, ctap_client_pin_req_t *req)
{
    uint8_t shared_key[MD_LEN];
    sha256_context_t ctx;
    uint8_t pin_hash_dec[CTAP_PIN_TOKEN_SIZE];
    int len;
    uint8_t pin_hash_dec_final[SHA256_DIGEST_LENGTH];
    uint8_t iv[BC_LEN] = {0};

    /* +16 = padding that relic expects */
    uint8_t pin_token_enc[CTAP_PIN_TOKEN_SIZE + 16];
    int ret;

    if (!pin_is_set()) {
        return CTAP2_ERR_PIN_NOT_SET;
    }

    if (!req->key_agreement_present || !req->pin_hash_enc_present) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    if (get_remaining_pin_attempts() == 0) {
        return CTAP2_ERR_PIN_BLOCKED;
    }

    get_shared_key(shared_key, sizeof(shared_key), &req->key_agreement);

    len = sizeof(pin_hash_dec);
    ret = aes_dec(pin_hash_dec, &len, req->pin_hash_enc,
            sizeof(req->pin_hash_enc), shared_key, sizeof(shared_key) * 8, iv);

    if (ret == STS_ERR) {
        DEBUG("set pin: error while decrypting pin hash \n");
        return CTAP1_ERR_OTHER;
    }

    sha256_init(&ctx),
    sha256_update(&ctx, pin_hash_dec, 16);
    sha256_update(&ctx, g_state.pin_salt, sizeof(g_state.pin_salt));
    sha256_final(&ctx, pin_hash_dec_final);

    if (memcmp(pin_hash_dec_final, g_state.pin_hash, 16) != 0) {
        DEBUG("get_pin_token: invalid pin \n");
        reset_key_agreement();
        decrement_pin_attempts();
        save_state(&g_state);

        return CTAP2_ERR_PIN_INVALID;
    }

    reset_pin_attempts();

    len = sizeof(pin_token_enc);
    ret = bc_aes_cbc_enc(pin_token_enc, &len, g_pin_token,
                   sizeof(g_pin_token), shared_key, sizeof(shared_key) * 8, iv);

    if (ret == STS_ERR) {
        DEBUG("get pin token: error encrypting pin token \n");
        return CTAP1_ERR_OTHER;
    }

    return cbor_helper_encode_pin_token(encoder, pin_token_enc, sizeof(pin_token_enc) - 16);
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

static uint8_t make_auth_data_assert(uint8_t *rp_id, size_t rp_id_len, ctap_auth_data_header_t *auth_data)
{
    memset(auth_data, 0, sizeof(*auth_data));

    /* sha256 of relying party id */
    sha256(rp_id, rp_id_len, auth_data->rp_id_hash);

    /* get sign counter */
    uint32_t counter = 0;
    get_auth_data_sign_count(&counter);
    auth_data->counter = counter;

    /* todo: faking user presence because it is necessary for registration */
    auth_data->flags |= CTAP_AUTH_DATA_FLAG_UP;

    return CTAP2_OK;
}

static uint8_t make_auth_data_attest(ctap_rp_ent_t *rp, ctap_user_ent_t *user, ctap_pub_key_cred_params_t *cred_params,
                              ctap_auth_data_t* auth_data, ctap_resident_key_t *rk)
{
    int ret;
    uint32_t counter = 0;
    ec_t pub_key;
    bn_t priv_key;
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

    /* get sign counter */
    get_auth_data_sign_count(&counter);
    auth_header->counter = counter;

    memmove(cred_header->aaguid, &aaguid, sizeof(cred_header->aaguid));

    /* generate credential id */
    generate_random_sequence(cred_header->cred_id, sizeof(cred_header->cred_id));
    cred_header->cred_len_h = (sizeof(cred_header->cred_id) & 0xff00) >> 8;
    cred_header->cred_len_l = sizeof(cred_header->cred_id) & 0x00ff;

    ec_null(pub_key);
    bn_null(priv_key);

    ec_new(pub_key);
    bn_new(priv_key);

     /* generate key pair */
    ret = cp_ecdsa_gen(priv_key, pub_key);
    //todo: update package version to get up to date macro name
    if (ret == STS_ERR) {
        return CTAP1_ERR_OTHER;
    }

    fp_write_bin(cred_data->pub_key.x, sizeof(cred_data->pub_key.x), pub_key->x);
    fp_write_bin(cred_data->pub_key.y, sizeof(cred_data->pub_key.y), pub_key->y);

    bn_write_bin(rk->priv_key, sizeof(rk->priv_key), priv_key);

    cred_data->pub_key.params.alg_type = cred_params->alg_type;
    cred_data->pub_key.params.cred_type = cred_params->cred_type;

    /* init resident key struct */
    memmove(rk->rp_id_hash, auth_header->rp_id_hash, sizeof(rk->rp_id_hash));
    memmove(rk->cred_desc.cred_id, cred_header->cred_id, sizeof(rk->cred_desc.cred_id));
    memmove(rk->user_id, user->id, user->id_len);
    rk->cred_desc.cred_type = cred_params->cred_type;
    rk->user_id_len = user->id_len;

    ec_free(pub_key);
    bn_free(priv_key);

    return CTAP2_OK;
}

// https://wiki.openssl.org/index.php/DER
// http://luca.ntop.org/Teaching/Appunti/asn1.html
// https://www.w3.org/TR/webauthn/#packed-attestation
uint8_t ctap_get_attest_sig(uint8_t *auth_data, size_t auth_data_len, uint8_t *client_data_hash,
                            ctap_resident_key_t *rk, uint8_t* sig, size_t *sig_len)
{
    bn_t priv_key;
    bn_t r, s;
    int ret;
    sha256_context_t ctx;
    uint8_t hash[SHA256_DIGEST_LENGTH];

    sha256_init(&ctx);
    sha256_update(&ctx, auth_data, auth_data_len);
    sha256_update(&ctx, client_data_hash, SHA256_DIGEST_LENGTH);
    sha256_final(&ctx, hash);

    bn_null(priv_key);
    bn_null(r);
    bn_null(s);

    bn_new(priv_key);
    bn_new(r);
    bn_new(s);

    /*
    The signature is r||s, where || denotes concatenation,
    and where both r and s are both big-endian-encoded values that are left-padded to the maximum length
    */
    bn_read_bin(priv_key, rk->priv_key, sizeof(rk->priv_key));

    ret = cp_ecdsa_sig(r, s, hash, sizeof(hash), 1, priv_key);

    //todo: update package version to get up to date macro name
    if (ret == STS_ERR) {
        return CTAP1_ERR_OTHER;
    }

    ret = sig_to_der_format(r, s, sig, sig_len);

    if (ret != CTAP2_OK) {
        return ret;
    }

    bn_free(priv_key);
    bn_free(r);
    bn_free(s);

    return CTAP2_OK;
}

/* Encoding signature in ASN.1 DER format */
/* https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-0_pdf.pdf?__blob=publicationFile&v=2 */
static uint8_t sig_to_der_format(bn_t r, bn_t s, uint8_t* buf, size_t *sig_len)
{
    uint8_t offset = 0;

    uint8_t r_raw[32];
    uint8_t s_raw[32];

    uint8_t lead_r = 0;
    uint8_t lead_s = 0;

    uint8_t pad_s, pad_r;

    uint8_t i;

    bn_write_bin(r_raw, sizeof(r_raw), r);
    bn_write_bin(s_raw, sizeof(s_raw), s);

    /* get leading zeros to save space */
    for (i = 0; i < sizeof(r_raw); i++) {
        if (r_raw[i] == 0) {
            lead_r++;
        }
        else {
            break;
        }
    }

    for (i = 0; i < sizeof(s_raw); i++) {
        if (s_raw[i] == 0) {
            lead_s++;
        }
        else {
            break;
        }
    }

    /*
    if number is negative after removing leading zeros,
    pad with 1 zero byte in order to turn number positive again
    */
    pad_r = ((r_raw[lead_r] & 0x80) == 0x80);
    pad_s = ((s_raw[lead_s] & 0x80) == 0x80);

    memset(buf, 0, CTAP_ES256_DER_MAX_SIZE);

    /* sequence tag number, constructed method */
    buf[offset++] = 0x30;

    /* length octet (number of content octets) */
    buf[offset++] = 0x44 + pad_r + pad_s - lead_r - lead_s;

    /* integer tag number */
    buf[offset++] = 0x02;
    buf[offset + pad_r] = 0x00;
    buf[offset++] = 0x20 + pad_r - lead_r;
    offset += pad_r;

    memmove(buf + offset, r_raw + lead_r, 32 - lead_r);

    offset += 32 - lead_r;

    /* integer tag number */
    buf[offset++] = 0x02;
    buf[offset] = 0x00;
    buf[offset++] = 0x20 + pad_s - lead_s;
    offset += pad_s;

    memmove(buf + offset, s_raw + lead_s, 32 - lead_s);

    offset += 32 - lead_s;

    *sig_len = offset;

    return CTAP2_OK;
}
