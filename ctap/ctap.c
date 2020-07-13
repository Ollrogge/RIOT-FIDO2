
#define ENABLE_DEBUG    (1)
#include "debug.h"

#include <string.h>

#include "ctap.h"

#include "cbor.h"

#include "cbor_helper.h"

#include "xtimer.h"

#include "relic.h"

#include "hashes/sha256.h"

static uint8_t make_credential(CborEncoder* encoder, size_t size, uint8_t* req_raw);
static uint8_t make_auth_data(ctap_rp_ent_t *rp,ctap_pub_key_cred_params_t *cred_params, ctap_auth_data_t* auth_data);
static uint32_t get_auth_data_sign_count(uint32_t* auth_data_counter);
static void get_random_sequence(uint8_t *dst, size_t len);
static void sig_to_der_format(bn_t r, bn_t s, uint8_t* buf, size_t *sig_len);

/* for testing */
static bn_t g_priv_key;

void ctap_init(void)
{
     /* init relic */
    core_init();
    rand_init();
    ep_param_set(NIST_P256);
}

static void get_random_sequence(uint8_t *dst, size_t len)
{
    /* relic random bytes func */
    rand_bytes(dst, len);
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
    uint8_t *byte = (uint8_t*) &auth_data_counter;
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

size_t ctap_handle_request(uint8_t* req, size_t size, ctap_resp_t* resp)
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
        case CTAP_MAKE_CREDENTIAL:
            DEBUG("CTAP MAKE CREDENTIAL \n");
            resp->status = make_credential(&encoder, size, req);
            return cbor_encoder_get_buffer_size(&encoder, buf);
        default:
            DEBUG("CTAP UNKNOWN PACKET: %u \n", cmd);
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

    cred_source_t cred_source;
    (void)cred_source;

    memset(&req, 0, sizeof(req));

    ret = cbor_helper_parse_make_credential_req(&req, size, req_raw);

    if (ret != CTAP2_OK) {
        return ret;
    }

    ctap_auth_data_t auth_data;
    make_auth_data(&req.rp, &req.cred_params, &auth_data);

    if (ret != CTAP2_OK) {
        return ret;
    }

    print_hex(req.client_data_hash, sizeof(req.client_data_hash));

    cbor_helper_encode_attestation_object(encoder, &auth_data, req.client_data_hash);

    if (ret != CTAP2_OK) {
        return ret;
    }

    DEBUG("NO ERROR \n");
    return CTAP2_OK;
}

static uint8_t make_auth_data(ctap_rp_ent_t *rp, ctap_pub_key_cred_params_t *cred_params, ctap_auth_data_t* auth_data)
{
    int ret;

    memset(auth_data, 0, sizeof(ctap_auth_data_t));

    ctap_auth_data_header_t* auth_header = &auth_data->header;

    /* sha256 of relying party id */
    sha256(rp->id, rp->id_len, auth_header->rp_id_hash);

    /* set flag indicating that attested credential data included */
    auth_header->flags |= CTAP_AUTH_DATA_FLAG_AT;

    /* get sign counter */
    uint32_t counter = 0;
    get_auth_data_sign_count(&counter);
    auth_header->counter = counter;

    ctap_attested_cred_data_t * cred_data = &auth_data->attested_cred_data;
    ctap_attested_cred_data_header_t* cred_header = &cred_data->header;

    /* device aaguid */
    uint8_t aaguid[] = {DEVICE_AAGUID};
    memmove(cred_header->aaguid, &aaguid, sizeof(cred_header->aaguid));

    /* generate credential id */
    get_random_sequence(cred_header->cred_id, CTAP_CREDENTIAL_ID_SIZE);
    cred_header->cred_len_h = (sizeof(cred_header->cred_id) & 0xff00) >> 8;
    cred_header->cred_len_l = sizeof(cred_header->cred_id) & 0x00ff;

    /* generate key pair */
    ec_t pub_key;
    bn_t priv_key;

    ec_null(pub_key);
    bn_null(priv_key);

    ec_new(pub_key);
    bn_new(priv_key);

    ret = cp_ecdsa_gen(priv_key, pub_key);
    //todo: update package version to get up to date macro name
    if (ret == 1) {
        return CTAP2_ERR_PROCESSING;
    }

    fp_write_bin(cred_data->pub_key.x, sizeof(cred_data->pub_key.x), pub_key->x);
    fp_write_bin(cred_data->pub_key.y, sizeof(cred_data->pub_key.y), pub_key->y);

    //todo: rethink
    g_priv_key[0] = priv_key[0];

    cred_data->pub_key.params.alg_type = cred_params->alg_type;
    cred_data->pub_key.params.cred_type = cred_params->cred_type;

    return CTAP2_OK;
}

// https://wiki.openssl.org/index.php/DER
// http://luca.ntop.org/Teaching/Appunti/asn1.html
// https://www.w3.org/TR/webauthn/#packed-attestation
uint8_t ctap_get_attest_sig(uint8_t *auth_data, size_t auth_data_len, uint8_t *client_data_hash,
                            uint8_t* sig, size_t *sig_len)
{
    bn_t r, s;
    int ret;
    sha256_context_t ctx;
    uint8_t hash[CTAP_SHA256_HASH_SIZE];

    sha256_init(&ctx);
    sha256_update(&ctx, auth_data, auth_data_len);
    sha256_update(&ctx, client_data_hash, CTAP_CLIENT_DATA_HASH_SIZE);
    sha256_final(&ctx, hash);

    /*
    The signature is r||s, where || denotes concatenation,
    and where both r and s are both big-endian-encoded values that are left-padded to the maximum length
    */
    ret = cp_ecdsa_sig(r, s, hash, sizeof(hash), 1, g_priv_key);

    //todo: update package version to get up to date macro name
    if (ret == 1) {
        return CTAP2_ERR_PROCESSING;
    }

    sig_to_der_format(r, s, sig, sig_len);

    return CTAP2_OK;
}

/* Encoding signature in ASN.1 DER format */
/* https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-0_pdf.pdf?__blob=publicationFile&v=2 */
static void sig_to_der_format(bn_t r, bn_t s, uint8_t* buf, size_t *sig_len)
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
}
