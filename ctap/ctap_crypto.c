#define ENABLE_DEBUG    (1)
#include "debug.h"

#include "crypto/ciphers.h"
#include "crypto/modes/ccm.h"

#include "ctap_utils.h"

#include "relic.h"

#include "rijndael-api-fst.h"

#include "ctap_crypto.h"

typedef struct
{
    ec_t pub;
    bn_t priv;
} ctap_key_agreement_key_t;

static ctap_key_agreement_key_t g_ag_key;

static uint8_t sig_to_der_format(bn_t r, bn_t s, uint8_t *sig, size_t *sig_len);

uint8_t ctap_crypto_init(void)
{
    int ret;
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

    ret = cp_ecdh_gen(g_ag_key.priv, g_ag_key.pub);
    if (ret == STS_ERR) {
        DEBUG("ECDH key pair creation failed. Not good :( \n");
        return CTAP1_ERR_OTHER;
    }

    return CTAP2_OK;
}

void ctap_crypto_prng(uint8_t *dst, size_t len)
{
    timestamp();
    /* relic random bytes func */
    rand_bytes(dst, len);
    DEBUG("Crypto took: %d \n", timestamp());
}

int ctap_crypto_reset_key_agreement(void)
{
    bn_free(g_ag_key.priv);
    ec_free(g_ag_key.pub);

    bn_null(g_ag_key.priv);
    ec_null(g_ag_key.pub);

    bn_new(g_ag_key.priv);
    ec_new(g_ag_key.pub);

    return cp_ecdh_gen(g_ag_key.priv, g_ag_key.pub);
}

void ctap_crypto_get_key_agreement(ctap_cose_key_t *key)
{
    fp_write_bin(key->pubkey.x, sizeof(key->pubkey.x), g_ag_key.pub->x);
    fp_write_bin(key->pubkey.y, sizeof(key->pubkey.y), g_ag_key.pub->y);
}

void ctap_crypto_derive_key(uint8_t *key, size_t len, ctap_cose_key_t *cose)
{
    /* translate key into relic internal structure */
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

/* same as bc_aes_cbc_dec except that we use blockDecrypt instead of padDecrypt */
uint8_t ctap_crypto_aes_dec(uint8_t *out, int *out_len, uint8_t *in,
		int in_len, uint8_t *key, int key_len)
{
    uint8_t iv[BC_LEN] = {0};
    keyInstance key_inst;
	cipherInstance cipher_inst;

    /* relic expects key_len in bits */
    key_len *= 8;

	if (*out_len < in_len) {
		return CTAP1_ERR_OTHER;
	}

	if (makeKey2(&key_inst, DIR_DECRYPT, key_len, (char *)key) != TRUE) {
		return CTAP1_ERR_OTHER;
	}
	if (cipherInit(&cipher_inst, MODE_CBC, NULL) != TRUE) {
		return CTAP1_ERR_OTHER;
	}

    memcpy(cipher_inst.IV, iv, BC_LEN);

    /*blockDecrypt expects in_len in bits */
    in_len *= 8;
    *out_len = blockDecrypt(&cipher_inst, &key_inst, in, in_len, out);

    if (*out_len <= 0) {
        return CTAP1_ERR_OTHER;
    }

    return CTAP2_OK;
}

/* same as bc_aes_cbc_enc except that we use blockEncrypt instead of padEncrypt */
uint8_t ctap_crypto_aes_enc(uint8_t *out, int *out_len, uint8_t *in,
		int in_len, uint8_t *key, int key_len)
{
    uint8_t iv[BC_LEN] = {0};
    keyInstance key_inst;
	cipherInstance cipher_inst;

    /* relic expects key_len in bits */
    key_len *= 8;

    if (*out_len < in_len) {
		return CTAP1_ERR_OTHER;
	}

	if (makeKey2(&key_inst, DIR_ENCRYPT, key_len, (char *)key) != TRUE) {
		return CTAP1_ERR_OTHER;
	}
	if (cipherInit(&cipher_inst, MODE_CBC, NULL) != TRUE) {
		return CTAP1_ERR_OTHER;
    }

    memcpy(cipher_inst.IV, iv, BC_LEN);

    /*blockEncrypt expects in_len in bits */
    in_len *= 8;
    *out_len = blockEncrypt(&cipher_inst, &key_inst, in, in_len, out);

    if (*out_len <= 0) {
        return CTAP1_ERR_OTHER;
    }

    return CTAP2_OK;
}

//https://tools.ietf.org/html/rfc3610
//http://api.riot-os.org/ccm_8h.html
uint8_t ctap_crypto_aes_ccm_enc(uint8_t *out, uint8_t * in,
                                size_t in_len, uint8_t *a, size_t a_len,
                                uint8_t mac_len, uint8_t l, uint8_t *nonce,
                                uint8_t *key)
{
    timestamp();
    cipher_t cipher;
    int ret, len;

    ret = cipher_init(&cipher, CIPHER_AES_128, key, CCM_BLOCK_SIZE);

    if (ret != 1) {
        return CTAP1_ERR_OTHER;
    }

    len = cipher_encrypt_ccm(&cipher, a, a_len, mac_len, l, nonce, 15 - l,
                             in, in_len, out);


    if (len < 0) {
        return CTAP1_ERR_OTHER;
    }

    DEBUG("Crypto took: %d \n", timestamp());

    return CTAP2_OK;
}

uint8_t ctap_crypto_aes_ccm_dec(uint8_t *out, uint8_t *in,
                                size_t in_len, uint8_t *a, size_t a_len,
                                uint8_t mac_len, uint8_t l, uint8_t *nonce,
                                uint8_t *key)
{
    timestamp();
    cipher_t cipher;
    int ret, len;

    ret = cipher_init(&cipher, CIPHER_AES_128, key, CCM_BLOCK_SIZE);

    if (ret != 1) {
        return CTAP1_ERR_OTHER;
    }

    len = cipher_decrypt_ccm(&cipher, a, a_len, mac_len, l, nonce, 15 - l,
                             in, in_len, out);

    if (len < 0) {
        return CTAP1_ERR_OTHER;
    }

    DEBUG("Crypto took: %d \n", timestamp());

    return CTAP2_OK;
}

uint8_t ctap_crypto_gen_keypair(ctap_cose_key_t *key, uint8_t *priv_key)
{
    timestamp();
    ec_t pub;
    bn_t priv;
    int ret;

    ec_null(pub);
    bn_null(priv);

    ec_new(pub);
    bn_new(priv);

    ret = cp_ecdsa_gen(priv, pub);

    if (ret == STS_ERR) {
        return CTAP1_ERR_OTHER;
    }

    fp_write_bin(key->pubkey.x, sizeof(key->pubkey.x), pub->x);
    fp_write_bin(key->pubkey.y, sizeof(key->pubkey.y), pub->y);

    bn_write_bin(priv_key, sizeof(key->pubkey.x), priv);

    ec_free(pub);
    bn_free(priv);

    DEBUG("Crypto took: %d \n", timestamp());
    return CTAP2_OK;
}

uint8_t ctap_crypto_get_sig(uint8_t *data, size_t data_len, uint8_t *sig,
                            size_t *sig_len, uint8_t *key, size_t key_len)
{
    timestamp();
    bn_t priv, r, s;
    int ret;

    bn_null(priv);
    bn_null(r);
    bn_null(s);

    bn_new(priv);
    bn_new(r);
    bn_new(s);

    bn_read_bin(priv, key, key_len);

    ret = cp_ecdsa_sig(r, s, data, data_len, 1, priv);

    if (ret == STS_ERR) {
        goto cleanup;
    }

    ret = sig_to_der_format(r, s, sig, sig_len);

cleanup:
    bn_free(priv);
    bn_free(r);
    bn_free(s);

    DEBUG("Crypto took: %d \n", timestamp());
    return ret != CTAP2_OK ? CTAP1_ERR_OTHER : CTAP2_OK;
}

/* Encoding signature in ASN.1 DER format */
/* https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-0_pdf.pdf?__blob=publicationFile&v=2 */
static uint8_t sig_to_der_format(bn_t r, bn_t s, uint8_t *sig, size_t *sig_len)
{
    if (*sig_len < CTAP_ES256_DER_MAX_SIZE) {
        return CTAP1_ERR_OTHER;
    }

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

    memset(sig, 0, *sig_len);

    /* sequence tag number, constructed method */
    sig[offset++] = 0x30;

    /* length octet (number of content octets) */
    sig[offset++] = 0x44 + pad_r + pad_s - lead_r - lead_s;

    /* integer tag number */
    sig[offset++] = 0x02;
    sig[offset + pad_r] = 0x00;
    sig[offset++] = 0x20 + pad_r - lead_r;
    offset += pad_r;

    memmove(sig + offset, r_raw + lead_r, 32 - lead_r);

    offset += 32 - lead_r;

    /* integer tag number */
    sig[offset++] = 0x02;
    sig[offset] = 0x00;
    sig[offset++] = 0x20 + pad_s - lead_s;
    offset += pad_s;

    memmove(sig + offset, s_raw + lead_s, 32 - lead_s);

    offset += 32 - lead_s;

    *sig_len = offset;

    return CTAP2_OK;
}