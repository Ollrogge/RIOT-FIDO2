#define ENABLE_DEBUG    (1)
#include "debug.h"

#include "crypto/ciphers.h"
#include "crypto/modes/ccm.h"

#include "ctap_crypto.h"

#include "periph/hwrng.h"

#include "ctap_utils.h"

#include "assert.h"

static ctap_crypto_key_agreement_key_t g_ag_key;
static uint8_t sig_to_der_format(uint8_t *r, uint8_t *s, uint8_t *sig, size_t *sig_len);
static uint8_t init_key_agreement_key(ctap_crypto_key_agreement_key_t* key);

#if !CTAP_CRYPTO_MICRO_ECC
static int ecdh(uint8_t *key, int key_len, bn_t d, ec_t q);
#endif

uint8_t ctap_crypto_init(void)
{
    hwrng_init();

#if !CTAP_CRYPTO_MICRO_ECC
    core_init();
    ep_param_set(NIST_P256);
#endif

    /**
     * configuration operations upon power up
     * CTAP specification (version 20190130) section 5.5.2
     */
    return init_key_agreement_key(&g_ag_key);
}

static uint8_t init_key_agreement_key(ctap_crypto_key_agreement_key_t* key)
{
    int ret;

#if CTAP_CRYPTO_MICRO_ECC
    const struct uECC_Curve_t *curve = uECC_secp256r1();

    ret = uECC_make_key((uint8_t*)&key->pub, key->priv, curve);

    if (ret == 0) {
        return CTAP1_ERR_OTHER;
    }
#else
    ec_t pub;
    bn_t priv;

    bn_null(priv);
    ec_null(pub);

    bn_new(priv);
    ec_new(pub);

    memset(key, 0, sizeof(*key));

    ret = cp_ecdh_gen(priv, pub);
    if (ret == STS_ERR) {
        DEBUG("ECDH key pair creation failed. Not good :( \n");
        return CTAP1_ERR_OTHER;
    }

    ec_write_bin((uint8_t*)&key->pub, sizeof(key->pub), pub, false);
    bn_write_bin(key->priv, sizeof(key->priv), priv);

    bn_free(priv);
    ec_free(pub);
#endif

    return CTAP2_OK;
}

void ctap_crypto_prng(uint8_t *buf, size_t len)
{
    hwrng_read(buf, len);
}

int ctap_crypto_reset_key_agreement(void)
{
    return init_key_agreement_key(&g_ag_key);
}

void ctap_crypto_get_key_agreement(ctap_cose_key_t *key)
{
    memmove(key->pubkey.x, g_ag_key.pub.x, sizeof(key->pubkey.x));
    memmove(key->pubkey.y, g_ag_key.pub.y, sizeof(key->pubkey.y));
}

#if !CTAP_CRYPTO_MICRO_ECC
/* same as cp_ecdh_key but no KDF2 */
static int ecdh(uint8_t *key, int key_len, bn_t d, ec_t q) {
	ec_t p;
	bn_t x, h;
	int result = STS_OK;

	ec_null(p);
	bn_null(x);
	bn_null(h);

	TRY {
		ec_new(p);
		bn_new(x);
		bn_new(h);

		ec_curve_get_cof(h);
		if (bn_bits(h) < BN_DIGIT) {
			ec_mul_dig(p, q, h->dp[0]);
		} else {
			ec_mul(p, q, h);
		}
		ec_mul(p, p, d);
		if (ec_is_infty(p)) {
			result = STS_ERR;
		}
		ec_get_x(x, p);
        bn_write_bin(key, key_len, x);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ec_free(p);
		bn_free(x);
		bn_free(h);
	}
	return result;
}
#endif

/* CTAP specification (version 20190130) section 5.5.7 */
uint8_t ctap_crypto_ecdh(uint8_t *out, size_t len, ctap_cose_key_t *cose)
{
    int ret;
#if CTAP_CRYPTO_MICRO_ECC
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    ret = uECC_shared_secret((uint8_t*)&cose->pubkey, g_ag_key.priv, out, curve);

    if (ret == 0) {
        return CTAP1_ERR_OTHER;
    }
#else
    assert(len == FP_BYTES);
    assert(sizeof((*cose).pubkey.x) == FP_BYTES);
    assert(sizeof((*cose).pubkey.y) == FP_BYTES);
    /* translate key into relic internal structure */
    uint8_t *x = cose->pubkey.x;
    uint8_t *y = cose->pubkey.y;
    uint8_t bG[FP_BYTES * 2 + 1];
    ec_t pub;
    bn_t priv;

    ec_null(pub);
    bn_null(priv);

    ec_new(pub);
    bn_new(priv);

    /* public key of platformKeyAgreementKey */
    /* flag that point is not compressed */
    bG[0] = 0x04;
    memcpy(bG + 1, x, FP_BYTES);
    memcpy(bG + 1 + FP_BYTES, y, FP_BYTES);

    ep_read_bin(pub, bG, sizeof(bG));
    bn_read_bin(priv, g_ag_key.priv, sizeof(g_ag_key.priv));

    /* derive shared secret */
    ret = ecdh(out, len, priv, pub);

    ec_free(pub);
    bn_free(priv);

    if (ret != STS_OK) {
        return CTAP1_ERR_OTHER;
    }
#endif
    return CTAP2_OK;
}

/* same as bc_aes_cbc_dec except that we use blockDecrypt instead of padDecrypt */
uint8_t ctap_crypto_aes_dec(uint8_t *out, int *out_len, uint8_t *in,
		int in_len, const uint8_t *key, int key_len)
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

    memcpy(cipher_inst.IV, iv, sizeof(iv));

    /* blockDecrypt expects in_len in bits */
    in_len *= 8;
    *out_len = blockDecrypt(&cipher_inst, &key_inst, in, in_len, out);

    if (*out_len <= 0) {
        return CTAP1_ERR_OTHER;
    }

    return CTAP2_OK;
}

/* same as bc_aes_cbc_enc except that we use blockEncrypt instead of padEncrypt */
uint8_t ctap_crypto_aes_enc(uint8_t *out, int *out_len, uint8_t *in,
		int in_len, const uint8_t *key, int key_len)
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
uint8_t ctap_crypto_aes_ccm_enc(uint8_t *out, const uint8_t * in,
                                size_t in_len, uint8_t *a, size_t a_len,
                                uint8_t mac_len, uint8_t l, const uint8_t *nonce,
                                const uint8_t *key)
{
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

    return CTAP2_OK;
}

uint8_t ctap_crypto_aes_ccm_dec(uint8_t *out, const uint8_t *in,
                                size_t in_len, uint8_t *a, size_t a_len,
                                uint8_t mac_len, uint8_t l, const uint8_t *nonce,
                                const uint8_t *key)
{
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

    return CTAP2_OK;
}

uint8_t ctap_crypto_gen_keypair(ctap_cose_key_t *key, uint8_t *priv_key)
{
    int ret;
#if CTAP_CRYPTO_MICRO_ECC
    uint8_t pub_key[CTAP_P256_KEY_SIZE * 2];
    const struct uECC_Curve_t *curve = uECC_secp256r1();

    ret = uECC_make_key(pub_key, priv_key, curve);
    if (ret == 0) {
        return CTAP1_ERR_OTHER;
    }

    memmove(key->pubkey.x, pub_key, CTAP_P256_KEY_SIZE);
    memmove(key->pubkey.y, pub_key + CTAP_P256_KEY_SIZE, CTAP_P256_KEY_SIZE);
#else
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
#endif

    return CTAP2_OK;
}

uint8_t ctap_crypto_get_sig(uint8_t *hash, size_t hash_len, uint8_t *sig,
                            size_t *sig_len, const uint8_t *key, size_t key_len)
{
    uint8_t r_raw[CTAP_P256_KEY_SIZE];
    uint8_t s_raw[CTAP_P256_KEY_SIZE];
    int ret;

    assert(*sig_len > CTAP_P256_KEY_SIZE * 2);
    assert(key_len == CTAP_P256_KEY_SIZE);

#if CTAP_CRYPTO_MICRO_ECC
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    ret = uECC_sign(key, hash, hash_len, sig, curve);

    if (ret == 0) {
        return CTAP1_ERR_OTHER;
    }

    memmove(r_raw, sig, sizeof(r_raw));
    memmove(s_raw, sig + sizeof(r_raw), sizeof(s_raw));
#else
    bn_t priv, r, s;

    bn_null(priv);
    bn_null(r);
    bn_null(s);

    bn_new(priv);
    bn_new(r);
    bn_new(s);

    bn_read_bin(priv, key, key_len);

    ret = cp_ecdsa_sig(r, s, hash, hash_len, 1, priv);

    if (ret == STS_ERR) {
        bn_free(priv);
        bn_free(r);
        bn_free(s);

        return CTAP1_ERR_OTHER;
    }

    bn_write_bin(r_raw, sizeof(r_raw), r);
    bn_write_bin(s_raw, sizeof(s_raw), s);

    bn_free(priv);
    bn_free(r);
    bn_free(s);
#endif
    ret = sig_to_der_format(r_raw, s_raw, sig, sig_len);

    if (ret != CTAP2_OK) {
        return ret;
    }

    return CTAP2_OK;
}

/* Encoding signature in ASN.1 DER format */
/* https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-0_pdf.pdf?__blob=publicationFile&v=2 */
static uint8_t sig_to_der_format(uint8_t *r, uint8_t *s, uint8_t *sig, size_t *sig_len)
{
    uint8_t offset = 0;
    uint8_t lead_r = 0;
    uint8_t lead_s = 0;
    uint8_t pad_s, pad_r;
    uint8_t i;

    if (*sig_len < CTAP_ES256_DER_MAX_SIZE) {
        return CTAP1_ERR_OTHER;
    }

    /* get leading zeros to save space */
    for (i = 0; i < CTAP_P256_KEY_SIZE; i++) {
        if (r[i] == 0) {
            lead_r++;
        }
        else {
            break;
        }
    }

    for (i = 0; i < CTAP_P256_KEY_SIZE; i++) {
        if (s[i] == 0) {
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
    pad_r = ((r[lead_r] & 0x80) == 0x80);
    pad_s = ((s[lead_s] & 0x80) == 0x80);

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

    memmove(sig + offset, r + lead_r, 32 - lead_r);

    offset += 32 - lead_r;

    /* integer tag number */
    sig[offset++] = 0x02;
    sig[offset] = 0x00;
    sig[offset++] = 0x20 + pad_s - lead_s;
    offset += pad_s;

    memmove(sig + offset, s + lead_s, 32 - lead_s);

    offset += 32 - lead_s;

    *sig_len = offset;

    return CTAP2_OK;
}