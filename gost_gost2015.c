/*
 * Copyright (c) 2020 Dmitry Belyavskiy <beldmit@gmail.com>
 * Pascal Heller 2024
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */
#include "gost_lcl.h"
#include "gost_gost2015.h"
#include "gost_grasshopper_defines.h"
#include "gost_grasshopper_math.h"
#include "gost_grasshopper_cipher.c"
#include "e_gost_err.h"
#include <string.h>
#include <openssl/rand.h>

#pragma region hide

int gost2015_final_call(EVP_CIPHER_CTX *ctx, EVP_MD_CTX *omac_ctx, size_t mac_size,
    unsigned char *encrypted_mac,
    int (*do_cipher) (EVP_CIPHER_CTX *ctx,
    unsigned char *out,
    const unsigned char *in,
    size_t inl))
{
    unsigned char calculated_mac[KUZNYECHIK_MAC_MAX_SIZE];
    memset(calculated_mac, 0, KUZNYECHIK_MAC_MAX_SIZE);

    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        EVP_DigestSignFinal(omac_ctx, calculated_mac, &mac_size);

        if (do_cipher(ctx, encrypted_mac, calculated_mac, mac_size) <= 0) {
            return -1;
        }
    } else {
        unsigned char expected_mac[KUZNYECHIK_MAC_MAX_SIZE];

        memset(expected_mac, 0, KUZNYECHIK_MAC_MAX_SIZE);
        EVP_DigestSignFinal(omac_ctx, calculated_mac, &mac_size);

        if (do_cipher(ctx, expected_mac, encrypted_mac, mac_size) <= 0) {
            return -1;
        }

        if (CRYPTO_memcmp(expected_mac, calculated_mac, mac_size) != 0)
            return -1;
    }
    return 0;
}

/*
 * UKM = iv|kdf_seed
 * */
#define MAX_GOST2015_UKM_SIZE 16
#define KDF_SEED_SIZE 8
int gost2015_get_asn1_params(const ASN1_TYPE *params, size_t ukm_size,
    unsigned char *iv, size_t ukm_offset, unsigned char *kdf_seed)
{
    int iv_len = 16;
    GOST2015_CIPHER_PARAMS *gcp = NULL;

    unsigned char *p = NULL;

    memset(iv, 0, iv_len);

    /* Проверяем тип params */
    if (ASN1_TYPE_get(params) != V_ASN1_SEQUENCE) {
        GOSTerr(GOST_F_GOST2015_GET_ASN1_PARAMS, GOST_R_INVALID_CIPHER_PARAMS);
        return 0;
    }

    p = params->value.sequence->data;
    /* Извлекаем структуру параметров */
    gcp = d2i_GOST2015_CIPHER_PARAMS(NULL, (const unsigned char **)&p, params->value.sequence->length);
    if (gcp == NULL) {
        GOSTerr(GOST_F_GOST2015_GET_ASN1_PARAMS, GOST_R_INVALID_CIPHER_PARAMS);
        return 0;
    }

    /* Проверяем длину синхропосылки */
    if (gcp->ukm->length != (int)ukm_size) {
        GOSTerr(GOST_F_GOST2015_GET_ASN1_PARAMS, GOST_R_INVALID_CIPHER_PARAMS);
        GOST2015_CIPHER_PARAMS_free(gcp);
        return 0;
    }

    memcpy(iv, gcp->ukm->data, ukm_offset);
    memcpy(kdf_seed, gcp->ukm->data+ukm_offset, KDF_SEED_SIZE);

    GOST2015_CIPHER_PARAMS_free(gcp);
    return 1;
}

int gost2015_set_asn1_params(ASN1_TYPE *params,
    const unsigned char *iv, size_t iv_size, const unsigned char *kdf_seed)
{
    GOST2015_CIPHER_PARAMS *gcp = GOST2015_CIPHER_PARAMS_new();
    int ret = 0, len = 0;

    ASN1_OCTET_STRING *os = NULL;
    unsigned char ukm_buf[MAX_GOST2015_UKM_SIZE];
    unsigned char *buf = NULL;

    if (gcp == NULL) {
        GOSTerr(GOST_F_GOST2015_SET_ASN1_PARAMS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    memcpy(ukm_buf, iv, iv_size);
    memcpy(ukm_buf+iv_size, kdf_seed, KDF_SEED_SIZE);

    if (ASN1_STRING_set(gcp->ukm, ukm_buf, iv_size + KDF_SEED_SIZE) == 0) {
        GOSTerr(GOST_F_GOST2015_SET_ASN1_PARAMS, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    len = i2d_GOST2015_CIPHER_PARAMS(gcp, &buf);

    if (len <= 0
       || (os = ASN1_OCTET_STRING_new()) == NULL
       || ASN1_OCTET_STRING_set(os, buf, len) == 0) {
        goto end;
  }

    ASN1_TYPE_set(params, V_ASN1_SEQUENCE, os);
    ret = 1;

end:
    OPENSSL_free(buf);
    if (ret <= 0 && os)
        ASN1_OCTET_STRING_free(os);

    GOST2015_CIPHER_PARAMS_free(gcp);
    return ret;
}

int gost2015_process_unprotected_attributes(
    STACK_OF(X509_ATTRIBUTE) *attrs,
    int encryption, size_t mac_len, unsigned char *final_tag)
{
    if (encryption == 0) /*Decrypting*/ {
        ASN1_OCTET_STRING *osExpectedMac = X509at_get0_data_by_OBJ(attrs,
            OBJ_txt2obj(OID_GOST_CMS_MAC, 1), -3, V_ASN1_OCTET_STRING);

        if (!osExpectedMac || osExpectedMac->length != (int)mac_len)
            return -1;

        memcpy(final_tag, osExpectedMac->data, osExpectedMac->length);
    } else {
        if (attrs == NULL)
            return -1;
        return (X509at_add1_attr_by_OBJ(&attrs,
               OBJ_txt2obj(OID_GOST_CMS_MAC, 1),
               V_ASN1_OCTET_STRING, final_tag,
               mac_len) == NULL) ? -1 : 1;
    }
    return 1;
}

int gost2015_acpkm_omac_init(int nid, int enc, const unsigned char *inkey,
                             EVP_MD_CTX *omac_ctx,
                             unsigned char *outkey, unsigned char *kdf_seed)
{
    int ret = 0;
    unsigned char keys[64];
    const EVP_MD *md = EVP_get_digestbynid(nid);
    EVP_PKEY *mac_key;

    if (md == NULL)
        return 0;

    if (enc) {
        if (RAND_bytes(kdf_seed, 8) != 1)
            return 0;
    }

    if (gost_kdftree2012_256(keys, 64, inkey, 32,
       (const unsigned char *)"kdf tree", 8, kdf_seed, 8, 1) <= 0)
        return 0;

    mac_key = EVP_PKEY_new_mac_key(nid, NULL, keys+32, 32);

    if (mac_key == NULL)
        goto end;

    if (EVP_DigestInit_ex(omac_ctx, md, NULL) <= 0 ||
       EVP_DigestSignInit(omac_ctx, NULL, md, NULL, mac_key) <= 0)
        goto end;

    memcpy(outkey, keys, 32);

    ret = 1;
end:
    EVP_PKEY_free(mac_key);
    OPENSSL_cleanse(keys, sizeof(keys));

    return ret;
}

int init_zero_kdf_seed(unsigned char *kdf_seed)
{
    int is_zero_kdfseed = 1, i;
    for (i = 0; i < 8; i++) {
        if (kdf_seed[i] != 0)
            is_zero_kdfseed = 0;
    }

    return is_zero_kdfseed ? RAND_bytes(kdf_seed, 8) : 1;
}

#pragma endregion

#pragma region inits

inline void gost_mgm128_init(mgm128_context *ctx, void *key, block128_f block, mul128_f mul_gf, int blen)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->mul_gf = mul_gf;
    ctx->key = key;
    ctx->blocklen = blen;

    /* some precalculations place here
     *
     */
}

inline void gost_mgm128_init_clmul(mgm128_clmul_context *ctx, void *key, block128_f block, clmul128_f mul_gf, int blen)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->mul_gf = mul_gf;
    ctx->key = key;
    ctx->blocklen = blen;
}

inline void gost_mgm128_init_cllr(mgm128_cllr_context *ctx, void *key, block128_f block, clmul128_f mul_gf, int blen)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->mul_gf = mul_gf;
    ctx->key = key;
    ctx->blocklen = blen;
}

inline void gost_mgm128_init_cllr_n(mgm128_cllr_n_context *ctx, void *key, block128_f block, clmul128_f mul_gf, int blen)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->mul_gf = mul_gf;
    ctx->key = key;
    ctx->blocklen = blen;
}

inline void gost_mgm128_init_cllr_o(mgm128_cllr_o_context *ctx, void *key, block128_f block, clmul128_f mul_gf, int blen)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->mul_gf = mul_gf;
    ctx->key = key;
    ctx->blocklen = blen;
}

inline void gost_mgm128_init_cllr_no(mgm128_cllr_no_context *ctx, void *key, block128_f block, clmul128_f mul_gf, int blen)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->mul_gf = mul_gf;
    ctx->key = key;
    ctx->blocklen = blen;
}

#pragma endregion

#pragma region setiv

inline int gost_mgm128_setiv(mgm128_context *ctx, const unsigned char *iv, size_t len)
{
    ctx->len.u[0] = 0;          /* AAD length */
    ctx->len.u[1] = 0;          /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    ctx->ACi.u[0] = 0;
    ctx->ACi.u[1] = 0;
    ctx->sum.u[0] = 0;
    ctx->sum.u[1] = 0;

    memcpy(ctx->nonce.c, iv, ctx->blocklen);
    ctx->nonce.c[0] &= 0x7f;    /* IV - random vector, but 1st bit should be 0 */
    return 1;
}

inline int gost_mgm128_setiv_clmul(mgm128_clmul_context *ctx, const unsigned char *iv, size_t len)
{
    ctx->len.u[0] = 0;          /* AAD length */
    ctx->len.u[1] = 0;          /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    ctx->ACi.m[0] = _mm_setzero_si128();
    
    ctx->sum.m[0] = _mm_setzero_si128();
    
    memcpy(ctx->nonce.c, iv, ctx->blocklen);
    ctx->nonce.c[0] &= 0x7f;    /* IV - random vector, but 1st bit should be 0 */
    return 1;
}

inline int gost_mgm128_setiv_cllr(mgm128_cllr_context *ctx, const unsigned char *iv, size_t len)
{
    ctx->len.u[0] = 0;          /* AAD length */
    ctx->len.u[1] = 0;          /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    ctx->ACi.m[0] = _mm_setzero_si128();
    
    ctx->sum.m[0] = _mm_setzero_si128();
    ctx->sum.m[1] = _mm_setzero_si128();
    ctx->sum.m[2] = _mm_setzero_si128();

    memcpy(ctx->nonce.c, iv, ctx->blocklen);
    ctx->nonce.c[0] &= 0x7f;    /* IV - random vector, but 1st bit should be 0 */
    return 1;
}

inline int gost_mgm128_setiv_cllr_n(mgm128_cllr_n_context *ctx, const unsigned char *iv, size_t len)
{
    ctx->len.u[0] = 0;          /* AAD length */
    ctx->len.u[1] = 0;          /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    ctx->ACi_e.m[0] = _mm_setzero_si128();
    ctx->ACi_o.m[0] = _mm_setzero_si128();
    
    ctx->sum.m[0] = _mm_setzero_si128();
    ctx->sum.m[1] = _mm_setzero_si128();
    ctx->sum.m[2] = _mm_setzero_si128();

    memcpy(ctx->nonce.c, iv, ctx->blocklen);
    ctx->nonce.c[0] &= 0x7f;    /* IV - random vector, but 1st bit should be 0 */
    return 1;
}

inline int gost_mgm128_setiv_cllr_o(mgm128_cllr_o_context *ctx, const unsigned char *iv, size_t len)
{
    ctx->len.u[0] = 0;          /* AAD length */
    ctx->len.u[1] = 0;          /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    ctx->ACi_e.m[0] = _mm_setzero_si128();
    ctx->ACi_o.m[0] = _mm_setzero_si128();
    
    ctx->sum_e.m[0] = _mm_setzero_si128();
    ctx->sum_e.m[1] = _mm_setzero_si128();
    ctx->sum_e.m[2] = _mm_setzero_si128();

    ctx->sum_o.m[0] = _mm_setzero_si128();
    ctx->sum_o.m[1] = _mm_setzero_si128();
    ctx->sum_o.m[2] = _mm_setzero_si128();

    memcpy(ctx->nonce.c, iv, ctx->blocklen);
    ctx->nonce.c[0] &= 0x7f;    /* IV - random vector, but 1st bit should be 0 */
    return 1;
}

inline int gost_mgm128_setiv_cllr_no(mgm128_cllr_no_context *ctx, const unsigned char *iv, size_t len)
{
    ctx->len.u[0] = 0;          /* AAD length */
    ctx->len.u[1] = 0;          /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    ctx->ACi_e1.m[0] = _mm_setzero_si128();
    ctx->ACi_e2.m[0] = _mm_setzero_si128();
    ctx->ACi_o1.m[0] = _mm_setzero_si128();
    ctx->ACi_o2.m[0] = _mm_setzero_si128();
    
    ctx->sum_e.m[0] = _mm_setzero_si128();
    ctx->sum_e.m[1] = _mm_setzero_si128();
    ctx->sum_e.m[2] = _mm_setzero_si128();

    ctx->sum_o.m[0] = _mm_setzero_si128();
    ctx->sum_o.m[1] = _mm_setzero_si128();
    ctx->sum_o.m[2] = _mm_setzero_si128();

    memcpy(ctx->nonce.c, iv, ctx->blocklen);
    ctx->nonce.c[0] &= 0x7f;    /* IV - random vector, but 1st bit should be 0 */
    return 1;
}

#pragma endregion

inline int gost_mgm128_aad(mgm128_context *ctx, const unsigned char *aad, size_t len)
{
    size_t i;
    unsigned int n;
    uint64_t alen = ctx->len.u[0];
    block128_f block = ctx->block;
    mul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (ctx->len.u[1]) {
        GOSTerr(GOST_F_GOST_MGM128_AAD,
                GOST_R_BAD_ORDER);
        return -2;
    }

    if (alen == 0) {
        ctx->nonce.c[0] |= 0x80;
        (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
    }

    alen += len;
    if (alen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||      // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && alen < len)) {
            GOSTerr(GOST_F_GOST_MGM128_AAD,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[0] = alen;

    n = ctx->ares;
    if (n) {
        /* Finalize partial_data */
        while (n && len) {
            ctx->ACi.c[n] = *(aad++);
            --len;
            n = (n + 1) % bl;
        }
        if (n == 0) {
            (*block) (ctx->Zi.c, ctx->Hi.c, key);                   // H_i = E_K(Z_i)
            mul_gf(ctx->mul.u, ctx->Hi.u, ctx->ACi.u);              // H_i (x) A_i
            grasshopper_plus128((grasshopper_w128_t*)ctx->sum.u,    // acc XOR
              (grasshopper_w128_t*)ctx->sum.u, (grasshopper_w128_t*)ctx->mul.u);
            inc_counter(ctx->Zi.c, bl / 2);                              // Z_{i+1} = incr_l(Z_i)
        } else {
            ctx->ares = n;
            return 0;
        }
    }
    while (len >= bl) {
        (*block) (ctx->Zi.c, ctx->Hi.c, key);                       // H_i = E_K(Z_i)
        mul_gf(ctx->mul.u, ctx->Hi.u, (uint64_t *)aad);             // H_i (x) A_i
        grasshopper_plus128((grasshopper_w128_t*)ctx->sum.u,        // acc XOR
            (grasshopper_w128_t*)ctx->sum.u, (grasshopper_w128_t*)ctx->mul.u);
        inc_counter(ctx->Zi.c, bl / 2);                                  // Z_{i+1} = incr_l(Z_i)
        aad += bl;
        len -= bl;
    }
    if (len) {
        n = (unsigned int)len;
        for (i = 0; i < len; ++i)
            ctx->ACi.c[i] = aad[i];
    }

    ctx->ares = n;
    return 0;
}

inline int gost_mgm128_encrypt(mgm128_context *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
    size_t i;
    unsigned int n, mres;
    uint64_t alen = ctx->len.u[0];
    uint64_t mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    mul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (mlen == 0) {
        if (alen == 0) {
            ctx->nonce.c[0] |= 0x80;
            (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
        }
        ctx->nonce.c[0] &= 0x7f;
        (*block) (ctx->nonce.c, ctx->Yi.c, key);    // Y_1 = E_K(0 || nonce)
    }

    mlen += len;

    if (mlen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||     // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && mlen < len) ||
        (mlen + alen) > ((ossl_uintmax_t)(1) << (bl * 4 - 3))) {
            GOSTerr(GOST_F_GOST_MGM128_ENCRYPT,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[1] = mlen;

    mres = ctx->mres;

    if (ctx->ares) {
        /* First call to encrypt finalizes AAD */
        memset(ctx->ACi.c + ctx->ares, 0, bl - ctx->ares);
        (*block) (ctx->Zi.c, ctx->Hi.c, key);                   // H_i = E_K(Z_i)
        mul_gf(ctx->mul.u, ctx->Hi.u, ctx->ACi.u);              // H_i (x) A_i
        grasshopper_plus128((grasshopper_w128_t*)ctx->sum.u,    // acc XOR
            (grasshopper_w128_t*)ctx->sum.u, (grasshopper_w128_t*)ctx->mul.u);
        inc_counter(ctx->Zi.c, bl / 2);                         // Z_{i+1} = incr_l(Z_i)

        ctx->ares = 0;
    }

    n = mres % bl;
    // TODO: replace with full blocks processing
    for (i = 0; i < len; ++i) {
        if (n == 0) {
            (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
            inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})
        }
        ctx->ACi.c[n] = out[i] = in[i] ^ ctx->EKi.c[n];     // C_i = P_i (xor) E_K(Y_i)
        mres = n = (n + 1) % bl;
        if (n == 0) {
            (*block) (ctx->Zi.c, ctx->Hi.c, key);                   // H_i = E_K(Z_i)
            mul_gf(ctx->mul.u, ctx->Hi.u, ctx->ACi.u);              // H_i (x) C_i
            grasshopper_plus128((grasshopper_w128_t*)ctx->sum.u,    // acc XOR
                (grasshopper_w128_t*)ctx->sum.u, (grasshopper_w128_t*)ctx->mul.u);
            inc_counter(ctx->Zi.c, bl / 2);                         // Z_{i+1} = incr_l(Z_i)
        }
    }

    ctx->mres = mres;
    return 0;
}

/// @brief hashes one block of data
inline static int mgm128_hash_block(mgm128_context *ctx){
    block128_f block = ctx->block;
    mul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    (*block) (ctx->Zi.c, ctx->Hi.c, key);                       // H_i = E_K(Z_i)
    mul_gf(ctx->mul.u, ctx->Hi.u, ctx->ACi.u);                  // H_i (x) A_i
    grasshopper_plus128((grasshopper_w128_t*)ctx->sum.u,        // acc XOR
        (grasshopper_w128_t*)ctx->sum.u, (grasshopper_w128_t*)ctx->mul.u);
    inc_counter(ctx->Zi.c, bl / 2);                             // Z_{i+1} = incr_l(Z_i)

    return 0;
}

/// @brief fills the currently started block with zeroes, starting at index; hashes full block
inline static int mgm128_block_finalize(mgm128_context *ctx, unsigned index){
    int bl = ctx->blocklen;
    memset(ctx->ACi.c + index, 0, bl - index);
    mgm128_hash_block(ctx);
    return 0;
}

/// @brief fills the partial block with data, and processes it if it is full; updates address of in and values of len
inline static int mgm128_block_fill_bytewise(mgm128_context *ctx, const unsigned char *in, unsigned *rest, size_t *inLen)
{    
    int bl = ctx->blocklen;
    unsigned index = *rest;
    unsigned long len = *inLen;

    if(len == 0){
        return 0;
    }
    while (index && len) {
        ctx->ACi.c[index] = *(in++);
        --len;
        index = (index + 1) % bl;
    }
    if (index == 0) {     //a started block has been filled, process accordingly
        mgm128_hash_block(ctx);
    }
    //writing back updated "rest" and len index
    *rest = index;
    *inLen = len;
    return 0;
}

/// @brief processes a single full 128-bit block of *in
inline static int mgm128_block_full(mgm128_context *ctx, const unsigned char *in){
    //full blocks processing
    ctx->ACi.u[0] = *((uint64_t*)in);
    ctx->ACi.u[1] = *((uint64_t*)(in+8));
    mgm128_hash_block(ctx);
    return 0;
}

inline int gost_mgm128_block_aad(mgm128_context *ctx, const unsigned char *aad, size_t len)
{
    unsigned int n;
    uint64_t alen = ctx->len.u[0];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (ctx->len.u[1]) {
        GOSTerr(GOST_F_GOST_MGM128_AAD,
                GOST_R_BAD_ORDER);
        return -2;
    }

    if (alen == 0) {
        ctx->nonce.c[0] |= 0x80;
        (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
    }

    alen += len;
    if (alen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||      // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && alen < len)) {
            GOSTerr(GOST_F_GOST_MGM128_AAD,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[0] = alen;

    n = ctx->ares;
    if (n) {
        /* Finalize partial_data */
        mgm128_block_fill_bytewise(ctx, aad, &n, &len);
        if (len == 0) {
            ctx->ares = n;
            return 0;
        }
    }
    while (len >= bl) {
        mgm128_block_full(ctx, aad);
        aad += bl;
        len -= bl;
    }
    if (len) {
        mgm128_block_fill_bytewise(ctx, aad, &n, &len);
    }

    ctx->ares = n;
    return 0;
}

inline int gost_mgm128_block_encrypt(mgm128_context *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
    size_t i;
    unsigned int mres;
    uint64_t alen = ctx->len.u[0];
    uint64_t mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;
    union{
        grasshopper_w128_t m[1];
        uint64_t u[2];
        uint8_t c[16];
    } blk;

    if (mlen == 0) {
        if (alen == 0) {
            ctx->nonce.c[0] |= 0x80;
            (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
        }
        ctx->nonce.c[0] &= 0x7f;
        (*block) (ctx->nonce.c, ctx->Yi.c, key);    // Y_1 = E_K(0 || nonce)
    }

    mlen += len;

    if (mlen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||     // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && mlen < len) ||
        (mlen + alen) > ((ossl_uintmax_t)(1) << (bl * 4 - 3))) {
            GOSTerr(GOST_F_GOST_MGM128_ENCRYPT,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[1] = mlen;

    if (ctx->ares) {
        /* First call to encrypt finalizes AAD */
        mgm128_block_finalize(ctx, ctx->ares);
        ctx->ares = 0;
    }

    mres = ctx->mres;

    if(mres){   //process partial block of message leftover from last enc call
        int fill = bl - mres;

        if(len < fill){ //not enough data to fill the block, so process out and store in started ACi block
            for(i = 0; i < len; i++){
                ctx->ACi.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i]; // C_i = P_i (xor) E_K(Y_i)
            }
            
            ctx->mres = mres + len;
            return 0;
        }
        
        for(i = 0; i < mres; i++){ //load previous partial block
            blk.c[i] = ctx->ACi.c[i];
        }
    
        //process partial block
        for(i = 0; i < fill; i++){
            blk.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i];     // C_i = P_i (xor) E_K(Y_i)
        }
        size_t ptr = fill;
        mgm128_block_fill_bytewise(ctx, (unsigned char*)&blk.u, &mres, &ptr);
        //can ignore mres, since we verified earlier that "len" (bytes to write) is bigger than fill (free bytes left in current block)
        //also, because of that we check, we know that ptr is 0 and the in/out pointers are updated correctly with "fill" instead

        in += fill;
        out += fill;
        len -= fill;
    }

    while (len >= bl) {
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})

        grasshopper_plus128(&blk.m[0], (grasshopper_w128_t*)in,
                (grasshopper_w128_t*)ctx->EKi.u);    // C_i = P_i (xor) E_K(Y_i)
        mgm128_block_full(ctx, (unsigned char*)&blk.u);
        *(uint64_t*)out = blk.u[0];
        *(uint64_t*)(out+8) = blk.u[1];

        in += bl;
        out += bl;
        len -= bl;
    }

    if(len){
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})
        
        for(i = 0; i < len; i++){
            ctx->ACi.c[i] = out[i] = in[i] ^ ctx->EKi.c[i]; // C_i = P_i (xor) E_K(Y_i)
        }
    }

    ctx->mres = len;
    return 0;
}

/// @brief hashes one block of data for cllr
inline static int mgm128_hash_block_clmul(mgm128_clmul_context *ctx){
    block128_f block = ctx->block;
    clmul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    (*block) (ctx->Zi.c, ctx->Hi.c, key);                           // H_i = E_K(Z_i)
    mul_gf(ctx->mul.m, ctx->Hi.m, ctx->ACi.m);                      // H_i (x) A_i
    grasshopper_plus128_clmul(ctx->sum.m, ctx->sum.m, ctx->mul.m);  // acc XOR
    inc_counter(ctx->Zi.c, bl / 2);                                 // Z_{i+1} = incr_l(Z_i)

    return 0;
}

/// @brief fills the currently started block with zeroes, starting at index; hashes full block
inline static int mgm128_block_finalize_clmul(mgm128_clmul_context *ctx, unsigned index){
    int bl = ctx->blocklen;
    memset(ctx->ACi.c + index, 0, bl - index);
    mgm128_hash_block_clmul(ctx);
    return 0;
}

/// @brief fills the partial block with data, and processes it if it is full; updates address of in and values of len
inline static int mgm128_block_fill_bytewise_clmul(mgm128_clmul_context *ctx, const unsigned char *in, unsigned *rest, size_t *inLen)
{    
    int bl = ctx->blocklen;
    unsigned index = *rest;
    unsigned long len = *inLen;

    if(len == 0){
        return 0;
    }
    while (index && len) {
        ctx->ACi.c[index] = *(in++);
        --len;
        index = (index + 1) % bl;
    }
    if (index == 0) {     //a started block has been filled, process accordingly
        mgm128_hash_block_clmul(ctx);
    }
    //writing back updated "rest" and len index
    *rest = index;
    *inLen = len;
    return 0;
}

/// @brief processes a single full 128-bit block of *in
inline static int mgm128_block_full_clmul(mgm128_clmul_context *ctx, const unsigned char *in){
    //full blocks processing
    ctx->ACi.u[0] = *((uint64_t*)in);
    ctx->ACi.u[1] = *((uint64_t*)(in+8));
    mgm128_hash_block_clmul(ctx);
    return 0;
}

inline int gost_mgm128_clmul_aad(mgm128_clmul_context *ctx, const unsigned char *aad, size_t len)
{
    unsigned int n;
    uint64_t alen = ctx->len.u[0];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (ctx->len.u[1]) {
        GOSTerr(GOST_F_GOST_MGM128_AAD,
                GOST_R_BAD_ORDER);
        return -2;
    }

    if (alen == 0) {
        ctx->nonce.c[0] |= 0x80;
        (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
    }

    alen += len;
    if (alen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||      // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && alen < len)) {
            GOSTerr(GOST_F_GOST_MGM128_AAD,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[0] = alen;

    n = ctx->ares;
    if (n) {
        /* Finalize partial_data */
        mgm128_block_fill_bytewise_clmul(ctx, aad, &n, &len);
        if (len == 0) {
            ctx->ares = n;
            return 0;
        }
    }
    while (len >= bl) {
        mgm128_block_full_clmul(ctx, aad);
        aad += bl;
        len -= bl;
    }
    if (len) {
        mgm128_block_fill_bytewise_clmul(ctx, aad, &n, &len);
    }

    ctx->ares = n;
    return 0;
}

inline int gost_mgm128_clmul_encrypt(mgm128_clmul_context *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
    size_t i;
    unsigned int mres;
    uint64_t alen = ctx->len.u[0];
    uint64_t mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;
    union{
        __m128i m[1];
        uint64_t u[2];
        uint8_t c[16];
    } blk;

    if (mlen == 0) {
        if (alen == 0) {
            ctx->nonce.c[0] |= 0x80;
            (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
        }
        ctx->nonce.c[0] &= 0x7f;
        (*block) (ctx->nonce.c, ctx->Yi.c, key);    // Y_1 = E_K(0 || nonce)
    }

    mlen += len;

    if (mlen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||     // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && mlen < len) ||
        (mlen + alen) > ((ossl_uintmax_t)(1) << (bl * 4 - 3))) {
            GOSTerr(GOST_F_GOST_MGM128_ENCRYPT,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[1] = mlen;

    if (ctx->ares) {

        /* First call to encrypt finalizes AAD */
        mgm128_block_finalize_clmul(ctx, ctx->ares);
        ctx->ares = 0;
    }

    mres = ctx->mres;

    if(mres){   //process partial block of message leftover from last enc call
        int fill = bl - mres;

        if(len < fill){ //not enough data to fill the block, so process out and store in started ACi block
            for(i = 0; i < len; i++){
                ctx->ACi.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i]; // C_i = P_i (xor) E_K(Y_i)
            }
            
            ctx->mres = mres + len;
            return 0;
        }
        
        for(i = 0; i < mres; i++){
            blk.c[i] = ctx->ACi.c[i];
        }
    
        //process partial block
        for(i = 0; i < fill; i++){
            blk.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i];     // C_i = P_i (xor) E_K(Y_i)
        }
        size_t ptr = fill;
        mgm128_block_fill_bytewise_clmul(ctx, (unsigned char*)&blk.u, &mres, &ptr);

        in += fill;
        out += fill;
        len -= fill;
    }

    while (len >= bl) {
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})

        grasshopper_plus128_clmul(&blk.m[0], (__m128i *)in, ctx->EKi.m);    // C_i = P_i (xor) E_K(Y_i)
        mgm128_block_full_clmul(ctx, (unsigned char*)&blk.u);
        *(uint64_t*)out = blk.u[0];
        *(uint64_t*)(out+8) = blk.u[1];

        in += bl;
        out += bl;
        len -= bl;
    }

    if(len){
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})
        
        for(i = 0; i < len; i++){
            ctx->ACi.c[i] = out[i] = in[i] ^ ctx->EKi.c[i]; // C_i = P_i (xor) E_K(Y_i)
        }
    }

    ctx->mres = len;
    return 0;
}

/// @brief hashes one block of data for cllr
inline static int mgm128_hash_block_cllr(mgm128_cllr_context *ctx){
    block128_f block = ctx->block;
    clmul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    (*block) (ctx->Zi.c, ctx->Hi.c, key);                           // H_i = E_K(Z_i)
    mul_gf(ctx->mul.m, ctx->Hi.m, ctx->ACi.m);                      // H_i (x) A_i
    grasshopper_plus128_clmul_lr(ctx->sum.m, ctx->sum.m, ctx->mul.m);   // acc XOR
    inc_counter(ctx->Zi.c, bl / 2);                                 // Z_{i+1} = incr_l(Z_i)

    return 0;
}

/// @brief fills the currently started block with zeroes, starting at index; hashes full block
inline static int mgm128_block_finalize_cllr(mgm128_cllr_context *ctx, unsigned index){
    int bl = ctx->blocklen;
    memset(ctx->ACi.c + index, 0, bl - index);
    mgm128_hash_block_cllr(ctx);
    return 0;
}

/// @brief fills the partial block with data, and processes it if it is full; updates address of in and values of len
inline static int mgm128_block_fill_bytewise_cllr(mgm128_cllr_context *ctx, const unsigned char *in, unsigned *rest, size_t *inLen)
{    
    int bl = ctx->blocklen;
    unsigned index = *rest;
    unsigned long len = *inLen;

    if(len == 0){
        return 0;
    }
    while (index && len) {
        ctx->ACi.c[index] = *(in++);
        --len;
        index = (index + 1) % bl;
    }
    if (index == 0) {     //a started block has been filled, process accordingly
        mgm128_hash_block_cllr(ctx);
    }
    //writing back updated "rest" and len index
    *rest = index;
    *inLen = len;
    return 0;
}

/// @brief processes a single full 128-bit block of *in
inline static int mgm128_block_full_cllr(mgm128_cllr_context *ctx, const unsigned char *in){
    //full blocks processing
    ctx->ACi.u[0] = *((uint64_t*)in);
    ctx->ACi.u[1] = *((uint64_t*)(in+8));
    mgm128_hash_block_cllr(ctx);
    return 0;
}

inline int gost_mgm128_cllr_aad(mgm128_cllr_context *ctx, const unsigned char *aad, size_t len)
{
    unsigned int n;
    uint64_t alen = ctx->len.u[0];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (ctx->len.u[1]) {
        GOSTerr(GOST_F_GOST_MGM128_AAD,
                GOST_R_BAD_ORDER);
        return -2;
    }

    if (alen == 0) {
        ctx->nonce.c[0] |= 0x80;
        (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
    }

    alen += len;
    if (alen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||      // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && alen < len)) {
            GOSTerr(GOST_F_GOST_MGM128_AAD,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[0] = alen;

    n = ctx->ares;
    if (n) {
        /* Finalize partial_data */
        mgm128_block_fill_bytewise_cllr(ctx, aad, &n, &len);
        if (len == 0) {
            ctx->ares = n;
            return 0;
        }
    }
    while (len >= bl) {
        mgm128_block_full_cllr(ctx, aad);
        aad += bl;
        len -= bl;
    }
    if (len) {
        mgm128_block_fill_bytewise_cllr(ctx, aad, &n, &len);
    }

    ctx->ares = n;
    return 0;
}

inline int gost_mgm128_cllr_encrypt(mgm128_cllr_context *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
    size_t i;
    unsigned int mres;
    uint64_t alen = ctx->len.u[0];
    uint64_t mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;
    union{
        __m128i m[1];
        uint64_t u[2];
        uint8_t c[16];
    } blk;

    if (mlen == 0) {
        if (alen == 0) {
            ctx->nonce.c[0] |= 0x80;
            (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
        }
        ctx->nonce.c[0] &= 0x7f;
        (*block) (ctx->nonce.c, ctx->Yi.c, key);    // Y_1 = E_K(0 || nonce)
    }

    mlen += len;

    if (mlen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||     // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && mlen < len) ||
        (mlen + alen) > ((ossl_uintmax_t)(1) << (bl * 4 - 3))) {
            GOSTerr(GOST_F_GOST_MGM128_ENCRYPT,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[1] = mlen;

    if (ctx->ares) {

        /* First call to encrypt finalizes AAD */
        mgm128_block_finalize_cllr(ctx, ctx->ares);
        ctx->ares = 0;
    }

    mres = ctx->mres;

    if(mres){   //process partial block of message leftover from last enc call
        int fill = bl - mres;

        if(len < fill){ //not enough data to fill the block, so process out and store in started ACi block
            for(i = 0; i < len; i++){
                ctx->ACi.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i]; // C_i = P_i (xor) E_K(Y_i)
            }
            
            ctx->mres = mres + len;
            return 0;
        }
        
        for(i = 0; i < mres; i++){
            blk.c[i] = ctx->ACi.c[i];
        }
    
        //process partial block
        for(i = 0; i < fill; i++){
            blk.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i];     // C_i = P_i (xor) E_K(Y_i)
        }
        size_t ptr = fill;
        mgm128_block_fill_bytewise_cllr(ctx, (unsigned char*)&blk.u, &mres, &ptr);

        in += fill;
        out += fill;
        len -= fill;
    }

    while (len >= bl) {
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})

        grasshopper_plus128_clmul(&blk.m[0], (__m128i *)in, ctx->EKi.m);    // C_i = P_i (xor) E_K(Y_i)
        mgm128_block_full_cllr(ctx, (unsigned char*)&blk.u);
        *(uint64_t*)out = blk.u[0];
        *(uint64_t*)(out+8) = blk.u[1];

        in += bl;
        out += bl;
        len -= bl;
    }

    if(len){
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})
        
        for(i = 0; i < len; i++){
            ctx->ACi.c[i] = out[i] = in[i] ^ ctx->EKi.c[i]; // C_i = P_i (xor) E_K(Y_i)
        }
    }

    ctx->mres = len;
    return 0;
}

/// @brief hashes two blocks of data/one sum for nmh
inline static int mgm128_hash_even_block_nmh(mgm128_cllr_n_context *ctx){
    block128_f block = ctx->block;
    clmul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    //no need to use delayed reduction in first two additions, as the sum is calculated from input data and hash keys previous to any accumulation

    (*block) (ctx->Zi.c, ctx->Hi.c, key);                                   // H_i = E_K(Z_i)
    grasshopper_plus128_clmul(ctx->ACi_e.m, ctx->ACi_e.m, ctx->Hi.m);       // H_i (+) A_i_o
    inc_counter(ctx->Zi.c, bl / 2);                                         // Z_{i+1} = incr_l(Z_i)

    mul_gf(ctx->mul.m, ctx->ACi_e.m, ctx->ACi_o.m);                         // odd (x) even
    grasshopper_plus128_clmul_lr(ctx->sum.m, ctx->sum.m, ctx->mul.m);       // acc XOR

    ctx->oddSet = 0;
    return 0;
}

/// @brief prehashes one blocks of data
inline static int mgm128_hash_odd_block_nmh(mgm128_cllr_n_context *ctx){
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    (*block) (ctx->Zi.c, ctx->Hi.c, key);                                   // H_i = E_K(Z_i)
    grasshopper_plus128_clmul(ctx->ACi_o.m, ctx->ACi_o.m, ctx->Hi.m);       // H_i (+) A_i_e
    inc_counter(ctx->Zi.c, bl / 2);                                         // Z_{i+1} = incr_l(Z_i)

    ctx->oddSet = 1;
    return 0;
}

/// @brief pads an empty block before the length encoding with hash key added to an empty block
inline static int mgm128_pad_empty_odd_block_nmh(mgm128_cllr_n_context *ctx){
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    //no need to load zeroes to a block to then add the block key to it; instead load the block key to empty block directly
    (*block) (ctx->Zi.c, ctx->ACi_o.c, key);                                // A_i_o = E_K(Z_i)
    inc_counter(ctx->Zi.c, bl / 2);                                         // Z_{i+1} = incr_l(Z_i)

    ctx->oddSet = 1;
    return 0;
}

/// @brief fills the currently started block with zeroes, starting at index; hashes if both blocks are full
inline static int mgm128_block_finalize_pad_nmh(mgm128_cllr_n_context *ctx, unsigned index){
    int bl = ctx->blocklen;

    if(ctx->oddSet){
        memset(ctx->ACi_e.c + index, 0, bl - index);
        mgm128_hash_even_block_nmh(ctx);
    }else{
        memset(ctx->ACi_o.c + index, 0, bl - index);
        mgm128_hash_odd_block_nmh(ctx);
    }
    return 0;
}

/// @brief fills the partial block with data, and processes it if it is full; updates address of in and values of len
inline static int mgm128_block_fill_bytewise_nmh(mgm128_cllr_n_context *ctx, const unsigned char *in, unsigned *rest, size_t *inLen)
{    
    int bl = ctx->blocklen;
    unsigned index = *rest;
    unsigned long len = *inLen;

    if(len == 0){
        return 0;
    }

    if(ctx->oddSet){    //fill started block with data
        while (index && len) {
            ctx->ACi_e.c[index] = *(in++);
            --len;
            index = (index + 1) % bl;
        }
    }else{
        while (index && len) {
            ctx->ACi_o.c[index] = *(in++);
            --len;
            index = (index + 1) % bl;
        }
    }

    if (index == 0) {     //a started block has been filled, process accordingly
        if(ctx->oddSet){
            mgm128_hash_even_block_nmh(ctx);
        }else{
            mgm128_hash_odd_block_nmh(ctx);
        }
    }
    //writing back updated "rest" and len index
    *rest = index;
    *inLen = len;
    return 0;
}

/// @brief processes a single full 128-bit block of *in
inline static int mgm128_block_full_nmh(mgm128_cllr_n_context *ctx, const unsigned char *in){
    //full blocks processing
    if(ctx->oddSet){    //odd is set, so we process the even block
        ctx->ACi_e.u[0] = *((uint64_t*)in);
        ctx->ACi_e.u[1] = *((uint64_t*)(in+8));
        mgm128_hash_even_block_nmh(ctx);
    }else{
        ctx->ACi_o.u[0] = *((uint64_t*)in);
        ctx->ACi_o.u[1] = *((uint64_t*)(in+8));
        mgm128_hash_odd_block_nmh(ctx);
    }

    return 0;
}

inline int gost_mgm128_cllr_n_aad(mgm128_cllr_n_context *ctx, const unsigned char *aad, size_t len)
{
    unsigned int n;
    uint64_t alen = ctx->len.u[0];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (ctx->len.u[1]) {
        GOSTerr(GOST_F_GOST_MGM128_AAD,
                GOST_R_BAD_ORDER);
        return -2;
    }

    if (alen == 0) {
        ctx->nonce.c[0] |= 0x80;
        (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
    }

    alen += len;
    if (alen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||      // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && alen < len)) {
            GOSTerr(GOST_F_GOST_MGM128_AAD,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[0] = alen;

    n = ctx->ares;
    if (n) {    /* Finalize partial_data */
        mgm128_block_fill_bytewise_nmh(ctx, aad, &n, &len);
        if(len == 0){ //finished processing input
            ctx->ares = n;
            return 0;
        }
    }
    while (len >= bl) {
        mgm128_block_full_nmh(ctx, aad);
        aad += bl;
        len -= bl;
    }

    if (len) {  //write rest of aad < block size
        mgm128_block_fill_bytewise_nmh(ctx, aad, &n, &len);
    }

    ctx->ares = n;
    return 0;
}

inline int gost_mgm128_cllr_n_encrypt(mgm128_cllr_n_context *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
    size_t i;
    unsigned int mres;
    uint64_t alen = ctx->len.u[0];
    uint64_t mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;
    union{
        __m128i m[1];
        uint64_t u[2];
        uint8_t c[16];
    } blk;

    if (mlen == 0) {
        if (alen == 0) {
            ctx->nonce.c[0] |= 0x80;
            (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
        }
        ctx->nonce.c[0] &= 0x7f;
        (*block) (ctx->nonce.c, ctx->Yi.c, key);    // Y_1 = E_K(0 || nonce)
    }

    mlen += len;

    if (mlen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||     // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && mlen < len) ||
        (mlen + alen) > ((ossl_uintmax_t)(1) << (bl * 4 - 3))) {
            GOSTerr(GOST_F_GOST_MGM128_ENCRYPT,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[1] = mlen;

    if (ctx->ares) {        /* First call to encrypt finalizes AAD */
        mgm128_block_finalize_pad_nmh(ctx, ctx->ares);        
        ctx->ares = 0;
    }

    mres = ctx->mres;


    if(mres){   //process partial block of message leftover from last enc call
        int fill = bl - mres;

        if(len < fill){ //not enough data to fill the block, so process out and store in corresponding started ACi block
            if(ctx->oddSet){
                for(i = 0; i < len; i++){
                    ctx->ACi_e.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i]; // C_i = P_i (xor) E_K(Y_i)
                }
            }else{
                for(i = 0; i < len; i++){
                    ctx->ACi_o.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i]; // C_i = P_i (xor) E_K(Y_i)
                }
            }

            ctx->mres = mres + len;
            return 0;
        }
        
        //block will be filled, so load previous partial data to process
        if(ctx->oddSet){
            for(i = 0; i < mres; i++){
                blk.c[i] = ctx->ACi_e.c[i];
            }
        }else{
            for(i = 0; i < mres; i++){
                blk.c[i] = ctx->ACi_o.c[i];
            }
        }

        //process partial block
        for(i = 0; i < fill; i++){
            blk.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i];     // C_i = P_i (xor) E_K(Y_i)
        }
        size_t ptr = fill;
        mgm128_block_fill_bytewise_nmh(ctx, (unsigned char*)&blk.u, &mres, &ptr);

        in += fill;
        out += fill;
        len -= fill;
    }

    while (len >= bl) {
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})

        grasshopper_plus128_clmul(&blk.m[0], (__m128i *)in, ctx->EKi.m);    // C_i = P_i (xor) E_K(Y_i)
        mgm128_block_full_nmh(ctx, (unsigned char*)&blk.u);
        *(uint64_t*)out = blk.u[0];
        *(uint64_t*)(out+8) = blk.u[1];

        in += bl;
        out += bl;
        len -= bl;
    }

    if(len){
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})
        
        if(ctx->oddSet){
            for(i = 0; i < len; i++){
                ctx->ACi_e.c[i] = out[i] = in[i] ^ ctx->EKi.c[i]; // C_i = P_i (xor) E_K(Y_i)
            }
        }else{
            for(i = 0; i < len; i++){
                ctx->ACi_o.c[i] = out[i] = in[i] ^ ctx->EKi.c[i]; // C_i = P_i (xor) E_K(Y_i)
            }
        }
    }

    ctx->mres = len;
    return 0;
}

/// @brief hashes the first, odd of two blocks in optimised hashing
inline static int mgm128_hash_odd_block_optimised(mgm128_cllr_o_context *ctx){
    block128_f block = ctx->block;
    clmul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;

    (*block) (ctx->Zi.c, ctx->Hi.c, key);                       // H_i = E_K(Z_i)
    mul_gf(ctx->mul_o.m, ctx->Hi.m, ctx->ACi_o.m);              // H_i (x) A_i_o
    grasshopper_plus128_clmul_lr(ctx->sum_o.m, ctx->sum_o.m, ctx->mul_o.m);    // acc XOR odd

    ctx->oddSet = 1;
    return 0;
}

/// @brief hashes the second, even of two blocks in optimised hashing
inline static int mgm128_hash_even_block_optimised(mgm128_cllr_o_context *ctx){
    clmul128_f mul_gf = ctx->mul_gf;
    int bl = ctx->blocklen;

    mul_gf(ctx->mul_e.m, ctx->Hi.m, ctx->ACi_e.m);              // H_i (x) A_i_e
    grasshopper_plus128_clmul_lr(ctx->sum_e.m, ctx->sum_e.m, ctx->mul_e.m);    // acc XOR even
    inc_counter(ctx->Zi.c, bl / 2);                         // Z_{i+1} = incr_l(Z_i)

    ctx->oddSet = 0;
    return 0;
}

/// @brief fills the currently started block with zeroes, starting at index; hashes if both blocks are full
inline static int mgm128_block_finalize_optimised(mgm128_cllr_o_context *ctx, unsigned index){
    int bl = ctx->blocklen;

    if(ctx->oddSet){
        memset(ctx->ACi_e.c + index, 0, bl - index);
        mgm128_hash_even_block_optimised(ctx);
    }else{
        memset(ctx->ACi_o.c + index, 0, bl - index);
        mgm128_hash_odd_block_optimised(ctx);
    }
    return 0;
}

/// @brief fills the partial block with data, and processes it if it is full; updates address of in and values of len
inline static int mgm128_block_fill_bytewise_optimised(mgm128_cllr_o_context *ctx, const unsigned char *in, unsigned *rest, size_t *inLen)
{    
    int bl = ctx->blocklen;
    unsigned index = *rest;
    unsigned long len = *inLen;

    if(len == 0){
        return 0;
    }

    if(ctx->oddSet){    //fill started block with data
        while (index && len) {
            ctx->ACi_e.c[index] = *(in++);
            --len;
            index = (index + 1) % bl;
        }
    }else{
        while (index && len) {
            ctx->ACi_o.c[index] = *(in++);
            --len;
            index = (index + 1) % bl;
        }
    }

    if (index == 0) {     //a started block has been filled, process accordingly
        if(ctx->oddSet){
            mgm128_hash_even_block_optimised(ctx);
        }else{
            mgm128_hash_odd_block_optimised(ctx);
        }
    }
    //writing back updated "rest" and len index
    *rest = index;
    *inLen = len;
    return 0;
}

/// @brief processes a single full 128-bit block of *in
inline static int mgm128_block_full_optimised(mgm128_cllr_o_context *ctx, const unsigned char *in){
    //full blocks processing
    if(ctx->oddSet){    //odd is set, so we process the even block
        ctx->ACi_e.u[0] = *((uint64_t*)in);
        ctx->ACi_e.u[1] = *((uint64_t*)(in+8));
        mgm128_hash_even_block_optimised(ctx);
    }else{
        ctx->ACi_o.u[0] = *((uint64_t*)in);
        ctx->ACi_o.u[1] = *((uint64_t*)(in+8));
        mgm128_hash_odd_block_optimised(ctx);
    }

    return 0;
}

inline int gost_mgm128_cllr_o_aad(mgm128_cllr_o_context *ctx, const unsigned char *aad, size_t len)
{
    unsigned int n;
    uint64_t alen = ctx->len.u[0];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (ctx->len.u[1]) {
        GOSTerr(GOST_F_GOST_MGM128_AAD,
                GOST_R_BAD_ORDER);
        return -2;
    }

    if (alen == 0) {
        ctx->nonce.c[0] |= 0x80;
        (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
    }

    alen += len;
    if (alen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||      // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && alen < len)) {
            GOSTerr(GOST_F_GOST_MGM128_AAD,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[0] = alen;

    n = ctx->ares;
    if (n) {
        /* Finalize partial_data */
        mgm128_block_fill_bytewise_optimised(ctx, aad, &n, &len);
        if(len == 0){ //finished processing input
            ctx->ares = n;
            return 0;
        }
    }
    while (len >= bl) {
        mgm128_block_full_optimised(ctx, aad);
        aad += bl;
        len -= bl;
    }
    if (len) {  //write rest of aad < block size
        mgm128_block_fill_bytewise_optimised(ctx, aad, &n, &len);
    }

    ctx->ares = n;
    return 0;
}

inline int gost_mgm128_cllr_o_encrypt(mgm128_cllr_o_context *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
    size_t i;
    unsigned int mres;
    uint64_t alen = ctx->len.u[0];
    uint64_t mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;
    union{
        __m128i m[1];
        uint64_t u[2];
        uint8_t c[16];
    } blk;

    if (mlen == 0) {
        if (alen == 0) {
            ctx->nonce.c[0] |= 0x80;
            (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
        }
        ctx->nonce.c[0] &= 0x7f;
        (*block) (ctx->nonce.c, ctx->Yi.c, key);    // Y_1 = E_K(0 || nonce)
    }

    mlen += len;

    if (mlen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||     // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && mlen < len) ||
        (mlen + alen) > ((ossl_uintmax_t)(1) << (bl * 4 - 3))) {
            GOSTerr(GOST_F_GOST_MGM128_ENCRYPT,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[1] = mlen;

    if (ctx->ares) {        /* First call to encrypt finalizes AAD */
        mgm128_block_finalize_optimised(ctx, ctx->ares);        
        ctx->ares = 0;
    }

    mres = ctx->mres;

    if(mres){   //process partial block of message leftover from last enc call
        int fill = bl - mres;

        if(len < fill){ //not enough data to fill the block, so process out and store in corresponding started ACi block
            if(ctx->oddSet){
                for(i = 0; i < len; i++){
                    ctx->ACi_e.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i]; // C_i = P_i (xor) E_K(Y_i)
                }
            }else{
                for(i = 0; i < len; i++){
                    ctx->ACi_o.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i]; // C_i = P_i (xor) E_K(Y_i)
                }
            }

            ctx->mres = mres + len;
            return 0;
        }
        
        //block will be filled, so load previous partial data to process
        if(ctx->oddSet){
            for(i = 0; i < mres; i++){
                blk.c[i] = ctx->ACi_e.c[i];
            }
        }else{
            for(i = 0; i < mres; i++){
                blk.c[i] = ctx->ACi_o.c[i];
            }
        }

        //process partial block
        for(i = 0; i < fill; i++){
            blk.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i];     // C_i = P_i (xor) E_K(Y_i)
        }
        size_t ptr = fill;
        mgm128_block_fill_bytewise_optimised(ctx, (unsigned char*)&blk.u, &mres, &ptr);

        in += fill;
        out += fill;
        len -= fill;
    }

    while (len >= bl) {
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})

        grasshopper_plus128_clmul(&blk.m[0], (__m128i *)in, ctx->EKi.m);    // C_i = P_i (xor) E_K(Y_i)
        mgm128_block_full_optimised(ctx, (unsigned char*)&blk.u);
        *(uint64_t*)out = blk.u[0];
        *(uint64_t*)(out+8) = blk.u[1];

        in += bl;
        out += bl;
        len -= bl;
    }

    if(len){
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})
        
        if(ctx->oddSet){
            for(i = 0; i < len; i++){
                ctx->ACi_e.c[i] = out[i] = in[i] ^ ctx->EKi.c[i]; // C_i = P_i (xor) E_K(Y_i)
            }
        }else{
            for(i = 0; i < len; i++){
                ctx->ACi_o.c[i] = out[i] = in[i] ^ ctx->EKi.c[i]; // C_i = P_i (xor) E_K(Y_i)
            }
        }
    }

    ctx->mres = len;
    return 0;
}

/// @brief hashes the first odd block (M1) of data for nmh optimised
inline static int mgm128_hash_first_odd_block_nmh_optimised(mgm128_cllr_no_context *ctx){
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    (*block) (ctx->Zi.c, ctx->Hi1.c, key);                                // H_i = E_K(Z_i)
    grasshopper_plus128_clmul(ctx->ACi_o1.m, ctx->ACi_o1.m, ctx->Hi1.m);  // H_i (+) A_i_o1
    inc_counter(ctx->Zi.c, bl / 2);                                       // Z_{i+1} = incr_l(Z_i)

    ctx->firstSet = 1;
    ctx->oddSet = 1;
    return 0;
}

/// @brief hashes the first even block (M3) of data for nmh optimised
inline static int mgm128_hash_first_even_block_nmh_optimised(mgm128_cllr_no_context *ctx){
    
    grasshopper_plus128_clmul(ctx->ACi_e1.m, ctx->ACi_e1.m, ctx->Hi1.m);  // H_i (+) A_i_o1

    ctx->firstSet = 1;
    ctx->oddSet = 0;
    return 0;
}

/// @brief hashes the second odd block (M2) of data for nmh optimised
inline static int mgm128_hash_second_odd_block_nmh_optimised(mgm128_cllr_no_context *ctx){
    block128_f block = ctx->block;
    clmul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    (*block) (ctx->Zi.c, ctx->Hi2.c, key);                                  // H_i = E_K(Z_i)
    grasshopper_plus128_clmul(ctx->ACi_o2.m, ctx->ACi_o2.m, ctx->Hi2.m);    // H_i (+) A_i_o2
    inc_counter(ctx->Zi.c, bl / 2);                                         // Z_{i+1} = incr_l(Z_i)

    mul_gf(ctx->mul_o.m, ctx->ACi_o1.m, ctx->ACi_o2.m);                     // NMH: odd1 (x) odd2   
    grasshopper_plus128_clmul_lr(ctx->sum_o.m, ctx->sum_o.m, ctx->mul_o.m); // acc XOR odd
    
    ctx->firstSet = 0;
    return 0;
}

/// @brief hashes the second even block (M4) of data for nmh optimised
inline static int mgm128_hash_second_even_block_nmh_optimised(mgm128_cllr_no_context *ctx){
    clmul128_f mul_gf = ctx->mul_gf;

    grasshopper_plus128_clmul(ctx->ACi_e2.m, ctx->ACi_e2.m, ctx->Hi2.m);  // H_i (+) A_i_e2

    mul_gf(ctx->mul_e.m, ctx->ACi_e1.m, ctx->ACi_e2.m);                     // NMH: even1 (x) even2
    grasshopper_plus128_clmul_lr(ctx->sum_e.m, ctx->sum_e.m, ctx->mul_e.m); // acc XOR even

    ctx->firstSet = 0;
    return 0;
}


/// @brief fills the currently started block with zeroes, starting at index; hashes if all four blocks are full
inline static int mgm128_block_finalize_nmh_optimised(mgm128_cllr_no_context *ctx, unsigned index){
    int bl = ctx->blocklen;

    if(ctx->oddSet){
        if(ctx->firstSet){ //first odd was set, now second is too, so we continue with the even block
            memset(ctx->ACi_o2.c + index, 0, bl - index);
            mgm128_hash_second_odd_block_nmh_optimised(ctx);
        }else{ //second odd was set, so now the first even is set
            memset(ctx->ACi_e1.c + index, 0, bl - index);
            mgm128_hash_first_even_block_nmh_optimised(ctx);
        }
    }else{
        if(ctx->firstSet){//first even was set, now so is also second, so we can hash
            memset(ctx->ACi_e2.c + index, 0, bl - index);
            mgm128_hash_second_even_block_nmh_optimised(ctx);
        }else{ //second even was set, so now the first odd is set
            memset(ctx->ACi_o1.c + index, 0, bl - index);
            mgm128_hash_first_odd_block_nmh_optimised(ctx);
        }
    }
    return 0;
}

/// @brief fills the partial block with data, and processes it if it is full; updates address of in and values of len
inline static int mgm128_block_fill_bytewise_nmh_optimised(mgm128_cllr_no_context *ctx, const unsigned char *in, unsigned *rest, size_t *inLen)
{    
    int bl = ctx->blocklen;
    unsigned index = *rest;
    unsigned long len = *inLen;

    if(len == 0){
        return 0;
    }

    if(ctx->oddSet){    //fill started block with data
        if(ctx->firstSet){
            while (index && len) {          //first odd was set, now we set the second one
                ctx->ACi_o2.c[index] = *(in++);
                --len;
                index = (index + 1) % bl;
            }    
        }else{                          //second odd was set, so now we set the first even
            while (index && len) {
                ctx->ACi_e1.c[index] = *(in++);
                --len;
                index = (index + 1) % bl;
            }
        }
    }else{
        if(ctx->firstSet){              //first even was set, now we set the second one
            while (index && len) {
                ctx->ACi_e2.c[index] = *(in++);
                --len;
                index = (index + 1) % bl;
            }
        }else{                          //second even was set, so now we set the first odd
            while (index && len) {
                ctx->ACi_o1.c[index] = *(in++);
                --len;
                index = (index + 1) % bl;
            }
        }
    }

    if (index == 0) {     //a started block has been filled, process accordingly
        if(ctx->oddSet){
            if(ctx->firstSet){ //first odd was set, now second is too, so we continue with the even block
                mgm128_hash_second_odd_block_nmh_optimised(ctx);
            }else{  //second odd was set, so now the first even is set
                mgm128_hash_first_even_block_nmh_optimised(ctx);
            }
        }else{
            if(ctx->firstSet){ //first even was set, now so is also second, so we can hash
                mgm128_hash_second_even_block_nmh_optimised(ctx);                 
            }else{  //second even was set, so now the first odd is set
                mgm128_hash_first_odd_block_nmh_optimised(ctx);
            }
        }
    }
    //writing back updated "rest" and len index
    *rest = index;
    *inLen = len;
    return 0;
}

/// @brief processes a single full 128-bit block of *in
inline static int mgm128_block_full_nmh_optimised(mgm128_cllr_no_context *ctx, const unsigned char *in){
    //full blocks processing
    if(ctx->oddSet){
        if(ctx->firstSet){ //first odd was set, now second is too, so we continue with the even block
            ctx->ACi_o2.u[0] = *((uint64_t*)in);
            ctx->ACi_o2.u[1] = *((uint64_t*)(in+8));
            mgm128_hash_second_odd_block_nmh_optimised(ctx);
        }else{  //second odd was set, so now the first even is set
            ctx->ACi_e1.u[0] = *((uint64_t*)in);
            ctx->ACi_e1.u[1] = *((uint64_t*)(in+8));
            mgm128_hash_first_even_block_nmh_optimised(ctx);
        }
    }else{
        if(ctx->firstSet){ //first even was set, now so is also second, so we can hash
            ctx->ACi_e2.u[0] = *((uint64_t*)in);
            ctx->ACi_e2.u[1] = *((uint64_t*)(in+8));
            mgm128_hash_second_even_block_nmh_optimised(ctx);                
        }else{  //second even was set, so now the first odd is set
            ctx->ACi_o1.u[0] = *((uint64_t*)in);
            ctx->ACi_o1.u[1] = *((uint64_t*)(in+8));
            mgm128_hash_first_odd_block_nmh_optimised(ctx);
        }
    }

    return 0;
}

/// @brief adds length encoding to the last block, padding previous blocks if necessary
inline static int mgm128_block_encode_length_nmh_optimised(mgm128_cllr_no_context *ctx, const unsigned char *in){
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    //if second block has been set, need zero padding. 
    if(!ctx->firstSet){
        if(ctx->oddSet){ //since oddSet is true if o1 or o2 were just set, and firstSet is false, we know that o2 is set last
            //since 2BO is used, the hash key has been precomputed earlier, so we can reuse it.
            grasshopper_plus128_clmul(ctx->ACi_e1.m, ctx->ACi_e1.m, ctx->Hi1.m);  // H_i (+) A_i_o1
        }else{
            //since nmh is used and we need a new key, we can skip addition and store the newly created block key directly
            (*block) (ctx->Zi.c, ctx->ACi_o1.c, key);            // H_i = E_K(Z_i)
            inc_counter(ctx->Zi.c, bl / 2);
        }
    }

    //full blocks processing
    if(ctx->oddSet){
        //first even was set, length will be in second even
        ctx->ACi_e2.u[0] = *((uint64_t*)in);
        ctx->ACi_e2.u[1] = *((uint64_t*)(in+8));
        mgm128_hash_second_even_block_nmh_optimised(ctx);
    }else{
        //first odd was set, length will be in second odd
        ctx->ACi_o2.u[0] = *((uint64_t*)in);
        ctx->ACi_o2.u[1] = *((uint64_t*)(in+8));
        mgm128_hash_second_odd_block_nmh_optimised(ctx);
    }

    return 0;
}

inline int gost_mgm128_cllr_no_aad(mgm128_cllr_no_context *ctx, const unsigned char *aad, size_t len)
{
    unsigned int n;
    uint64_t alen = ctx->len.u[0];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (ctx->len.u[1]) {
        GOSTerr(GOST_F_GOST_MGM128_AAD,
                GOST_R_BAD_ORDER);
        return -2;
    }

    if (alen == 0) {
        ctx->nonce.c[0] |= 0x80;
        (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
    }

    alen += len;
    if (alen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||      // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && alen < len)) {
            GOSTerr(GOST_F_GOST_MGM128_AAD,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[0] = alen;

    n = ctx->ares;
    if (n) {    /* Finalize partial_data */
        mgm128_block_fill_bytewise_nmh_optimised(ctx, aad, &n, &len);
        if(len == 0){ //finished processing input
            ctx->ares = n;
            return 0;
        }
    }
    while (len >= bl) {
        mgm128_block_full_nmh_optimised(ctx, aad);
        aad += bl;
        len -= bl;
    }

    if (len) {  //write rest of aad < block size
        mgm128_block_fill_bytewise_nmh_optimised(ctx, aad, &n, &len);
    }

    ctx->ares = n;
    return 0;
}

inline int gost_mgm128_cllr_no_encrypt(mgm128_cllr_no_context *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
    size_t i;
    unsigned int mres;
    uint64_t alen = ctx->len.u[0];
    uint64_t mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;
    union{
        __m128i m[1];
        uint64_t u[2];
        uint8_t c[16];
    } blk;

    if (mlen == 0) {
        if (alen == 0) {
            ctx->nonce.c[0] |= 0x80;
            (*block) (ctx->nonce.c, ctx->Zi.c, key);    // Z_1 = E_K(1 || nonce)
        }
        ctx->nonce.c[0] &= 0x7f;
        (*block) (ctx->nonce.c, ctx->Yi.c, key);    // Y_1 = E_K(0 || nonce)
    }

    mlen += len;

    if (mlen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||     // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && mlen < len) ||
        (mlen + alen) > ((ossl_uintmax_t)(1) << (bl * 4 - 3))) {
            GOSTerr(GOST_F_GOST_MGM128_ENCRYPT,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[1] = mlen;

    if (ctx->ares) {        /* First call to encrypt finalizes AAD */
        mgm128_block_finalize_nmh_optimised(ctx, ctx->ares);        
        ctx->ares = 0;
    }
    
    mres = ctx->mres;

    if(mres){   //process partial block of message leftover from last enc call
        int fill = bl - mres;

        if(len < fill){ //not enough data to fill the block, so process out and store in corresponding started ACi block
            if(ctx->oddSet){
                 if(ctx->firstSet){
                    for(i = 0; i < len; i++){
                        ctx->ACi_o2.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i]; // C_i = P_i (xor) E_K(Y_i)
                    }
                }else{
                    for(i = 0; i < len; i++){
                        ctx->ACi_e1.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i]; // C_i = P_i (xor) E_K(Y_i)
                    }
                }
            }else{
                if(ctx->firstSet){
                    for(i = 0; i < len; i++){
                        ctx->ACi_e2.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i]; // C_i = P_i (xor) E_K(Y_i)
                    }
                }else{
                    for(i = 0; i < len; i++){
                        ctx->ACi_o1.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i]; // C_i = P_i (xor) E_K(Y_i)
                    }
                }
            }

            ctx->mres = mres + len;
            return 0;
        }
        
        //block will be filled, so load previous partial data to process
        if(ctx->oddSet){
             if(ctx->firstSet){
                for(i = 0; i < mres; i++){
                    blk.c[i] = ctx->ACi_o2.c[i];
                }
            }else{
                for(i = 0; i < mres; i++){
                    blk.c[i] = ctx->ACi_e1.c[i];
                }
            }
        }else{
            if(ctx->firstSet){
                for(i = 0; i < mres; i++){
                    blk.c[i] = ctx->ACi_e2.c[i];
                }
            }else{
                for(i = 0; i < mres; i++){
                    blk.c[i] = ctx->ACi_o1.c[i];
                }
            }
        }

        //process partial block
        for(i = 0; i < fill; i++){
            blk.c[mres + i] = out[i] = in[i] ^ ctx->EKi.c[mres + i];     // C_i = P_i (xor) E_K(Y_i)
        }
        size_t ptr = fill;
        mgm128_block_fill_bytewise_nmh_optimised(ctx, (unsigned char*)&blk.u, &mres, &ptr);

        in += fill;
        out += fill;
        len -= fill;
    }

    while (len >= bl) {
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})

        grasshopper_plus128_clmul(&blk.m[0], (__m128i *)in, ctx->EKi.m);    // C_i = P_i (xor) E_K(Y_i)
        mgm128_block_full_nmh_optimised(ctx, (unsigned char*)&blk.u);
        *(uint64_t*)out = blk.u[0];
        *(uint64_t*)(out+8) = blk.u[1];

        in += bl;
        out += bl;
        len -= bl;
    }

    if(len){
        (*block) (ctx->Yi.c, ctx->EKi.c, key);          // E_K(Y_i)
        inc_counter(ctx->Yi.c + bl / 2, bl / 2);        // Y_i = incr_r(Y_{i-1})
        
        if(ctx->oddSet){
            if(ctx->firstSet){
                for(i = 0; i < len; i++){
                    ctx->ACi_o2.c[i] = out[i] = in[i] ^ ctx->EKi.c[i]; // C_i = P_i (xor) E_K(Y_i)
                }
            }else{
                for(i = 0; i < len; i++){
                    ctx->ACi_e1.c[i] = out[i] = in[i] ^ ctx->EKi.c[i]; // C_i = P_i (xor) E_K(Y_i)
                }
            }
        }else{
            if(ctx->firstSet){
                for(i = 0; i < len; i++){
                    ctx->ACi_e2.c[i] = out[i] = in[i] ^ ctx->EKi.c[i]; // C_i = P_i (xor) E_K(Y_i)
                }
            }else{
                for(i = 0; i < len; i++){
                    ctx->ACi_o1.c[i] = out[i] = in[i] ^ ctx->EKi.c[i]; // C_i = P_i (xor) E_K(Y_i)
                }
            }
        }
    }

    ctx->mres = len;
    return 0;
}

#pragma region finish

inline int gost_mgm128_finish(mgm128_context *ctx, const unsigned char *tag, size_t len)
{
    uint64_t alen = ctx->len.u[0] << 3;
    uint64_t clen = ctx->len.u[1] << 3;
    block128_f block = ctx->block;
    mul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (ctx->mres || ctx->ares) {
        /* First call to encrypt finalizes AAD/ENC */
        memset(ctx->ACi.c + ctx->ares + ctx->mres, 0, bl - (ctx->ares + ctx->mres));
        (*block) (ctx->Zi.c, ctx->Hi.c, key);                   // H_i = E_K(Z_i)
        mul_gf(ctx->mul.u, ctx->Hi.u, ctx->ACi.u);              // H_i (x) [A_i or C_i]
        grasshopper_plus128((grasshopper_w128_t*)ctx->sum.u,    // acc XOR
            (grasshopper_w128_t*)ctx->sum.u, (grasshopper_w128_t*)ctx->mul.u);
        inc_counter(ctx->Zi.c, bl / 2);                         // Z_{i+1} = incr_l(Z_i)
    }

#ifdef L_ENDIAN
    alen = BSWAP64(alen);
    clen = BSWAP64(clen);
#endif
    if (bl == 16) {
        ctx->len.u[0] = alen;
        ctx->len.u[1] = clen;
    } else {
#ifdef L_ENDIAN
        ctx->len.u[0] = (alen >> 32) | clen;
#else
        ctx->len.u[0] = (alen << 32) | clen;
#endif
        ctx->len.u[1] = 0;
    }

    (*block) (ctx->Zi.c, ctx->Hi.c, key);                   // H_i = E_K(Z_i)
    mul_gf(ctx->mul.u, ctx->Hi.u, ctx->len.u);              // H_i (x) (len(A) || len(C))
    grasshopper_plus128((grasshopper_w128_t*)ctx->sum.u,    // acc XOR
            (grasshopper_w128_t*)ctx->sum.u, (grasshopper_w128_t*)ctx->mul.u);
    (*block) (ctx->sum.c, ctx->tag.c, key);                 // E_K(sum)

    if (tag && len <= sizeof(ctx->tag))
        return CRYPTO_memcmp(ctx->tag.c, tag, len);         // MSB_S(E_K(sum))
    else
        return -1;
}

inline int gost_mgm128_block_finish(mgm128_context *ctx, const unsigned char *tag, size_t len)
{
    uint64_t alen = ctx->len.u[0] << 3;
    uint64_t clen = ctx->len.u[1] << 3;
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (ctx->mres || ctx->ares) {
        /* First call to encrypt finalizes AAD/ENC */
        mgm128_block_finalize(ctx, ctx->ares + ctx->mres);
    }

#ifdef L_ENDIAN
    alen = BSWAP64(alen);
    clen = BSWAP64(clen);
#endif
    if (bl == 16) {
        ctx->len.u[0] = alen;
        ctx->len.u[1] = clen;
    } else {
#ifdef L_ENDIAN
        ctx->len.u[0] = (alen >> 32) | clen;
#else
        ctx->len.u[0] = (alen << 32) | clen;
#endif
        ctx->len.u[1] = 0;
    }

    mgm128_block_full(ctx, (unsigned char*)ctx->len.u);     //last block (len(A)||len(C))
    (*block) (ctx->sum.c, ctx->tag.c, key);                 // E_K(sum)

    if (tag && len <= sizeof(ctx->tag))
        return CRYPTO_memcmp(ctx->tag.c, tag, len);         // MSB_S(E_K(sum))
    else
        return -1;
}

inline int gost_mgm128_clmul_finish(mgm128_clmul_context *ctx, const unsigned char *tag, size_t len)
{
    uint64_t alen = ctx->len.u[0] << 3;
    uint64_t clen = ctx->len.u[1] << 3;
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;


    if (ctx->mres || ctx->ares) {
        /* First call to encrypt finalizes AAD/ENC */
        mgm128_block_finalize_clmul(ctx, ctx->ares + ctx->mres);
    }

#ifdef L_ENDIAN
    alen = BSWAP64(alen);
    clen = BSWAP64(clen);
#endif
    if (bl == 16) {
        ctx->len.u[0] = alen;
        ctx->len.u[1] = clen;
    } else {
#ifdef L_ENDIAN
        ctx->len.u[0] = (alen >> 32) | clen;
#else
        ctx->len.u[0] = (alen << 32) | clen;
#endif
        ctx->len.u[1] = 0;
    }

    mgm128_block_full_clmul(ctx, (unsigned char*)ctx->len.m);     //last block (len(A)||len(C))
    (*block) (ctx->sum.c, ctx->tag.c, key);                 // E_K(sum)

    if (tag && len <= sizeof(ctx->tag))
        return CRYPTO_memcmp(ctx->tag.c, tag, len);         // MSB_S(E_K(sum))
    else
        return -1;
}

inline int gost_mgm128_cllr_finish(mgm128_cllr_context *ctx, const unsigned char *tag, size_t len)
{
    uint64_t alen = ctx->len.u[0] << 3;
    uint64_t clen = ctx->len.u[1] << 3;
    block128_f block = ctx->block;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (ctx->mres || ctx->ares) {
        /* First call to encrypt finalizes AAD/ENC */
        mgm128_block_finalize_cllr(ctx, ctx->ares + ctx->mres);
    }

#ifdef L_ENDIAN
    alen = BSWAP64(alen);
    clen = BSWAP64(clen);
#endif
    if (bl == 16) {
        ctx->len.u[0] = alen;
        ctx->len.u[1] = clen;
    } else {
#ifdef L_ENDIAN
        ctx->len.u[0] = (alen >> 32) | clen;
#else
        ctx->len.u[0] = (alen << 32) | clen;
#endif
        ctx->len.u[1] = 0;
    }

    mgm128_block_full_cllr(ctx, (unsigned char*)ctx->len.m);     //last block (len(A)||len(C))

    gf128_mul_clmul_jr(ctx->sum.m, ctx->sum.m);                         //do reduction
    (*block) (ctx->sum.c, ctx->tag.c, key);                             // E_K(sum)
    
    if (tag && len <= sizeof(ctx->tag))
        return CRYPTO_memcmp(ctx->tag.c, tag, len);         // MSB_S(E_K(sum))
    else
        return -1;
}

inline int gost_mgm128_cllr_n_finish(mgm128_cllr_n_context *ctx, const unsigned char *tag, size_t len)
{
    uint64_t alen = ctx->len.u[0] << 3;
    uint64_t clen = ctx->len.u[1] << 3;
    block128_f block = ctx->block;
    void *key = ctx->key;
    
    if (ctx->mres || ctx->ares) {
        // First call to finish finalizes AAD/ENC
        mgm128_block_finalize_pad_nmh(ctx, ctx->ares + ctx->mres);
    }
    
    if(!ctx->oddSet){                                                   //zero padding before length encoding
        mgm128_pad_empty_odd_block_nmh(ctx);
    }
   
#ifdef L_ENDIAN
    alen = BSWAP64(alen);
    clen = BSWAP64(clen);
#endif
    ctx->len.u[0] = alen;
    ctx->len.u[1] = clen;

    mgm128_block_full_nmh(ctx,(unsigned char*)ctx->len.m);     //last block (len(A)||len(C))
        
    gf128_mul_clmul_jr(ctx->sum.m, ctx->sum.m);                         //do reduction
    (*block) (ctx->sum.c, ctx->tag.c, key);                             // E_K(sum)

    if (tag && len <= sizeof(ctx->tag))
        return CRYPTO_memcmp(ctx->tag.c, tag, len);                     // MSB_S(E_K(sum))
    else
        return -1;
}

inline int gost_mgm128_cllr_o_finish(mgm128_cllr_o_context *ctx, const unsigned char *tag, size_t len)
{
    uint64_t alen = ctx->len.u[0] << 3;
    uint64_t clen = ctx->len.u[1] << 3;
    block128_f block = ctx->block;
    clmul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;
    int bl = ctx->blocklen;
    

    if (ctx->mres || ctx->ares) {
        // First call to finish finalizes AAD/ENC
        mgm128_block_finalize_optimised(ctx, ctx->ares + ctx->mres);
    }
    
    if(!ctx->oddSet){                                                   //zero padding before last block
        memset(ctx->ACi_o.c, 0, bl);
        mgm128_hash_odd_block_optimised(ctx);
    }
   
#ifdef L_ENDIAN
    alen = BSWAP64(alen);
    clen = BSWAP64(clen);
#endif
    ctx->len.u[0] = alen;
    ctx->len.u[1] = clen;

    mgm128_block_full_optimised(ctx,(unsigned char*)ctx->len.m);     //last block (len(A)||len(C))
    
    //combine even and odd blocks, store in sum_even:
    (*block) (ctx->Zi.c, ctx->Hi.c, key);                       // H_i = E_K(Z_i)  - no need to increase the counter any more, as this is its last use
    gf128_mul_clmul_jr(ctx->sum_o.m, ctx->sum_o.m);                       //do reduction
    mul_gf(ctx->mul_o.m, ctx->Hi.m, ctx->sum_o.m);              // H_i (x) A_i_o
    grasshopper_plus128_clmul_lr(ctx->sum_e.m, ctx->sum_e.m, ctx->mul_o.m);    // acc XOR

    gf128_mul_clmul_jr(ctx->sum_e.m, ctx->sum_e.m);                       //do reduction
    (*block) (ctx->sum_e.c, ctx->tag.c, key);                             // E_K(sum)

    if (tag && len <= sizeof(ctx->tag))
        return CRYPTO_memcmp(ctx->tag.c, tag, len);                     // MSB_S(E_K(sum))
    else
        return -1;
}

inline int gost_mgm128_cllr_no_finish(mgm128_cllr_no_context *ctx, const unsigned char *tag, size_t len)
{
    uint64_t alen = ctx->len.u[0] << 3;
    uint64_t clen = ctx->len.u[1] << 3;
    block128_f block = ctx->block;
    clmul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;
    
    if (ctx->mres || ctx->ares) {
        // First call to finish finalizes AAD/ENC
        mgm128_block_finalize_nmh_optimised(ctx, ctx->ares + ctx->mres);
    }
    
#ifdef L_ENDIAN
    alen = BSWAP64(alen);
    clen = BSWAP64(clen);
#endif
    ctx->len.u[0] = alen;
    ctx->len.u[1] = clen;

    mgm128_block_encode_length_nmh_optimised(ctx,(unsigned char*)ctx->len.m);     //last block (len(A)||len(C))

    //combine even and odd blocks, store in sum_even:
    (*block) (ctx->Zi.c, ctx->Hi1.c, key);                       // H_i = E_K(Z_i)  - no need to increase the counter any more, as this is its last use
    gf128_mul_clmul_jr(ctx->sum_o.m, ctx->sum_o.m);                       //do reduction
    mul_gf(ctx->mul_o.m, ctx->Hi1.m, ctx->sum_o.m);              // H_i (x) sum_odd
    grasshopper_plus128_clmul_lr(ctx->sum_e.m, ctx->sum_e.m, ctx->mul_o.m);    // sum_even XOR (H_i (x) sum_odd)

    gf128_mul_clmul_jr(ctx->sum_e.m, ctx->sum_e.m);                       //do reduction
    (*block) (ctx->sum_e.c, ctx->tag.c, key);                             // E_K(sum)

    if (tag && len <= sizeof(ctx->tag))
        return CRYPTO_memcmp(ctx->tag.c, tag, len);                     // MSB_S(E_K(sum))
    else
        return -1;
}

#pragma endregion

#pragma region tag

inline void gost_mgm128_tag(mgm128_context *ctx, unsigned char *tag, size_t len)
{
    gost_mgm128_finish(ctx, NULL, 0);
    memcpy(tag, ctx->tag.c,
           len <= sizeof(ctx->tag.c) ? len : sizeof(ctx->tag.c));
}

inline void gost_mgm128_block_tag(mgm128_context *ctx, unsigned char *tag, size_t len)
{
    gost_mgm128_block_finish(ctx, NULL, 0);
    memcpy(tag, ctx->tag.c,
           len <= sizeof(ctx->tag.c) ? len : sizeof(ctx->tag.c));
}

inline void gost_mgm128_clmul_tag(mgm128_clmul_context *ctx, unsigned char *tag, size_t len)
{
    gost_mgm128_clmul_finish(ctx, NULL, 0);
    memcpy(tag, ctx->tag.c,
           len <= sizeof(ctx->tag.c) ? len : sizeof(ctx->tag.c));
}

inline void gost_mgm128_cllr_tag(mgm128_cllr_context *ctx, unsigned char *tag, size_t len)
{
    gost_mgm128_cllr_finish(ctx, NULL, 0);
    memcpy(tag, ctx->tag.c,
           len <= sizeof(ctx->tag.c) ? len : sizeof(ctx->tag.c));
}

inline void gost_mgm128_cllr_n_tag(mgm128_cllr_n_context *ctx, unsigned char *tag, size_t len)
{
    gost_mgm128_cllr_n_finish(ctx, NULL, 0);
    memcpy(tag, ctx->tag.c,
           len <= sizeof(ctx->tag.c) ? len : sizeof(ctx->tag.c));
}

inline void gost_mgm128_cllr_o_tag(mgm128_cllr_o_context *ctx, unsigned char *tag, size_t len)
{
    gost_mgm128_cllr_o_finish(ctx, NULL, 0);
    memcpy(tag, ctx->tag.c,
           len <= sizeof(ctx->tag.c) ? len : sizeof(ctx->tag.c));
}

inline void gost_mgm128_cllr_no_tag(mgm128_cllr_no_context *ctx, unsigned char *tag, size_t len)
{
    gost_mgm128_cllr_no_finish(ctx, NULL, 0);
    memcpy(tag, ctx->tag.c,
           len <= sizeof(ctx->tag.c) ? len : sizeof(ctx->tag.c));
}

#pragma endregion

inline int gost_mgm128_decrypt(mgm128_context *ctx, const unsigned char *in,
                          unsigned char *out, size_t len)
{
    size_t i;
    unsigned int n, mres;
    uint64_t alen = ctx->len.u[0];
    uint64_t mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    mul128_f mul_gf = ctx->mul_gf;
    void *key = ctx->key;
    int bl = ctx->blocklen;

    if (mlen == 0) {
        ctx->nonce.c[0] &= 0x7f;
        (*block) (ctx->nonce.c, ctx->Yi.c, key);  // Y_1 = E_K(0 || nonce)
    }

    mlen += len;
    if (mlen > ((ossl_uintmax_t)(1) << (bl * 4 - 3)) ||     // < 2^(n/2)  (len stores in bytes)
        (sizeof(len) == 8 && mlen < len) ||
        (mlen + alen) > ((ossl_uintmax_t)(1) << (bl * 4 - 3))) {
            GOSTerr(GOST_F_GOST_MGM128_DECRYPT,
                    GOST_R_DATA_TOO_LARGE);
            return -1;
        }
    ctx->len.u[1] = mlen;

    mres = ctx->mres;

    if (ctx->ares) {
        /* First call to encrypt finalizes AAD */
        memset(ctx->ACi.c + ctx->ares, 0, bl - ctx->ares);
        (*block) (ctx->Zi.c, ctx->Hi.c, key);                   // H_i = E_K(Z_i)
        mul_gf(ctx->mul.u, ctx->Hi.u, ctx->ACi.u);              // H_i (x) A_i
        grasshopper_plus128((grasshopper_w128_t*)ctx->sum.u,    // acc XOR
            (grasshopper_w128_t*)ctx->sum.u, (grasshopper_w128_t*)ctx->mul.u);
        inc_counter(ctx->Zi.c, bl / 2);                         // Z_{i+1} = incr_l(Z_i)

        ctx->ares = 0;
    }

    n = mres % bl;
    // TODO: replace with full blocks processing
    for (i = 0; i < len; ++i) {
        uint8_t c;
        if (n == 0) {
            (*block) (ctx->Yi.c, ctx->EKi.c, key);      // E_K(Y_i)
            inc_counter(ctx->Yi.c + bl / 2, bl / 2);    // Y_i = incr_r(Y_{i-1})
        }
        ctx->ACi.c[n] = c = in[i];
        out[i] = c ^ ctx->EKi.c[n];             // P_i = C_i (xor) E_K(Y_i)
        mres = n = (n + 1) % bl;
        if (n == 0) {
            (*block) (ctx->Zi.c, ctx->Hi.c, key);                   // H_i = E_K(Z_i)
            mul_gf(ctx->mul.u, ctx->Hi.u, ctx->ACi.u);              // H_i (x) C_i
            grasshopper_plus128((grasshopper_w128_t*)ctx->sum.u,    // acc XOR
                (grasshopper_w128_t*)ctx->sum.u, (grasshopper_w128_t*)ctx->mul.u);
            inc_counter(ctx->Zi.c, bl / 2);                         // Z_{i+1} = incr_l(Z_i)
        }
    }

    ctx->mres = mres;
    return 0;
}