/*
 * Maxim Tishkov 2016
 * Pascal Heller 2024
 * This file is distributed under the same license as OpenSSL
 */

#ifndef GOST_GRASSHOPPER_CIPHER_H
#define GOST_GRASSHOPPER_CIPHER_H

#define SN_kuznyechik_mgm       "kuznyechik-mgm"
#define SN_kuznyechik_mgm_b     "kuznyechik-mgm-b"
#define SN_kuznyechik_mgm_c     "kuznyechik-mgm-c"
#define SN_kuznyechik_mgm_cl    "kuznyechik-mgm-cl"
#define SN_kuznyechik_mgm_cln   "kuznyechik-mgm-cln"
#define SN_kuznyechik_mgm_clo   "kuznyechik-mgm-clo"
#define SN_kuznyechik_mgm_clno  "kuznyechik-mgm-clno"
#define SN_kuznyechik_mgm_a     "kuznyechik-mgm-a"
#define SN_kuznyechik_mgm_ab    "kuznyechik-mgm-ab"
#define SN_kuznyechik_mgm_ad    "kuznyechik-mgm-ad"
#define SN_kuznyechik_mgm_ac    "kuznyechik-mgm-ac"
#define SN_kuznyechik_mgm_acl   "kuznyechik-mgm-acl"
#define SN_kuznyechik_mgm_acln  "kuznyechik-mgm-acln"
#define SN_kuznyechik_mgm_aclo  "kuznyechik-mgm-aclo"
#define SN_kuznyechik_mgm_aclno "kuznyechik-mgm-aclno"

#if defined(__cplusplus)
extern "C" {
#endif

#include "gost_grasshopper_defines.h"

#include "gost_lcl.h"
#include <openssl/evp.h>

// not thread safe
// because of buffers
typedef struct {
    uint8_t type;
    grasshopper_key_t master_key;
    grasshopper_key_t key;
    grasshopper_round_keys_t encrypt_round_keys;
    grasshopper_round_keys_t decrypt_round_keys;
    grasshopper_w128_t buffer;
} gost_grasshopper_cipher_ctx;

typedef struct {
    gost_grasshopper_cipher_ctx c;
    grasshopper_w128_t partial_buffer;
    unsigned int section_size;  /* After how much bytes mesh the key,
				   if 0 never mesh and work like plain ctr. */
    unsigned char kdf_seed[8];
		unsigned char tag[16];
		EVP_MD_CTX *omac_ctx;
} gost_grasshopper_cipher_ctx_ctr;

static void gost_grasshopper_cipher_key(gost_grasshopper_cipher_ctx* c, const uint8_t* k);

static void gost_grasshopper_cipher_destroy(gost_grasshopper_cipher_ctx* c);

static int gost_grasshopper_cipher_init_ecb(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_cbc(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ofb(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_cfb(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ctr(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ctracpkm(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ctracpkm_omac(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_mgm(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_mgm_clmul(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_mgm_cllr(EVP_CIPHER_CTX *ctx,
    const unsigned char *key, const unsigned char *iv, int enc);

static int gost_grasshopper_cipher_init_mgm_cllr_n(EVP_CIPHER_CTX *ctx,
    const unsigned char *key, const unsigned char *iv, int enc);

static int gost_grasshopper_cipher_init_mgm_cllr_o(EVP_CIPHER_CTX *ctx,
    const unsigned char *key, const unsigned char *iv, int enc);

static int gost_grasshopper_cipher_init_mgm_cllr_no(EVP_CIPHER_CTX *ctx,
    const unsigned char *key, const unsigned char *iv, int enc);

static int aes_cipher_init_mgm(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int aes_dep_cipher_init_mgm(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int aes_cipher_init_mgm_clmul(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int aes_cipher_init_mgm_cllr(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int aes_cipher_init_mgm_cllr_n(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int aes_cipher_init_mgm_cllr_o(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int aes_cipher_init_mgm_cllr_no(EVP_CIPHER_CTX* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init(EVP_CIPHER_CTX* ctx, const unsigned char* key,
    const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_do(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ecb(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_cbc(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ofb(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_cfb(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ctr(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ctracpkm(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ctracpkm_omac(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_mgm(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_mgm_blockwise(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_mgm_clmul(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_mgm_cllr(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_mgm_cllr_n(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_mgm_cllr_o(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_mgm_cllr_no(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int aes_cipher_do_mgm(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int aes_cipher_do_mgm_blockwise(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int aes_dep_cipher_do_mgm(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int aes_cipher_do_mgm_clmul(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int aes_cipher_do_mgm_cllr(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int aes_cipher_do_mgm_cllr_n(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int aes_cipher_do_mgm_cllr_o(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int aes_cipher_do_mgm_cllr_no(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_cleanup(EVP_CIPHER_CTX* ctx);

static int gost_grasshopper_mgm_cleanup(EVP_CIPHER_CTX *c);

static int gost_grasshopper_mgm_cleanup_clmul(EVP_CIPHER_CTX *c);

static int gost_grasshopper_mgm_cleanup_cllr(EVP_CIPHER_CTX *c);

static int gost_grasshopper_mgm_cleanup_cllr_n(EVP_CIPHER_CTX *c);

static int gost_grasshopper_mgm_cleanup_cllr_o(EVP_CIPHER_CTX *c);

static int gost_grasshopper_mgm_cleanup_cllr_no(EVP_CIPHER_CTX *c);

static int aes_mgm_cleanup(EVP_CIPHER_CTX *c);

static int aes_dep_mgm_cleanup(EVP_CIPHER_CTX *c);

static int aes_mgm_cleanup_clmul(EVP_CIPHER_CTX *c);

static int aes_mgm_cleanup_cllr(EVP_CIPHER_CTX *c);

static int aes_mgm_cleanup_cllr_n(EVP_CIPHER_CTX *c);

static int aes_mgm_cleanup_cllr_o(EVP_CIPHER_CTX *c);

static int aes_mgm_cleanup_cllr_no(EVP_CIPHER_CTX *c);

static int gost_grasshopper_set_asn1_parameters(EVP_CIPHER_CTX* ctx, ASN1_TYPE* params);

static int gost_grasshopper_get_asn1_parameters(EVP_CIPHER_CTX* ctx, ASN1_TYPE* params);

static int gost_grasshopper_cipher_ctl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr);

static int gost_grasshopper_mgm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int gost_grasshopper_mgm_ctrl_clmul(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int gost_grasshopper_mgm_ctrl_cllr(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int gost_grasshopper_mgm_ctrl_cllr_n(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int gost_grasshopper_mgm_ctrl_cllr_o(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int gost_grasshopper_mgm_ctrl_cllr_no(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int aes_mgm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int aes_dep_mgm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int aes_mgm_ctrl_clmul(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int aes_mgm_ctrl_cllr(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int aes_mgm_ctrl_cllr_n(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int aes_mgm_ctrl_cllr_o(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int aes_mgm_ctrl_cllr_no(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

const EVP_CIPHER* cipher_gost_grasshopper_ctracpkm();

#if defined(__cplusplus)
}
#endif

#endif
