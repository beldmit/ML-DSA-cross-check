#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#define SEED_LEN 32

#define EXIT_OK    0
#define EXIT_FAIL  1
#define EXIT_USAGE 2

enum {
    API_MESSAGE,
    API_ONESHOT,
    API_DIGEST,
    API_COUNT
};

static const char *api_names[API_COUNT] = {
    "sign_message",
    "sign_oneshot",
    "DigestSign"
};

typedef struct {
    const unsigned char *data;
    size_t len;
} msg_t;

typedef int (*sign_fn)(EVP_PKEY *pkey, const char *alg,
                       const unsigned char *msg, size_t msg_len,
                       unsigned char *sig, size_t sig_sz);

typedef int (*ctx_sign_fn)(EVP_PKEY_CTX *ctx, EVP_SIGNATURE *sa,
                           const unsigned char *msg, size_t msg_len,
                           unsigned char *sig, size_t sig_sz);

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static size_t sig_size_for_alg(const char *alg)
{
    if (strcmp(alg, "ML-DSA-44") == 0) return 2420;
    if (strcmp(alg, "ML-DSA-65") == 0) return 3309;
    if (strcmp(alg, "ML-DSA-87") == 0) return 4627;
    return 0;
}

static unsigned char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);

    unsigned char *buf = malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static int parse_messages(const unsigned char *data, size_t data_len,
                          msg_t **out, size_t *out_count)
{
    size_t count = 0, off = 0;

    while (off + 4 <= data_len) {
        uint32_t mlen = ((uint32_t)data[off]     << 24) |
                        ((uint32_t)data[off + 1] << 16) |
                        ((uint32_t)data[off + 2] << 8)  |
                         (uint32_t)data[off + 3];
        off += 4;
        if (off + mlen > data_len) {
            fprintf(stderr, "Truncated message at index %zu\n", count);
            return -1;
        }
        off += mlen;
        count++;
    }
    if (off != data_len) {
        fprintf(stderr, "Trailing data in messages file (%zu bytes)\n",
                data_len - off);
        return -1;
    }

    msg_t *msgs = calloc(count, sizeof(msg_t));
    if (!msgs)
        return -1;

    off = 0;
    for (size_t i = 0; i < count; i++) {
        uint32_t mlen = ((uint32_t)data[off]     << 24) |
                        ((uint32_t)data[off + 1] << 16) |
                        ((uint32_t)data[off + 2] << 8)  |
                         (uint32_t)data[off + 3];
        off += 4;
        msgs[i].data = data + off;
        msgs[i].len  = mlen;
        off += mlen;
    }

    *out       = msgs;
    *out_count = count;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Key generation from seed                                          */
/* ------------------------------------------------------------------ */

static EVP_PKEY *keygen_from_seed(const char *alg, const unsigned char *seed)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!ctx)
        return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto end;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                          (void *)seed, SEED_LEN),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0)
        goto end;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        pkey = NULL;

end:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* ------------------------------------------------------------------ */
/*  Signing — API 1: streaming (sign_message_init / update / final)   */
/* ------------------------------------------------------------------ */

static int sign_message_api(EVP_PKEY *pkey, const char *alg,
                            const unsigned char *msg, size_t msg_len,
                            unsigned char *sig, size_t sig_sz)
{
    int ret = 0;
    int deterministic = 1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    EVP_SIGNATURE *sa = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    if (!ctx || !sa)
        goto end;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC,
                                 &deterministic),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_sign_message_init(ctx, sa, params) <= 0)
        goto end;

    size_t slen = sig_sz;
    if (EVP_PKEY_sign(ctx, sig, &slen, msg, msg_len) <= 0)
        goto end;

    ret = 1;
end:
    EVP_SIGNATURE_free(sa);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Signing — API 2: one-shot (sign_message_init + EVP_PKEY_sign)     */
/* ------------------------------------------------------------------ */

static int sign_oneshot_api(EVP_PKEY *pkey, const char *alg,
                            const unsigned char *msg, size_t msg_len,
                            unsigned char *sig, size_t sig_sz)
{
    int ret = 0;
    int deterministic = 1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    EVP_SIGNATURE *sa = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    if (!ctx || !sa)
        goto end;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC,
                                 &deterministic),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_sign_message_init(ctx, sa, params) <= 0)
        goto end;

    size_t slen = sig_sz;
    if (EVP_PKEY_sign(ctx, sig, &slen, msg, msg_len) <= 0)
        goto end;

    ret = 1;
end:
    EVP_SIGNATURE_free(sa);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Signing — API 3: digest (EVP_DigestSign)                          */
/* ------------------------------------------------------------------ */

static int sign_digest_api(EVP_PKEY *pkey, const char *alg,
                           const unsigned char *msg, size_t msg_len,
                           unsigned char *sig, size_t sig_sz)
{
    (void)alg;
    int ret = 0;
    int deterministic = 1;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return 0;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC,
                                 &deterministic),
        OSSL_PARAM_construct_end()
    };

    if (EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, params) <= 0)
        goto end;

    size_t slen = sig_sz;
    if (EVP_DigestSign(mdctx, sig, &slen, msg, msg_len) <= 0)
        goto end;

    ret = 1;
end:
    EVP_MD_CTX_free(mdctx);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Signing with reused EVP_PKEY_CTX (re-init on each call)           */
/* ------------------------------------------------------------------ */

static int sign_message_with_ctx(EVP_PKEY_CTX *ctx, EVP_SIGNATURE *sa,
                                 const unsigned char *msg, size_t msg_len,
                                 unsigned char *sig, size_t sig_sz)
{
    int deterministic = 1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC,
                                 &deterministic),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_sign_message_init(ctx, sa, params) <= 0)
        return 0;

    size_t slen = sig_sz;
    if (EVP_PKEY_sign(ctx, sig, &slen, msg, msg_len) <= 0)
        return 0;

    return 1;
}

static int sign_oneshot_with_ctx(EVP_PKEY_CTX *ctx, EVP_SIGNATURE *sa,
                                 const unsigned char *msg, size_t msg_len,
                                 unsigned char *sig, size_t sig_sz)
{
    int deterministic = 1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC,
                                 &deterministic),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_sign_message_init(ctx, sa, params) <= 0)
        return 0;

    size_t slen = sig_sz;
    if (EVP_PKEY_sign(ctx, sig, &slen, msg, msg_len) <= 0)
        return 0;

    return 1;
}

static const ctx_sign_fn ctx_fns[2] = {
    sign_message_with_ctx, sign_oneshot_with_ctx
};

/* ------------------------------------------------------------------ */
/*  Test 1 — reproducibility + reference + cross-API consistency      */
/* ------------------------------------------------------------------ */

static int run_test1(const char *alg, EVP_PKEY **keys, size_t nkeys,
                     const msg_t *msgs, size_t nmsgs,
                     const unsigned char *ref_sigs, size_t sig_sz)
{
    static const sign_fn fns[API_COUNT] = {
        sign_message_api, sign_oneshot_api, sign_digest_api
    };
    int total = 0, fails = 0;
    unsigned char *sig_a = malloc(sig_sz);
    unsigned char *sig_b = malloc(sig_sz);
    unsigned char *cross[API_COUNT];

    for (int a = 0; a < API_COUNT; a++)
        cross[a] = malloc(sig_sz);

    (void)nmsgs;
    for (size_t i = 0; i < nkeys; i++) {
        const unsigned char *ref = ref_sigs + i * sig_sz;
        int got_cross[API_COUNT] = {0};

        for (int api = 0; api < API_COUNT; api++) {
            total += 2;

            if (!fns[api](keys[i], alg,
                          msgs[i].data, msgs[i].len, sig_a, sig_sz)) {
                fprintf(stderr, "FAIL: Test1 %s sign error (index %zu)\n",
                        api_names[api], i);
                ERR_print_errors_fp(stderr);
                fails += 2;
                continue;
            }

            if (memcmp(sig_a, ref, sig_sz) != 0) {
                fprintf(stderr, "FAIL: Test1 %s reference mismatch"
                        " (index %zu)\n", api_names[api], i);
                fails++;
            }

            if (!fns[api](keys[i], alg,
                          msgs[i].data, msgs[i].len, sig_b, sig_sz)) {
                fprintf(stderr, "FAIL: Test1 %s second sign error"
                        " (index %zu)\n", api_names[api], i);
                ERR_print_errors_fp(stderr);
                fails++;
                continue;
            }
            if (memcmp(sig_a, sig_b, sig_sz) != 0) {
                fprintf(stderr, "FAIL: Test1 %s not reproducible"
                        " (index %zu)\n", api_names[api], i);
                fails++;
            }

            memcpy(cross[api], sig_a, sig_sz);
            got_cross[api] = 1;
        }

        for (int api = 1; api < API_COUNT; api++) {
            if (!got_cross[0] || !got_cross[api])
                continue;
            total++;
            if (memcmp(cross[0], cross[api], sig_sz) != 0) {
                fprintf(stderr, "FAIL: Test1 cross-API %s vs %s"
                        " (index %zu)\n",
                        api_names[0], api_names[api], i);
                fails++;
            }
        }
    }

    printf("Test 1 (reproducibility + reference): %d/%d passed",
           total - fails, total);
    if (fails)
        printf(", %d FAILED", fails);
    printf("\n");

    for (int a = 0; a < API_COUNT; a++)
        free(cross[a]);
    free(sig_a);
    free(sig_b);
    return fails;
}

/* ------------------------------------------------------------------ */
/*  Test 1b — same as Test 1, but reusing EVP_PKEY_CTX (APIs 1 & 2)   */
/* ------------------------------------------------------------------ */

static int run_test1_reused_ctx(const char *alg, EVP_PKEY **keys, size_t nkeys,
                                const msg_t *msgs, size_t nmsgs,
                                const unsigned char *ref_sigs, size_t sig_sz)
{
    int total = 0, fails = 0;
    unsigned char *sig_a = malloc(sig_sz);
    unsigned char *sig_b = malloc(sig_sz);

    (void)nmsgs;
    for (int api = 0; api < 2; api++) {
        for (size_t i = 0; i < nkeys; i++) {
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL,
                                                           keys[i], NULL);
            EVP_SIGNATURE *sa = EVP_SIGNATURE_fetch(NULL, alg, NULL);
            if (!ctx || !sa) {
                fprintf(stderr, "FAIL: Test1b %s ctx/fetch error"
                        " (index %zu)\n", api_names[api], i);
                ERR_print_errors_fp(stderr);
                EVP_SIGNATURE_free(sa);
                EVP_PKEY_CTX_free(ctx);
                fails += 2;
                total += 2;
                continue;
            }

            const unsigned char *ref = ref_sigs + i * sig_sz;
            total += 2;

            if (!ctx_fns[api](ctx, sa, msgs[i].data, msgs[i].len,
                              sig_a, sig_sz)) {
                fprintf(stderr, "FAIL: Test1b %s sign error"
                        " (index %zu)\n", api_names[api], i);
                ERR_print_errors_fp(stderr);
                fails += 2;
                EVP_SIGNATURE_free(sa);
                EVP_PKEY_CTX_free(ctx);
                continue;
            }

            if (memcmp(sig_a, ref, sig_sz) != 0) {
                fprintf(stderr, "FAIL: Test1b %s reference mismatch"
                        " (index %zu)\n", api_names[api], i);
                fails++;
            }

            if (!ctx_fns[api](ctx, sa, msgs[i].data, msgs[i].len,
                              sig_b, sig_sz)) {
                fprintf(stderr, "FAIL: Test1b %s second sign error"
                        " (index %zu)\n", api_names[api], i);
                ERR_print_errors_fp(stderr);
                fails++;
                EVP_SIGNATURE_free(sa);
                EVP_PKEY_CTX_free(ctx);
                continue;
            }
            if (memcmp(sig_a, sig_b, sig_sz) != 0) {
                fprintf(stderr, "FAIL: Test1b %s not reproducible"
                        " (index %zu)\n", api_names[api], i);
                fails++;
            }

            EVP_SIGNATURE_free(sa);
            EVP_PKEY_CTX_free(ctx);
        }
    }

    printf("Test 1b (reproducibility, reused EVP_PKEY_CTX): %d/%d passed",
           total - fails, total);
    if (fails)
        printf(", %d FAILED", fails);
    printf("\n");

    free(sig_a);
    free(sig_b);
    return fails;
}

/* ------------------------------------------------------------------ */
/*  Test 2 — key replacement (regenerate keys from seeds each time)   */
/* ------------------------------------------------------------------ */

static int run_test2(const char *alg, const unsigned char *seeds, size_t nkeys,
                     const unsigned char *msg, size_t msg_len, size_t sig_sz)
{
    if (nkeys < 2) {
        printf("Test 2 (key replacement): SKIPPED (need >= 2 seeds)\n");
        return 0;
    }

    static const sign_fn fns[API_COUNT] = {
        sign_message_api, sign_oneshot_api, sign_digest_api
    };
    int total = 0, fails = 0;
    unsigned char *sig_old1 = malloc(sig_sz);
    unsigned char *sig_new  = malloc(sig_sz);
    unsigned char *sig_old2 = malloc(sig_sz);

    for (size_t i = 0; i + 1 < nkeys; i++) {
        for (int api = 0; api < API_COUNT; api++) {
            total++;

            EVP_PKEY *key_old = keygen_from_seed(alg,
                                                 seeds + i * SEED_LEN);
            if (!key_old) {
                fprintf(stderr, "FAIL: Test2 %s keygen old (pair %zu)\n",
                        api_names[api], i);
                ERR_print_errors_fp(stderr);
                fails++;
                continue;
            }

            int ok = fns[api](key_old, alg, msg, msg_len, sig_old1, sig_sz);
            EVP_PKEY_free(key_old);
            if (!ok) {
                fprintf(stderr, "FAIL: Test2 %s sign old_1 (pair %zu)\n",
                        api_names[api], i);
                ERR_print_errors_fp(stderr);
                fails++;
                continue;
            }

            EVP_PKEY *key_new = keygen_from_seed(alg,
                                                 seeds + (i + 1) * SEED_LEN);
            if (!key_new) {
                fprintf(stderr, "FAIL: Test2 %s keygen new (pair %zu)\n",
                        api_names[api], i);
                fails++;
                continue;
            }
            fns[api](key_new, alg, msg, msg_len, sig_new, sig_sz);
            EVP_PKEY_free(key_new);

            key_old = keygen_from_seed(alg, seeds + i * SEED_LEN);
            if (!key_old) {
                fprintf(stderr, "FAIL: Test2 %s keygen old2 (pair %zu)\n",
                        api_names[api], i);
                fails++;
                continue;
            }
            ok = fns[api](key_old, alg, msg, msg_len, sig_old2, sig_sz);
            EVP_PKEY_free(key_old);
            if (!ok) {
                fprintf(stderr, "FAIL: Test2 %s sign old_2 (pair %zu)\n",
                        api_names[api], i);
                ERR_print_errors_fp(stderr);
                fails++;
                continue;
            }

            if (memcmp(sig_old1, sig_old2, sig_sz) != 0) {
                fprintf(stderr, "FAIL: Test2 %s old-key mismatch (pair %zu)\n",
                        api_names[api], i);
                fails++;
            }
        }
    }

    printf("Test 2 (key replacement): %d/%d passed",
           total - fails, total);
    if (fails)
        printf(", %d FAILED", fails);
    printf("\n");

    free(sig_old1);
    free(sig_new);
    free(sig_old2);
    return fails;
}

/* ------------------------------------------------------------------ */
/*  Test 3 — context reuse                                            */
/*  APIs 1 & 2: new EVP_PKEY_CTX per key, reuse EVP_PKEY objects      */
/*  API  3:     reuse EVP_MD_CTX across keys via re-init              */
/* ------------------------------------------------------------------ */

static int test3_pkey_ctx(int api_idx,
                          EVP_PKEY *key_old, EVP_PKEY *key_new,
                          const char *alg,
                          const unsigned char *msg, size_t msg_len,
                          size_t sig_sz)
{
    static const sign_fn fns[2] = { sign_message_api, sign_oneshot_api };
    unsigned char *sig1 = malloc(sig_sz);
    unsigned char *sig2 = malloc(sig_sz);
    unsigned char *sig3 = malloc(sig_sz);
    int ret = 0;

    if (!fns[api_idx](key_old, alg, msg, msg_len, sig1, sig_sz))
        goto end;
    if (!fns[api_idx](key_new, alg, msg, msg_len, sig2, sig_sz))
        goto end;
    if (!fns[api_idx](key_old, alg, msg, msg_len, sig3, sig_sz))
        goto end;

    ret = (memcmp(sig1, sig3, sig_sz) == 0);
end:
    free(sig1);
    free(sig2);
    free(sig3);
    return ret;
}

static int test3_pkey_ctx_reuse(int api_idx,
                                EVP_PKEY *key_old, EVP_PKEY *key_new,
                                const char *alg,
                                const unsigned char *msg, size_t msg_len,
                                size_t sig_sz)
{
    int ret = 0;
    unsigned char *sig1 = malloc(sig_sz);
    unsigned char *sig2 = malloc(sig_sz);
    unsigned char *sig3 = malloc(sig_sz);
    unsigned char *sig4 = malloc(sig_sz);

    EVP_PKEY_CTX *ctx_old = EVP_PKEY_CTX_new_from_pkey(NULL, key_old, NULL);
    EVP_PKEY_CTX *ctx_new = EVP_PKEY_CTX_new_from_pkey(NULL, key_new, NULL);
    EVP_SIGNATURE *sa = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    if (!ctx_old || !ctx_new || !sa)
        goto end;

    if (!ctx_fns[api_idx](ctx_old, sa, msg, msg_len, sig1, sig_sz))
        goto end;
    if (!ctx_fns[api_idx](ctx_old, sa, msg, msg_len, sig2, sig_sz))
        goto end;
    if (!ctx_fns[api_idx](ctx_new, sa, msg, msg_len, sig3, sig_sz))
        goto end;
    if (!ctx_fns[api_idx](ctx_old, sa, msg, msg_len, sig4, sig_sz))
        goto end;

    ret = (memcmp(sig1, sig2, sig_sz) == 0) &&
          (memcmp(sig1, sig4, sig_sz) == 0);
end:
    EVP_SIGNATURE_free(sa);
    EVP_PKEY_CTX_free(ctx_old);
    EVP_PKEY_CTX_free(ctx_new);
    free(sig1);
    free(sig2);
    free(sig3);
    free(sig4);
    return ret;
}

static int test3_digest_reuse(EVP_PKEY *key_old, EVP_PKEY *key_new,
                              const unsigned char *msg, size_t msg_len,
                              size_t sig_sz)
{
    int ret = 0;
    int deterministic = 1;
    unsigned char *sig1 = malloc(sig_sz);
    unsigned char *sig2 = malloc(sig_sz);
    unsigned char *sig3 = malloc(sig_sz);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        goto end;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC,
                                 &deterministic),
        OSSL_PARAM_construct_end()
    };
    size_t slen;

    slen = sig_sz;
    if (EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, NULL,
                              key_old, params) <= 0)
        goto end;
    if (EVP_DigestSign(mdctx, sig1, &slen, msg, msg_len) <= 0)
        goto end;

    slen = sig_sz;
    if (EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, NULL,
                              key_new, params) <= 0)
        goto end;
    if (EVP_DigestSign(mdctx, sig2, &slen, msg, msg_len) <= 0)
        goto end;

    slen = sig_sz;
    if (EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, NULL,
                              key_old, params) <= 0)
        goto end;
    if (EVP_DigestSign(mdctx, sig3, &slen, msg, msg_len) <= 0)
        goto end;

    ret = (memcmp(sig1, sig3, sig_sz) == 0);
end:
    EVP_MD_CTX_free(mdctx);
    free(sig1);
    free(sig2);
    free(sig3);
    return ret;
}

static int run_test3(const char *alg, EVP_PKEY **keys, size_t nkeys,
                     const unsigned char *msg, size_t msg_len, size_t sig_sz)
{
    if (nkeys < 2) {
        printf("Test 3 (context reuse): SKIPPED (need >= 2 seeds)\n");
        return 0;
    }

    int total = 0, fails = 0;

    for (size_t i = 0; i + 1 < nkeys; i++) {
        for (int api = 0; api < 2; api++) {
            total++;
            if (!test3_pkey_ctx(api, keys[i], keys[i + 1],
                                alg, msg, msg_len, sig_sz)) {
                fprintf(stderr, "FAIL: Test3 %s fresh-ctx key-cycle"
                        " mismatch (pair %zu)\n", api_names[api], i);
                fails++;
            }

            total++;
            if (!test3_pkey_ctx_reuse(api, keys[i], keys[i + 1],
                                      alg, msg, msg_len, sig_sz)) {
                fprintf(stderr, "FAIL: Test3 %s reused-ctx key-cycle"
                        " mismatch (pair %zu)\n", api_names[api], i);
                ERR_print_errors_fp(stderr);
                fails++;
            }
        }

        total++;
        if (!test3_digest_reuse(keys[i], keys[i + 1],
                                msg, msg_len, sig_sz)) {
            fprintf(stderr, "FAIL: Test3 %s context reuse mismatch"
                    " (pair %zu)\n", api_names[API_DIGEST], i);
            ERR_print_errors_fp(stderr);
            fails++;
        }
    }

    printf("Test 3 (context reuse): %d/%d passed",
           total - fails, total);
    if (fails)
        printf(", %d FAILED", fails);
    printf("\n");

    return fails;
}

/* ------------------------------------------------------------------ */
/*  Test 4 — EVP_PKEY immutability (key material not replaceable)     */
/* ------------------------------------------------------------------ */

static int run_test4(const char *alg, EVP_PKEY **keys, size_t nkeys)
{
    if (nkeys < 2) {
        printf("Test 4 (EVP_PKEY immutability): SKIPPED (need >= 2 seeds)\n");
        return 0;
    }

    int total = 0, fails = 0;
    unsigned char pub[2592], priv[4896]; /* max across ML-DSA-44/65/87 */
    size_t pub_len = 0, priv_len = 0;

    if (EVP_PKEY_get_octet_string_param(keys[1], OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, sizeof(pub), &pub_len) <= 0
        || EVP_PKEY_get_octet_string_param(keys[1], OSSL_PKEY_PARAM_PRIV_KEY,
                                           priv, sizeof(priv), &priv_len) <= 0) {
        fprintf(stderr, "FAIL: Test4 cannot extract key material from key 1\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    ERR_clear_error();

    total++;
    OSSL_PARAM pub_params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                          pub, pub_len),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_set_params(keys[0], pub_params) > 0) {
        fprintf(stderr, "FAIL: Test4 public key replacement should have"
                " been rejected\n");
        fails++;
    } else {
        ERR_clear_error();
    }

    total++;
    OSSL_PARAM priv_params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                          priv, priv_len),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_set_params(keys[0], priv_params) > 0) {
        fprintf(stderr, "FAIL: Test4 private key replacement should have"
                " been rejected\n");
        fails++;
    } else {
        ERR_clear_error();
    }

    total++;
    OSSL_PARAM both_params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                          pub, pub_len),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                          priv, priv_len),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_set_params(keys[0], both_params) > 0) {
        fprintf(stderr, "FAIL: Test4 keypair replacement should have"
                " been rejected\n");
        fails++;
    } else {
        ERR_clear_error();
    }

    printf("Test 4 (EVP_PKEY immutability): %d/%d passed",
           total - fails, total);
    if (fails)
        printf(", %d FAILED", fails);
    printf("\n");

    return fails;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --algorithm <name> --seeds <file> "
            "--messages <file> --signatures <file>\n\n"
            "  --algorithm   ML-DSA-44, ML-DSA-65, or ML-DSA-87\n"
            "  --seeds       File with 32-byte key generation seeds\n"
            "  --messages    File with length-prefixed messages\n"
            "  --signatures  File with reference signatures\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *alg = NULL;
    const char *seed_path = NULL;
    const char *msg_path  = NULL;
    const char *sig_path  = NULL;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--help") == 0) ||
            (strcmp(argv[i], "-h") == 0)) {
            usage(argv[0]);
            return EXIT_OK;
        }
        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for %s\n", argv[i]);
            usage(argv[0]);
            return EXIT_USAGE;
        }
        if (strcmp(argv[i], "--algorithm") == 0)
            alg = argv[++i];
        else if (strcmp(argv[i], "--seeds") == 0)
            seed_path = argv[++i];
        else if (strcmp(argv[i], "--messages") == 0)
            msg_path = argv[++i];
        else if (strcmp(argv[i], "--signatures") == 0)
            sig_path = argv[++i];
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return EXIT_USAGE;
        }
    }

    if (!alg || !seed_path || !msg_path || !sig_path) {
        usage(argv[0]);
        return EXIT_USAGE;
    }

    size_t sig_sz = sig_size_for_alg(alg);
    if (sig_sz == 0) {
        fprintf(stderr, "Unsupported algorithm: %s\n", alg);
        return EXIT_USAGE;
    }

    EVP_SIGNATURE *probe = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    if (!probe) {
        fprintf(stderr, "Algorithm %s not available in this OpenSSL build\n",
                alg);
        ERR_print_errors_fp(stderr);
        return EXIT_USAGE;
    }
    EVP_SIGNATURE_free(probe);

    /* ---- read input files ---- */

    size_t seed_len = 0, msg_data_len = 0, sig_data_len = 0;
    unsigned char *seed_data = read_file(seed_path, &seed_len);
    unsigned char *msg_data  = read_file(msg_path,  &msg_data_len);
    unsigned char *sig_data  = read_file(sig_path,  &sig_data_len);

    if (!seed_data || !msg_data || !sig_data)
        return EXIT_USAGE;

    if (seed_len == 0 || seed_len % SEED_LEN != 0) {
        fprintf(stderr, "Seeds file size (%zu) must be a positive "
                "multiple of %d\n", seed_len, SEED_LEN);
        return EXIT_USAGE;
    }
    size_t nkeys = seed_len / SEED_LEN;

    msg_t  *msgs  = NULL;
    size_t  nmsgs = 0;
    if (parse_messages(msg_data, msg_data_len, &msgs, &nmsgs) < 0)
        return EXIT_USAGE;
    if (nmsgs == 0) {
        fprintf(stderr, "No messages in %s\n", msg_path);
        return EXIT_USAGE;
    }

    if (nkeys != nmsgs) {
        fprintf(stderr, "Seeds count (%zu) must equal messages count (%zu)\n",
                nkeys, nmsgs);
        return EXIT_USAGE;
    }

    size_t expected_sig_bytes = nkeys * sig_sz;
    if (sig_data_len != expected_sig_bytes) {
        fprintf(stderr, "Signatures file: expected %zu bytes "
                "(%zu entries * %zu), got %zu\n",
                expected_sig_bytes, nkeys, sig_sz, sig_data_len);
        return EXIT_USAGE;
    }

    printf("ML-DSA cross-check: %s\n", alg);
    printf("  Entries: %zu, Signature size: %zu\n\n", nkeys, sig_sz);

    /* ---- generate keys ---- */

    EVP_PKEY **keys = calloc(nkeys, sizeof(EVP_PKEY *));
    for (size_t i = 0; i < nkeys; i++) {
        keys[i] = keygen_from_seed(alg, seed_data + i * SEED_LEN);
        if (!keys[i]) {
            fprintf(stderr, "Key generation failed for seed %zu\n", i);
            ERR_print_errors_fp(stderr);
            return EXIT_FAIL;
        }
    }

    /* ---- run tests ---- */

    int total_fails = 0;

    total_fails += run_test1(alg, keys, nkeys, msgs, nmsgs,
                             sig_data, sig_sz);

    total_fails += run_test1_reused_ctx(alg, keys, nkeys, msgs, nmsgs,
                                        sig_data, sig_sz);

    total_fails += run_test2(alg, seed_data, nkeys,
                             msgs[0].data, msgs[0].len, sig_sz);

    total_fails += run_test3(alg, keys, nkeys,
                             msgs[0].data, msgs[0].len, sig_sz);

    total_fails += run_test4(alg, keys, nkeys);

    /* ---- cleanup ---- */

    for (size_t i = 0; i < nkeys; i++)
        EVP_PKEY_free(keys[i]);
    free(keys);
    free(msgs);
    free(seed_data);
    free(msg_data);
    free(sig_data);

    printf("\n%s\n", total_fails ? "FAILED" : "ALL PASSED");
    return total_fails ? EXIT_FAIL : EXIT_OK;
}
