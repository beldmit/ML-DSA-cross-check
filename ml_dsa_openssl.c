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
    MODE_PKEY_SIGN,
    MODE_DIGESTSIGN
};

typedef struct {
    const unsigned char *data;
    size_t len;
} msg_t;

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
/*  Key generation                                                    */
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

static int key_via_fromdata(const char *alg, const unsigned char *seed,
                            EVP_PKEY **ppkey)
{
    int ret = 0;
    EVP_PKEY *tmp = keygen_from_seed(alg, seed);
    if (!tmp)
        return 0;

    size_t pub_len = 0, priv_len = 0;
    if (EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PUB_KEY,
                                         NULL, 0, &pub_len) <= 0 ||
        EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PRIV_KEY,
                                         NULL, 0, &priv_len) <= 0) {
        EVP_PKEY_free(tmp);
        return 0;
    }

    unsigned char *pub = malloc(pub_len);
    unsigned char *priv = malloc(priv_len);
    if (!pub || !priv) {
        free(pub);
        free(priv);
        EVP_PKEY_free(tmp);
        return 0;
    }

    EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PUB_KEY,
                                     pub, pub_len, &pub_len);
    EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PRIV_KEY,
                                     priv, priv_len, &priv_len);
    EVP_PKEY_free(tmp);

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!dctx) {
        free(pub);
        free(priv);
        return 0;
    }

    OSSL_PARAM dparams[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                          pub, pub_len),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                          priv, priv_len),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_fromdata_init(dctx) > 0 &&
        EVP_PKEY_fromdata(dctx, ppkey, EVP_PKEY_KEYPAIR, dparams) > 0)
        ret = 1;

    EVP_PKEY_CTX_free(dctx);
    free(pub);
    free(priv);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --algorithm <name> --seeds <file> --messages <file>\n"
            "       --signatures <outfile> --mode <mode> [--reuse-ctx] [--reuse-key]\n\n"
            "  --algorithm   ML-DSA-44, ML-DSA-65, or ML-DSA-87\n"
            "  --seeds       File with 32-byte key generation seeds\n"
            "  --messages    File with length-prefixed messages\n"
            "  --signatures  Output file for generated signatures\n"
            "  --mode        evp_pkey_sign or evp_digestsign\n"
            "  --reuse-ctx   Reuse signing context across operations\n"
            "  --reuse-key   Reuse EVP_PKEY via EVP_PKEY_fromdata() across seeds\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *alg = NULL;
    const char *seed_path = NULL;
    const char *msg_path  = NULL;
    const char *sig_path  = NULL;
    const char *mode_str  = NULL;
    int reuse_ctx = 0;
    int reuse_key = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return EXIT_OK;
        }
        if (strcmp(argv[i], "--reuse-ctx") == 0) {
            reuse_ctx = 1;
            continue;
        }
        if (strcmp(argv[i], "--reuse-key") == 0) {
            reuse_key = 1;
            continue;
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
        else if (strcmp(argv[i], "--mode") == 0)
            mode_str = argv[++i];
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return EXIT_USAGE;
        }
    }

    if (!alg || !seed_path || !msg_path || !sig_path || !mode_str) {
        usage(argv[0]);
        return EXIT_USAGE;
    }

    int mode;
    if (strcmp(mode_str, "evp_pkey_sign") == 0)
        mode = MODE_PKEY_SIGN;
    else if (strcmp(mode_str, "evp_digestsign") == 0)
        mode = MODE_DIGESTSIGN;
    else {
        fprintf(stderr, "Unknown mode: %s\n", mode_str);
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

    size_t seed_len = 0, msg_data_len = 0;
    unsigned char *seed_data = read_file(seed_path, &seed_len);
    unsigned char *msg_data  = read_file(msg_path,  &msg_data_len);

    if (!seed_data || !msg_data)
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

    /* ---- open output file ---- */

    FILE *outf = fopen(sig_path, "wb");
    if (!outf) {
        fprintf(stderr, "Cannot open %s for writing: %s\n",
                sig_path, strerror(errno));
        return EXIT_USAGE;
    }

    fprintf(stderr, "ML-DSA cross-check: %s, mode=%s%s%s\n", alg, mode_str,
            reuse_ctx ? ", reuse-ctx" : "", reuse_key ? ", reuse-key" : "");
    fprintf(stderr, "  Seeds: %zu, Messages: %zu, Signature size: %zu\n",
            nkeys, nmsgs, sig_sz);

    /* ---- signing loop ---- */

    int ret = EXIT_OK;
    unsigned char *sig_buf = malloc(sig_sz);
    EVP_PKEY *pkey = NULL;
    int deterministic = 1;
    OSSL_PARAM sign_params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC,
                                 &deterministic),
        OSSL_PARAM_construct_end()
    };
    size_t total_sigs = 0;

    EVP_PKEY_CTX *pctx = NULL;
    EVP_SIGNATURE *sa = NULL;
    EVP_MD_CTX *mdctx = NULL;

    if (mode == MODE_PKEY_SIGN)
        sa = EVP_SIGNATURE_fetch(NULL, alg, NULL);

    if (reuse_ctx && mode == MODE_DIGESTSIGN)
        mdctx = EVP_MD_CTX_new();

    for (size_t i = 0; i < nkeys; i++) {
        if (reuse_key) {
            if (!key_via_fromdata(alg, seed_data + i * SEED_LEN, &pkey)) {
                fprintf(stderr, "Key import via fromdata failed"
                        " for seed %zu\n", i);
                ERR_print_errors_fp(stderr);
                ret = EXIT_FAIL;
                goto end;
            }
        } else {
            EVP_PKEY_free(pkey);
            pkey = keygen_from_seed(alg, seed_data + i * SEED_LEN);
            if (!pkey) {
                fprintf(stderr, "Key generation failed for seed %zu\n", i);
                ERR_print_errors_fp(stderr);
                ret = EXIT_FAIL;
                goto end;
            }
        }

        if (reuse_ctx && mode == MODE_PKEY_SIGN) {
            EVP_PKEY_CTX_free(pctx);
            pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            if (!pctx) {
                fprintf(stderr, "EVP_PKEY_CTX_new failed for seed %zu\n", i);
                ERR_print_errors_fp(stderr);
                ret = EXIT_FAIL;
                goto end;
            }
        }

        for (size_t j = 0; j < nmsgs; j++) {
            size_t slen = sig_sz;

            if (mode == MODE_PKEY_SIGN) {
                if (!reuse_ctx) {
                    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
                    if (!pctx) {
                        fprintf(stderr, "EVP_PKEY_CTX_new failed"
                                " (seed %zu, msg %zu)\n", i, j);
                        ERR_print_errors_fp(stderr);
                        ret = EXIT_FAIL;
                        goto end;
                    }
                }

                if (EVP_PKEY_sign_message_init(pctx, sa, sign_params) <= 0 ||
                    EVP_PKEY_sign(pctx, sig_buf, &slen,
                                  msgs[j].data, msgs[j].len) <= 0) {
                    fprintf(stderr, "Signing failed (seed %zu, msg %zu)\n",
                            i, j);
                    ERR_print_errors_fp(stderr);
                    ret = EXIT_FAIL;
                    goto end;
                }

                if (!reuse_ctx) {
                    EVP_PKEY_CTX_free(pctx);
                    pctx = NULL;
                }
            } else {
                if (!reuse_ctx) {
                    mdctx = EVP_MD_CTX_new();
                    if (!mdctx) {
                        fprintf(stderr, "EVP_MD_CTX_new failed"
                                " (seed %zu, msg %zu)\n", i, j);
                        ret = EXIT_FAIL;
                        goto end;
                    }
                }

                if (reuse_ctx && !EVP_MD_CTX_reset(mdctx)) {
                    fprintf(stderr, "EVP_MD_CTX_reset failed"
                            " (seed %zu, msg %zu)\n", i, j);
                    ret = EXIT_FAIL;
                    goto end;
                }

                if (EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, NULL,
                                           pkey, sign_params) <= 0 ||
                    EVP_DigestSign(mdctx, sig_buf, &slen,
                                   msgs[j].data, msgs[j].len) <= 0) {
                    fprintf(stderr, "Signing failed (seed %zu, msg %zu)\n",
                            i, j);
                    ERR_print_errors_fp(stderr);
                    ret = EXIT_FAIL;
                    goto end;
                }

                if (!reuse_ctx) {
                    EVP_MD_CTX_free(mdctx);
                    mdctx = NULL;
                }
            }

            if (fwrite(sig_buf, 1, sig_sz, outf) != sig_sz) {
                fprintf(stderr, "Write error: %s\n", strerror(errno));
                ret = EXIT_FAIL;
                goto end;
            }
            total_sigs++;
        }
    }

    fprintf(stderr, "Wrote %zu signatures to %s\n", total_sigs, sig_path);

end:
    if (reuse_ctx) {
        EVP_PKEY_CTX_free(pctx);
        EVP_MD_CTX_free(mdctx);
    }
    EVP_SIGNATURE_free(sa);
    EVP_PKEY_free(pkey);
    free(sig_buf);
    fclose(outf);
    free(msgs);
    free(seed_data);
    free(msg_data);

    return ret;
}
