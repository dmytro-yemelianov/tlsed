/* Times OpenSSL 3 chain + host verification alone, with the same policy the client uses:
 * fixture CA, purpose SSL_SERVER, X509_V_FLAG_X509_STRICT, host "localhost".
 * Diagnostic only: explains how much of the OpenSSL handshake gap is certificate policy. */
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static X509 *load(const char *path) {
    BIO *bio = BIO_new_file(path, "r");
    X509 *cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    BIO_free(bio);
    return cert;
}

static unsigned long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000000ULL + (unsigned long long)t.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: x509_verify_micro CA_PEM LEAF_PEM ITERATIONS\n");
        return 2;
    }
    X509 *ca = load(argv[1]);
    X509 *leaf = load(argv[2]);
    long n = atol(argv[3]);
    if (!ca || !leaf || n <= 0) {
        fprintf(stderr, "load failed\n");
        return 1;
    }
    /* The trust store lives in the SSL_CTX, so it is built once, outside the timer. */
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, ca);
    unsigned long long total = 0;
    for (long i = 0; i < n; i++) {
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        STACK_OF(X509) *untrusted = sk_X509_new_null();
        unsigned long long t0 = now_ns();
        X509_STORE_CTX_init(ctx, store, leaf, untrusted);
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
        X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_SERVER);
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT);
        X509_VERIFY_PARAM_set1_host(param, "localhost", 0);
        int ok = X509_verify_cert(ctx);
        total += now_ns() - t0;
        if (ok != 1) {
            fprintf(stderr, "verification failed: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
            return 1;
        }
        sk_X509_free(untrusted);
        X509_STORE_CTX_free(ctx);
    }
    X509_STORE_free(store);
    printf("iterations=%ld mean_ns=%.1f\n", n, (double)total / (double)n);
    X509_free(ca);
    X509_free(leaf);
    return 0;
}
