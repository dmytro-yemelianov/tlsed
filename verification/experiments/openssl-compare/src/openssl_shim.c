/* OpenSSL 3 TLS 1.3 client over memory BIOs: a benchmark-only peer for the paired comparison.
 * Surface mirrors the Rust clients: feed input, drain output, write and read plaintext. */
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const unsigned char kAlpn[] = {7, 'b', 'e', 'n', 'c', 'h', '/', '1'};

/* WANT_READ and WANT_WRITE never add to the error queue, so clearing it here would only
 * add work to every partial-record step. Clear only on a fatal error. */
static int want_io(SSL *s, int r) {
    int e = SSL_get_error(s, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
        return 1;
    }
    ERR_clear_error();
    return 0;
}

SSL_CTX *oc_ctx_new(const uint8_t *ca, size_t ca_len, const char *suite, const char *groups) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        return NULL;
    }
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf(ca, (int)ca_len);
    int ok = bio != NULL
        && SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1
        && SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1
        && SSL_CTX_set_ciphersuites(ctx, suite) == 1
        && SSL_CTX_set1_groups_list(ctx, groups) == 1
        && (cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL
        && X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert) == 1
        && SSL_CTX_set_alpn_protos(ctx, kAlpn, sizeof kAlpn) == 0;
    X509_free(cert);
    BIO_free(bio);
    if (!ok) {
        ERR_clear_error();
        SSL_CTX_free(ctx);
        return NULL;
    }
    X509_VERIFY_PARAM *param = SSL_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_SERVER);
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(ctx, 0);
    return ctx;
}

void oc_ctx_free(SSL_CTX *ctx) {
    SSL_CTX_free(ctx);
}

SSL *oc_conn_new(SSL_CTX *ctx, const char *host) {
    SSL *s = SSL_new(ctx);
    if (s == NULL) {
        return NULL;
    }
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    if (rbio == NULL || wbio == NULL) {
        BIO_free(rbio);
        BIO_free(wbio);
        SSL_free(s);
        return NULL;
    }
    SSL_set_bio(s, rbio, wbio); /* SSL_free releases both BIOs */
    SSL_set_connect_state(s);
    if (SSL_set1_host(s, host) != 1 || SSL_set_tlsext_host_name(s, host) != 1) {
        SSL_free(s);
        return NULL;
    }
    return s;
}

void oc_conn_free(SSL *s) {
    SSL_free(s);
}

/* Feed `in`, advance the handshake or record layer, drain up to `out_cap` bytes of output.
 * work: output still pending. ready: decrypted application data available. */
int oc_drive(SSL *s, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap,
             size_t *produced, int *work, int *ready) {
    BIO *rbio = SSL_get_rbio(s);
    BIO *wbio = SSL_get_wbio(s);
    if (in_len > 0 && BIO_write(rbio, in, (int)in_len) != (int)in_len) {
        return -1;
    }
    /* Process only when bytes arrived (or the first flight is owed), as rustls does with
     * read_tls + process_new_packets, so idle pump steps cost the same on every client. */
    if (!SSL_is_init_finished(s)) {
        if (in_len > 0 || SSL_in_before(s)) {
            int r = SSL_do_handshake(s);
            if (r != 1 && !want_io(s, r)) {
                return -1;
            }
        }
    } else if (in_len > 0) {
        unsigned char byte;
        int r = SSL_peek(s, &byte, 1); /* decrypts one record; leaves plaintext buffered */
        if (r <= 0 && !want_io(s, r)) {
            return -1;
        }
    }
    size_t pending = BIO_ctrl_pending(wbio);
    size_t n = pending < out_cap ? pending : out_cap;
    if (n > 0 && BIO_read(wbio, out, (int)n) != (int)n) {
        return -1;
    }
    *produced = n;
    *work = BIO_ctrl_pending(wbio) > 0;
    *ready = SSL_pending(s) > 0;
    return 0;
}

int oc_write(SSL *s, const uint8_t *data, size_t len) {
    size_t written = 0;
    if (SSL_write_ex(s, data, len, &written) != 1 || written != len) {
        ERR_clear_error();
        return -1;
    }
    return 0;
}

int oc_read(SSL *s, uint8_t *data, size_t len) {
    size_t got = 0;
    while (got < len) {
        size_t n = 0;
        if (SSL_read_ex(s, data + got, len - got, &n) != 1) {
            ERR_clear_error();
            return -1;
        }
        got += n;
    }
    return 0;
}

int oc_established(SSL *s) {
    return SSL_is_init_finished(s) ? 1 : 0;
}

/* 0 when TLS 1.3, the expected suite, verified chain and host, and ALPN bench/1. */
int oc_check(SSL *s, const char *cipher) {
    if (SSL_version(s) != TLS1_3_VERSION) {
        return -1;
    }
    const SSL_CIPHER *c = SSL_get_current_cipher(s);
    if (c == NULL || strcmp(SSL_CIPHER_get_name(c), cipher) != 0) {
        return -1;
    }
    if (SSL_get_verify_result(s) != X509_V_OK) {
        return -1;
    }
    const unsigned char *p = NULL;
    unsigned int len = 0;
    SSL_get0_alpn_selected(s, &p, &len);
    if (len != 7 || memcmp(p, "bench/1", 7) != 0) {
        return -1;
    }
    return 0;
}
