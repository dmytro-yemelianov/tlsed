/* Equivalent authenticated memory-BIO pair; benchmark-only external baseline. */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static void fail(const char *what) { fprintf(stderr,"%s\n",what); ERR_print_errors_fp(stderr); exit(1); }
static uint64_t now(void) { struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t)) fail("clock"); return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec; }
static int alpn(SSL *s,const unsigned char **out,unsigned char *len,const unsigned char *in,unsigned int n,void *arg) {
    (void)s;(void)arg;
    static const unsigned char protocols[] = {7,'b','e','n','c','h','/','1'};
    return SSL_select_next_proto((unsigned char**)out,len,protocols,sizeof protocols,in,n)==OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
}
static void pump(SSL *from,SSL *to) {
    unsigned char buf[32768]; BIO *a=SSL_get_wbio(from),*b=SSL_get_rbio(to);
    while(BIO_ctrl_pending(a)) { int n=BIO_read(a,buf,sizeof buf); if(n<=0 || BIO_write(b,buf,n)!=n) fail("BIO progress"); }
}
static void step(SSL *s) { int r=SSL_do_handshake(s); if(r!=1) { int e=SSL_get_error(s,r); if(e!=SSL_ERROR_WANT_READ && e!=SSL_ERROR_WANT_WRITE) fail("handshake"); } }
static void pair(SSL_CTX *cc,SSL_CTX *sc,SSL **c,SSL **s) {
    *c=SSL_new(cc); *s=SSL_new(sc); if(!*c||!*s) fail("SSL_new");
    SSL_set_bio(*c,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem())); SSL_set_connect_state(*c);
    SSL_set_bio(*s,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem())); SSL_set_accept_state(*s);
    if(!SSL_set1_host(*c,"localhost") || !SSL_set_tlsext_host_name(*c,"localhost")) fail("identity setup");
    static const unsigned char proto[]={7,'b','e','n','c','h','/','1'};
    if(SSL_set_alpn_protos(*c,proto,sizeof proto)) fail("ALPN setup");
    for(int i=0;i<32;i++) {
        step(*c); pump(*c,*s); step(*s); pump(*s,*c);
        if(SSL_is_init_finished(*c)&&SSL_is_init_finished(*s)) {
            const unsigned char *p;unsigned int n;SSL_get0_alpn_selected(*c,&p,&n);
            if(SSL_get_verify_result(*c)!=X509_V_OK || SSL_version(*c)!=TLS1_3_VERSION || n!=7 || memcmp(p,"bench/1",7)) fail("negotiated policy");
            return;
        }
    }
    fail("handshake progress bound");
}
int main(int argc,char **argv) {
    if(argc!=4) fail("usage: openssl-memory FIXTURE_DIR SAMPLES BULK_RECORDS");
    int samples=atoi(argv[2]),records=atoi(argv[3]); if(samples<=0||records<=0) fail("positive counts required");
    SSL_CTX *cc=SSL_CTX_new(TLS_client_method()),*sc=SSL_CTX_new(TLS_server_method()); if(!cc||!sc)fail("context");
    SSL_CTX *contexts[]={cc,sc};
    for(int i=0;i<2;i++) {
        if(!SSL_CTX_set_min_proto_version(contexts[i],TLS1_3_VERSION)||!SSL_CTX_set_max_proto_version(contexts[i],TLS1_3_VERSION)
           ||!SSL_CTX_set_ciphersuites(contexts[i],"TLS_AES_128_GCM_SHA256")||!SSL_CTX_set1_groups_list(contexts[i],"X25519")) fail("TLS profile");
        SSL_CTX_set_session_cache_mode(contexts[i],SSL_SESS_CACHE_OFF); SSL_CTX_set_options(contexts[i],SSL_OP_NO_TICKET);
    }
    SSL_CTX_set_num_tickets(sc,0); SSL_CTX_set_alpn_select_cb(sc,alpn,NULL); SSL_CTX_set_verify(cc,SSL_VERIFY_PEER,NULL);
    char path[4096];
    snprintf(path,sizeof path,"%s/ca.pem",argv[1]);if(!SSL_CTX_load_verify_locations(cc,path,NULL))fail("CA");
    snprintf(path,sizeof path,"%s/server.pem",argv[1]);if(SSL_CTX_use_certificate_file(sc,path,SSL_FILETYPE_PEM)!=1)fail("certificate");
    snprintf(path,sizeof path,"%s/server-key.pem",argv[1]);if(SSL_CTX_use_PrivateKey_file(sc,path,SSL_FILETYPE_PEM)!=1||!SSL_CTX_check_private_key(sc))fail("key");
    puts("implementation,workload,direction,payload_bytes,iterations,sample,elapsed_ns");
    SSL *c,*s;
    for(int i=0;i<5;i++){pair(cc,sc,&c,&s);SSL_free(c);SSL_free(s);}
    for(int i=0;i<samples;i++){uint64_t t=now();pair(cc,sc,&c,&s);uint64_t elapsed=now()-t;
        printf("openssl,full_handshake,both,0,1,%d,%llu\n",i,(unsigned long long)elapsed);SSL_free(c);SSL_free(s);}
    size_t sizes[]={64,1024,16384}; unsigned char payload[16384],received[16384];memset(payload,0x5a,sizeof payload);
    for(int z=0;z<3;z++) for(int d=0;d<2;d++) {
        pair(cc,sc,&c,&s);SSL *sender=d?s:c,*receiver=d?c:s;
        for(int i=0;i<samples;i++){uint64_t t=now();
            for(int j=0;j<records;j++){size_t n=0,m=0;
                if(!SSL_write_ex(sender,payload,sizes[z],&n)||n!=sizes[z])fail("write");pump(sender,receiver);
                if(!SSL_read_ex(receiver,received,sizes[z],&m)||m!=sizes[z]||memcmp(payload,received,m))fail("read/plaintext");
            }
            printf("openssl,bulk,%s,%zu,%d,%d,%llu\n",d?"server_to_client":"client_to_server",sizes[z],records,i,(unsigned long long)(now()-t));
        }SSL_free(c);SSL_free(s);
    }
    SSL_CTX_free(cc);SSL_CTX_free(sc);return 0;
}
