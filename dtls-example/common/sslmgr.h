#ifndef _sslmgr_h
#define _sslmgr_h

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

extern BIO *dtls_bio_err;
int dtls_exit_err (char *string);
int dtls_generate_rsa_key (SSL_CTX *ctx);
void dtls_destroy_ctx (SSL_CTX *);
void dtls_report_berr (char *, ...);
void dtls_report_err (char *, ...);
int dtls_password_cb (char *, int, int, void *);
void dtls_load_dh_params (SSL_CTX *ctx, char *dh_file);
void dtls_info_callback (const SSL *ssl, int where, int ret);
int dtls_verify_callback (int ok, X509_STORE_CTX *ctx);

#endif	// !_sslmgr_h
