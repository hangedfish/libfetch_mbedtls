#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>

typedef struct mbedtls_ssl_context SSL;
typedef void X509;
typedef void SSL_CTX;
typedef void SSL_METHOD;

#define SSL_read mbedtls_ssl_read
#define SSL_write mbedtls_ssl_write
#define SSL_get_error(x, rlen) rlen
#define SSL_ERROR_WANT_READ MBEDTLS_ERR_SSL_WANT_READ
#define SSL_ERROR_WANT_WRITE MBEDTLS_ERR_SSL_WANT_WRITE

#define SSL_shutdown mbedtls_ssl_free
#define SSL_set_connect_state(x) void
#define SSL_free(x) void
#define SSL_CTX_free(x) void
#define X509_free(x) void