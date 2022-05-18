#include "mbedtls.h"

static mbedtls_entropy_context *entropy = NULL;
static mbedtls_ctr_drbg_context *ctr_drbg = NULL;
static mbedtls_ssl_config *conf = NULL;
static mbedtls_x509_crt *cacert = NULL;
static mbedtls_x509_crt *clicert = NULL;
static mbedtls_pk_context *clikey = NULL;
static uint32_t timeout = 0;
static uint16_t mtu = 0;

int init_drbg(int verbose)
{
    if (ctr_drbg == NULL)
    {
        int ret;
        ctr_drbg = malloc(sizeof(mbedtls_ctr_drbg_context));
        mbedtls_ctr_drbg_init(ctr_drbg);

        time_t now;
        struct tm ts;
        char buf[92] = "libfetch/2.0";

        time(&now);

        // Format time, "ddd yyyy-mm-dd hh:mm:ss zzz"
        ts = *localtime(&now);
        strftime((buf + 12), sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
        
        entropy = malloc(sizeof(mbedtls_entropy_context));
        mbedtls_entropy_init(entropy);
        if ((ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                                         buf,
                                         92)) != 0)
        {
            if (verbose)
            {
                fprintf(stderr, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
            }
            return -1;
        }
    }
    return 0;
}

int init_config(int verbose)
{
    if (conf == NULL)
    {
        int ret;
        conf = malloc(sizeof(mbedtls_ssl_config));
        mbedtls_ssl_config_init(conf);
        if ((ret = mbedtls_ssl_config_defaults(conf,
                                               MBEDTLS_SSL_IS_CLIENT,
                                               MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
        {
            if (verbose)
            {
                fprintf(stderr, " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
            }
            return (-1);
        }

        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_ca_chain(conf, cacert, NULL);
        mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
        mbedtls_ssl_conf_renegotiation(conf, MBEDTLS_SSL_RENEGOTIATION_ENABLED);
        mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
        mbedtls_ssl_conf_read_timeout(conf, timeout);
    }
    return 0;
}

int mbedtls_set_read_timeout(uint32_t _timeout) {
    timeout = _timeout;
    if (conf != NULL) {
        mbedtls_ssl_conf_read_timeout(conf, timeout);
    }
    return 0;
}

int mbedtls_set_mtu(uint16_t _mtu) {
    mtu = _mtu;
    return 0;
}

int init_cacert(int verbose)
{
    if (cacert == NULL) {
        const unsigned char *cacert_s = "";
#if defined(CA_CERT_FILE)
        const char* cacertPath = CA_CERT_FILE;
#else
        const char *cacertPath = getenv("SSL_CA_CERT");
#endif

        cacert = malloc(sizeof(mbedtls_x509_crt));
        mbedtls_x509_crt_init(cacert);        

        int ret = mbedtls_x509_crt_parse_file(cacert, cacertPath == NULL ? "cacert.pem" : cacertPath); //cacertPath == NULL ? "cacert.pem" : cacertPath);

        if (ret < 0)
        {
            ret = mbedtls_x509_crt_parse(cacert, cacert_s, sizeof(cacert_s));
            if (ret < 0)
            {
                if (verbose)
                {
                    fprintf(stderr, " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
                }
                return -1;
            }
        }
    }
    return 0;
}

int init_clicert(int verbose)
{
    const char *clicertPath = getenv("SSL_CLIENT_CERT");
    const char *clikeyPath = getenv("SSL_CLIENT_KEY");
    const char *clikeyPass = getenv("SSL_CLIENT_KEY_PASS");

    if (clicert == NULL)
    {
        int ret;

        if (clicertPath != NULL && clikeyPath == NULL)
        {
            if (verbose)
            {
                fprintf(stderr, "SSL_CLIENT_KEY not specified!");
            }
            return -1;
        }

        if (clicertPath == NULL && clikeyPath != NULL)
        {
            if (verbose)
            {
                fprintf(stderr, "SSL_CLIENT_CERT not specified!");
            }
            return -1;
        }

        if (clicertPath != NULL && clikeyPath != NULL)
        {
            /* Load the client certificate */
            clicert = malloc(sizeof(mbedtls_x509_crt));
            mbedtls_x509_crt_init(clicert);
            ret = mbedtls_x509_crt_parse_file(clicert, clicertPath);
            if (ret)
            {
                if (verbose)
                {
                    fprintf(stderr, "Error reading client cert file %s - mbedTLS: (-0x%04X)",
                            clicertPath, -ret);
                }
                return -1;
            }

            /* Load the client private key */
            clikey = malloc(sizeof(mbedtls_pk_context));
            mbedtls_pk_init(clikey);

            ret = mbedtls_pk_parse_keyfile(clikey, clikeyPath, clikeyPass, mbedtls_ctr_drbg_random, NULL);
            if (ret == 0 && !(mbedtls_pk_can_do(clikey, MBEDTLS_PK_RSA) ||
                              mbedtls_pk_can_do(clikey, MBEDTLS_PK_ECKEY)))
                ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;

            if (ret)
            {
                if (verbose)
                {
                    fprintf(stderr, "Error reading private key %s - mbedTLS: (-0x%04X)",
                            clikey, -ret);
                }

                return -1;
            }

            mbedtls_ssl_conf_own_cert(conf, clicert, clikey);
        }
    }
    return 0;
}

/*
 * Enable SSL on a connection.
 */
int fetch_mbedtls(conn_t *conn, const struct url *URL, int verbose, int permissive)
{
    int ret;
    uint32_t flags;
    conn->ssl = malloc(sizeof(mbedtls_ssl_context));

    mbedtls_ssl_init(conn->ssl);
    if (conf != NULL && mtu > 0 && mtu < MBEDTLS_SSL_OUT_CONTENT_LEN) {
        mbedtls_ssl_set_mtu(conn->ssl, mtu);
    }
    if (init_drbg(verbose) != 0 || init_cacert(verbose) != 0 || init_clicert(verbose) != 0 || init_config(verbose) != 0)
    {
        return -1;
    }
   
    if ((ret = mbedtls_ssl_setup(conn->ssl, conf)) != 0 )
    {
        fprintf(stderr, " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        return (-1);
    }

    conn->buf_events = 0;
    mbedtls_ssl_set_bio(conn->ssl, &conn->sd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    while ((ret = mbedtls_ssl_handshake(conn->ssl)) != 0)
    {
        if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            if (verbose)
            {
		        char buf[1024];
                mbedtls_strerror(ret, buf, 1024);
                fprintf(stderr, " failed\n  ! mbedtls_ssl_handshake returned -0x%x - %s\n\n", -ret, buf);
            }
            return (-1);
        }
    }

    if ((flags = mbedtls_ssl_get_verify_result(conn->ssl)) != 0)
    {
        char vrfy_buf[512];
        if (verbose)
        {
            fprintf(stderr, " failed\n");
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
            fprintf(stderr, "%s\n", vrfy_buf);
        }
        if (!permissive)
        {
            return (-1);
        }
    }

    if (verbose)
    {
        fetch_info("SSL connection established using %s\n", mbedtls_ssl_get_ciphersuite(conn->ssl));
    }

    return 0;
}

int fetch_mbedtls_close()
{
    if (conf != NULL)
    {
        mbedtls_ssl_config_free(conf);
        conf = NULL;
    }
    if (ctr_drbg != NULL) 
    { 
        mbedtls_ctr_drbg_free(ctr_drbg);
        ctr_drbg = NULL;
    }
    if (entropy != NULL)
    {
        mbedtls_entropy_free(entropy);
        entropy = NULL;
    }
    if (clicert != NULL)
    {
        mbedtls_x509_crt_free(clicert);
        clicert = NULL;
    }
    if (cacert != NULL) 
    {
        mbedtls_x509_crt_free(cacert);
        cacert = NULL;
    }
    if (clikey != NULL)
    {
        mbedtls_pk_free(clikey);
        clikey = NULL;
    } 
}