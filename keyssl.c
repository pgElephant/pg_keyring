#include "postgres.h"

#include <openssl/ssl.h>
#include <openssl/pem.h>

#include "pg_kms.h"

static int pgkms_get_ssl_key();

int
pg_keyring_get_key(char *key_type, char** key)
{
    int ret = 0;
    switch (key_type)
    {
    case SSL_KEY:
        pgkms_get_ssl_key();
        ret = 0;
        break;

    case AWS_KEY:
        if (pgkms_get_aws_key() == 1)
            ret = 1;
        break;
    default:
        ret = -1;
        break;
    }
    return ret;    
 }

int
ssl_getkey()
{
    SSL_CTX *context; /* A context for SSL/TLS connections. */
    SSL *ssl; /* An SSL/TLS connection. */
    EVP_PKEY *key; /* The private key. */

    /* Initialize the OpenSSL library. */
    if (SSL_library_init() != 1)
    {
        return 1;
    }
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Create a context for SSL/TLS connections. */
    context = SSL_CTX_new(TLS_method());
    if (context == NULL)
    {
        return 1;
    }

    /* Load the private key file. */
    if (SSL_CTX_use_PrivateKey_file(context, "private_key.pem", SSL_FILETYPE_PEM) != 1)
    {
        SSL_CTX_free(context);
        return 1;
    }

    /* Load the certificate file. */
    if (SSL_CTX_use_certificate_file(context, "certificate.pem", SSL_FILETYPE_PEM) != 1)
    {
        SSL_CTX_free(context);
        return 1;
    }

    /* Create an SSL/TLS connection. */
    ssl = SSL_new(context);
    if (ssl == NULL)
    {
        SSL_CTX_free(context);
        return 1;
    }

    /* Get the private key. */
    key = SSL_CTX_get0_privatekey(context);
    if (key == NULL)
    {
        SSL_free(ssl);
        SSL_CTX_free(context);
        return 1;
    }

    /* Print the private key. */
    PEM_write_PrivateKey(stdout, key, NULL, NULL, 0, NULL, NULL);

    /* Clean up. */
    SSL_free(ssl);
    SSL_CTX_free(context);
    EVP_PKEY_free(key);

    return 0;
}
