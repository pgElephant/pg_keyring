#include "postgres.h"

#include <openssl/ssl.h>
#include <openssl/pem.h>

#include "pg_keyring.h"

static int  _generate_ssl_key(unsigned char* key);

/* 
 * Generates an AES-256 key for use with SSL
 * Returns 0 on success, -1 on error
 */
int 
_generate_ssl_key(unsigned char* key)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int success = 0;
    unsigned char* salt = NULL;
    unsigned char* data = NULL;
    int datal = 0;
    int count = 1;

    if (key == NULL)
        return -1;
  
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -2;
  
    /* Disable padding for the key, we want a 256 bit key */
    success = EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (!success)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }

    /* Generate the key */
    success = EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha256(), salt, data, datal, count, key, NULL);
    if (success != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}


/* 
 * Get a key from the keyring
 * Returns 0 on success, -1 on error
 */
int
pg_keyring_get_key(char key_type, unsigned char *key)
{
    /* Ensure that we have a valid key pointer */
    if (key == NULL)
        return -1;
 
    switch (key_type)
    {
    case SSL_KEY:
        _generate_ssl_key(key);
        break;
    default:
        return -5;
        break;
    }
    return 0;    
}