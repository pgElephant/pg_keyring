#include "postgres.h"

#include <openssl/ssl.h>
#include <openssl/pem.h>

#include "fmgr.h"

#include "pg_keyring.h"

PG_MODULE_MAGIC;

Datum pg_keyring_get_key(PG_FUNCTION_ARGS);
Datum pg_keyring_encrypt(PG_FUNCTION_ARGS);
Datum pg_keyring_decrypt(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(pg_keyring_get_key);
PG_FUNCTION_INFO_V1(pg_keyring_encrypt);
PG_FUNCTION_INFO_V1(pg_keyring_decrypt);

void _PG_init(void);

void _PG_init(void) 
{
    
}

/* 
 * pg_keyring_get_key
 * 
 * Gets a key from the keyring store.
 * 
 * Parameters:
 *  keyid - a unique identifier for the key
 * 
 * Returns: the key as a byte array
 */
Datum pg_keyring_get_key(PG_FUNCTION_ARGS)
{
    PG_RETURN_NULL();
}

/* 
 * pg_keyring_encrypt
 * 
 * Encrypts a string using a key from the keyring store.
 * 
 * Parameters:
 *  keyid - a unique identifier for the key
 *  clear_text - the string to be encrypted
 * 
 * Returns: the encrypted string as a byte array
 */
Datum pg_keyring_encrypt(PG_FUNCTION_ARGS)
{
    PG_RETURN_NULL();
}

/* 
 * pg_keyring_decrypt
 * 
 * Decrypts a string using a key from the keyring store.
 * 
 * Parameters:
 *  keyid - a unique identifier for the key
 *  cipher_text - the string to be decrypted
 * 
 * Returns: the decrypted string as a byte array
 */
Datum pg_keyring_decrypt(PG_FUNCTION_ARGS)
{
    PG_RETURN_NULL();
}
