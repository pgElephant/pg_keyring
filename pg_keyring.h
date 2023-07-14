
#ifndef PG_KMS
#define PG_KMS

#define SSL_KEY 0
#define KEY_LENGTH 256

int pg_keyring_get_key(char key_type, unsigned char *key);

#endif /* PG_KMS */
