
#ifndef PG_KMS
#define PG_KMS

#define SSL_KEY 0
#define KEY_LENGTH 256
#define MAXPATH 1024

int pg_keyring_get_key(char key_type, unsigned char *key);
char *keyring_file_password;
char *keyring_file_data;

#endif /* PG_KMS */
