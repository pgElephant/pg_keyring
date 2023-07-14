#include "postgres.h"

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <unistd.h>

#include "utils/guc.h"
#include "fmgr.h"
#include "utils/builtins.h"

#include "pg_keyring.h"

PG_MODULE_MAGIC;

Datum keyring_key_generate(PG_FUNCTION_ARGS);
Datum keyring_key_remove(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(keyring_key_generate);
PG_FUNCTION_INFO_V1(keyring_key_remove);

void _PG_init(void);

void _PG_init(void) 
{
    /* Set the value for keyring_file_data */
    SetConfigOption("keyring_file_data", "/usr/local/mysql/mysql-keyring/keyring", PGC_USERSET, PGC_S_FILE);

    /* Set the value for keyring_file_password */
    SetConfigOption("keyring_file_password", "/path/to/password_file", PGC_USERSET, PGC_S_FILE);
}

/*
 * keyring_key_generate
 *
 * Generate a key of the specified length using the specified encryption protocol.
 * Key will be stored in the keyring and encrypted using the password.
 */
Datum
keyring_key_generate(PG_FUNCTION_ARGS)
{
    text* txtPassword = PG_GETARG_TEXT_P(0);
    text* txtProtocol = PG_GETARG_TEXT_P(1);
    int32 keyLength = PG_GETARG_INT32(2);
    char* password = text_to_cstring(txtPassword);
    char* encryptionProtocol = text_to_cstring(txtProtocol);
    FILE* passwordFile;
    const char* passwordFileName;

    /* Only AES is supported */
    if (strcmp(encryptionProtocol, "AES") != 0)
    {
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("Invalid encryption protocol. Only AES is supported.")));
    }

    /* Key length must be a positive multiple of 8 */
    if (keyLength <= 0 || keyLength % 8 != 0)
    {
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("Invalid key size. Key size must be a positive multiple of 8.")));
    }

    passwordFileName = GetConfigOption("keyring_file_password", true, false);

    /* Create a new file to store the password */
    passwordFile = fopen(passwordFileName, "w");
    if (passwordFile == NULL)
    {
        ereport(ERROR, (errcode(ERRCODE_IO_ERROR),
                        errmsg("Failed to open the new password file for writing.")));
    }

    fprintf(passwordFile, "%s\n", password);
    fclose(passwordFile);

    pfree(password);
    pfree(encryptionProtocol);

    PG_RETURN_NULL();
}


/*
 * keyring_key_remove
 *
 * Remove the file associated with the keyring_file_password GUC variable.
 */
Datum
keyring_key_remove(PG_FUNCTION_ARGS)
{
    text* txtPassword = PG_GETARG_TEXT_P(0);
    char* password = text_to_cstring(txtPassword);
    const char *filename; 
 
    /*
     * Remove the file associated with keyring_file_password. The filename is
     * stored in the keyring_file_password GUC variable.
     */
    filename = GetConfigOption("keyring_file_password", true, false);
    if (filename == NULL)
    {
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("keyring_file_password not set")));
    }
    if (unlink(filename) != 0)
    {
        ereport(ERROR, (errcode_for_file_access(),
                        errmsg("Failed to remove the file associated with keyring_file_password")));
    }
    pfree(password);

    PG_RETURN_NULL();
}
