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
    /* Set the default value for keyring_file_data */
    DefineCustomStringVariable("pg_keyring.keyring_file_data",
                               "Path to the keyring data file",
                               NULL,
                               &keyring_file_data,
                               NULL,
                               PGC_USERSET,
                               GUC_SUPERUSER_ONLY,
                               NULL,
                               NULL,
                               NULL);

    /* Set the default value for keyring_file_password */
    DefineCustomStringVariable("pg_keyring.keyring_file_password",
                               "Path to the keyring password file",
                               NULL,
                               &keyring_file_password,
                               NULL,
                               PGC_USERSET,
                               GUC_SUPERUSER_ONLY,
                               NULL,
                               NULL,
                               NULL);
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

    if (!keyring_file_password || strlen(keyring_file_password) == 0)
    {
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("Invalid password file name. Set keyring_file_password in postgresql.conf.")));
    }

    if (!keyring_file_password || strlen(keyring_file_password) == 0)
    {
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("Invalid key file name. Set keyring_file_data in postgresql.conf.")));
    }

    /* Create a new file to store the password */
    passwordFile = fopen(keyring_file_password, "w");
    if (passwordFile == NULL)
    {
        ereport(ERROR, (errcode_for_file_access(),
                        errmsg("Could not write password file \"(%s)\"", keyring_file_password)));
    }

    fprintf(passwordFile, "%s\n", password);
    fclose(passwordFile);

    pfree(password);
    pfree(encryptionProtocol);

    PG_RETURN_TEXT_P(cstring_to_text_with_len("OK",2));
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
    char* storedPassword = NULL;
    FILE* passwordFile;
    char* password = text_to_cstring(txtPassword);

    /*
     * Verify that the provided password matches the content of the
     * keyring_file_password file.
     */
    passwordFile = fopen(keyring_file_password, "r");
    if (passwordFile != NULL)
    {
        char buffer[1024];
        if (fgets(buffer, sizeof(buffer), passwordFile) != NULL)
        {
            char* newline = NULL;
            storedPassword = strdup(buffer);
            /* Remove trailing newline character if present */
            newline = strchr(storedPassword, '\n');
            if (newline != NULL)
                *newline = '\0';
        }
        fclose(passwordFile);
    }
    if (storedPassword == NULL || strcmp(password, storedPassword) != 0)
    {
        ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD),
                        errmsg("Invalid password or permission denied")));
    }
    free(storedPassword);
    pfree(password);

    /*
     * Remove the file associated with keyring_file_password. The filename is
     * stored in the keyring_file_password GUC variable.
     */
    if (unlink(keyring_file_password) != 0)
    {
        ereport(ERROR, (errcode_for_file_access(),
                        errmsg("Failed to remove the file associated with keyring_file_password")));
    }

    PG_RETURN_TEXT_P(cstring_to_text_with_len("OK", 2));
}
