#ifndef __PERSONIFIER_INCLUDES__
#define __PERSONIFIER_INCLUDES__
#define CODE_DES_KEY_SIZE 8
#define CODE_DES_IV_SIZE 8
#define NUM_ENTRIES_SIZE 4
typedef enum personifier_error
{
        ERROR_NO_ERROR,
        ERROR_REQUEST_DATA,
        ERROR_PROTECT_DATA,
        ERROR_USER_DATA,
        ERROR_OUT_OF_MEM_RSA_DECRYPT,
        ERROR_OUT_OF_MEM_RSA_REQUEST,
        ERROR_RSA_DECRYPTION,
        ERROR_OUT_OF_MEM_REPLY,
        ERROR_OUT_OF_MEM_INIT,
		ERROR_GENERATE_USERID
} personifier_error;

size_t process(const unsigned char* request, size_t request_size,
const unsigned char* user, size_t user_size,
const unsigned char* dbprotect, size_t dbprotect_size,
unsigned char** result, size_t *result_size);

#endif//__PERSONIFIER_INCLUDES__
