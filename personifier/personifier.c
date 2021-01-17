#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include "rsaref/global.h"
#include "rsaref/rsaref.h"
#include "rsaref/rsa.h"
#include "personifier.h"

void InitRandomStruct (R_RANDOM_STRUCT *randomStruct);

size_t process(const unsigned char* request, size_t request_size,
const unsigned char* user, size_t user_size,
const unsigned char* dbprotect, size_t dbprotect_size,
unsigned char** result, size_t *result_size)
{
        R_RANDOM_STRUCT randomStruct;
        R_ENVELOPE_CTX context;
        char cid[16], iv[8], key[24], *decrypted, *decryptedrq, *userid, *cuserid;
        size_t replysize,keyLen;
        unsigned int decrlen, culen;
        int err, n;
        time_t tm;
        if(request && request_size)
        {
                if(dbprotect && dbprotect_size)
                {
						R_RSA_PRIVATE_KEY *PRIVATE_KEY = (R_RSA_PRIVATE_KEY *)(dbprotect + dbprotect_size - sizeof(R_RSA_PRIVATE_KEY));
						R_RSA_PUBLIC_KEY *PUBLIC_KEY = (R_RSA_PUBLIC_KEY *)(dbprotect + dbprotect_size - sizeof(R_RSA_PUBLIC_KEY) - sizeof(R_RSA_PRIVATE_KEY));
						char *seciv = (char *)(dbprotect + dbprotect_size - sizeof(R_RSA_PUBLIC_KEY) - sizeof(R_RSA_PRIVATE_KEY) - CODE_DES_IV_SIZE);
						char *seckey = (char *)(dbprotect + dbprotect_size - sizeof(R_RSA_PUBLIC_KEY) - sizeof(R_RSA_PRIVATE_KEY) - CODE_DES_IV_SIZE - CODE_DES_KEY_SIZE);
						int entries = *((int *)((char *)(dbprotect + dbprotect_size - sizeof(R_RSA_PUBLIC_KEY) - sizeof(R_RSA_PRIVATE_KEY) - CODE_DES_IV_SIZE - CODE_DES_KEY_SIZE) - NUM_ENTRIES_SIZE));
						unsigned long long *entry = (unsigned long long *)(dbprotect + dbprotect_size - NUM_ENTRIES_SIZE - sizeof(unsigned long long) * entries - sizeof(R_RSA_PUBLIC_KEY) - sizeof(R_RSA_PRIVATE_KEY) - CODE_DES_IV_SIZE - CODE_DES_KEY_SIZE);
                        if(user && (user_size == 2 || user_size == 4 || user_size == 8))
                        {
                                InitRandomStruct (&randomStruct);
                                context.encryptionAlgorithm = EA_DES_EDE3_CBC;
                                keyLen = 24;
                                decrypted = (char *)malloc(request_size);
								decrlen = (unsigned int)request_size;
                                if(decrypted)
                                {
                                        decryptedrq = (char *)malloc(request_size - (sizeof(key) + sizeof(iv)));
										memset(decryptedrq, 0, request_size - (sizeof(key) + sizeof(iv)));
                                        if(decryptedrq)
                                        {
											err = RSAPrivateDecrypt(decrypted, &decrlen, (unsigned char *)request, (unsigned int)request_size, PRIVATE_KEY);
                                            if(!err)
                                            {
												if(user_size >= 4 && user_size < 16)
												{
													time(&tm);
													memmove(key,decrypted,keyLen);
													memmove(iv,decrypted + keyLen,8);
													memmove(cid,decrypted + keyLen + sizeof(iv),sizeof(cid));
													replysize = ((dbprotect_size - sizeof(R_RSA_PUBLIC_KEY) - sizeof(R_RSA_PRIVATE_KEY) + 23) / 24) * 24 ;
													userid = (char *)malloc(PUBLIC_KEY->bits/8);
													memset(userid,0,PUBLIC_KEY->bits/8);
													cuserid = (char *)malloc(PUBLIC_KEY->bits/8);
													memset(cuserid, 0, PUBLIC_KEY->bits/8);
													memmove(userid, user, user_size);
													memmove(userid + user_size, &tm, sizeof(tm));
													culen = PUBLIC_KEY->bits/8;
													err = RSAPublicEncrypt(cuserid,&culen,userid,(unsigned int)(user_size + sizeof(tm)),PUBLIC_KEY,&randomStruct);
													if(!err)
													{
														for(n=0;n<entries;n++)if(cuserid[(n % PUBLIC_KEY->bits)/8] & (1 << ((n % PUBLIC_KEY->bits) % 8)))entry[n] |= 0x8000000000000000;
														for(n=0;n<8;n++)seckey[n] ^= cid[n%8];
														for(n=0;n<8;n++)seciv[n] ^= cid[n%8+8];
														for(n=0;n<8;n++)seckey[n] ^= cid[n%8+8];
														for(n=0;n<8;n++)seciv[n] ^= cid[n%8];
														*result = (char *)malloc(replysize);
														*result_size = replysize;
														free(userid);
														free(cuserid);
													}else
													{
														free(userid);
														free(cuserid);
														return ERROR_GENERATE_USERID;
													}
												}else if(user_size == 2)
												{
													memmove(key,decrypted,keyLen);
                                                    memmove(iv,decrypted + keyLen,8);
                                                    memmove(decryptedrq,decrypted + sizeof(key) + sizeof(iv),request_size - (sizeof(key) + sizeof(iv)));
													dbprotect = decryptedrq;
                                                    printf("%s\n",decryptedrq);
                                                    replysize = ((request_size - (sizeof(key) + sizeof(iv)) + 23) / 24) * 24;
                                                    *result = (char *)malloc(replysize);
                                                    *result_size = replysize;
                                                }
                                                if(*result)
                                                {
													CipherInit(&context, EA_DES_EDE3_CBC, key, iv, 1);
													CipherUpdate(&context,*result,(unsigned char *)dbprotect,(unsigned int)replysize);
													free(decryptedrq);
													free(decrypted);
													return ERROR_NO_ERROR;
                                                }else
                                                {
													free(decryptedrq);
													free(decrypted);
													return ERROR_OUT_OF_MEM_REPLY;
                                                }
											}else
											{
												free(decryptedrq);
												free(decrypted);
												return ERROR_RSA_DECRYPTION;
											}
										}else
										{
											free(decrypted);
											return ERROR_OUT_OF_MEM_RSA_DECRYPT;
										}
								}else
                                {
									return ERROR_OUT_OF_MEM_RSA_REQUEST;
								}
						}else 
                        {
							return ERROR_USER_DATA;
						}
                }else return ERROR_PROTECT_DATA;
        }else return ERROR_REQUEST_DATA;
}
///////////////////////////////////////////////////////////////////////////////////////
void InitRandomStruct(R_RANDOM_STRUCT *randomStruct)
{
  static unsigned int seedDword = 0;
  unsigned int bytesNeeded;
  time_t tm;
  time(&tm);
  seedDword = (unsigned int)tm;
  R_RandomInit (randomStruct);

  /* Initialize with all zero seed bytes, which will not yield an actual
       random number output.
   */
  while (1) {
    R_GetRandomBytesNeeded (&bytesNeeded, randomStruct);
    if (bytesNeeded == 0)
      break;

    R_RandomUpdate (randomStruct, (unsigned char *)&seedDword, 4);
  }
}
///////////////////////////////////////////////////////////////////////////////////////

