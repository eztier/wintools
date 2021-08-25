#ifndef DLLEXPORT
#define DLLEXPORT __attribute__((visibility("default")))
#endif

#ifdef _WIN32
#include <windows.h>
#define DLLEXPORT __declspec( dllexport )
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
// Link 1.0.0 with -L/lib/x86_64-linux-gnu -l:libcrypto.so.1.0.0
#ifdef OPENSSL_100
#include "openssl-1_0_0/evp.h"
#else
// Link 1.1.0 with -L/usr/local/lib -lcrypto
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#endif

#include <openssl/pem.h>
#include "base64.h"

#ifndef EVP_CIPHER_CTX_reset
#define EVP_CIPHER_CTX_reset(c) EVP_CIPHER_CTX_init(c)
#endif

#ifndef TINYCRYPTO
#define TINYCRYPTO

extern unsigned char* decrypted_data;

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, char *hiv, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);
int set_hex(char *in, unsigned char *out, int size);
DLLEXPORT char* get_shared_secret(const char* keyfile, const char* ssecret);
void extract_shared_secret(char* secret, unsigned char** key_data, char** iv);

// small file encrypt
DLLEXPORT int EncryptFileX(unsigned char* data, unsigned long datasize, char* private_key, char* shared_secret, char* filename);
// large file encrypt
DLLEXPORT int EncryptFileInit(char* private_key, char* shared_secret, char* filename);
DLLEXPORT int EncryptFileUpdate(unsigned char* data, unsigned long datasize);
DLLEXPORT int EncryptFileFinal();

DLLEXPORT unsigned char* DecryptFileX(char* private_key, char* shared_secret, char* filename, int* decrypted_size);
DLLEXPORT void FreeDecryptedMemory();

typedef bool BOOLEAN;

#endif
