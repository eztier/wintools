#include <windows.h>
// #include <strsafe.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

const char* tinycryto_version = "0.5.2";

extern unsigned char* decrypted_data;

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, char *hiv, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);
int set_hex(char *in, unsigned char *out, int size);
__declspec( dllexport ) char* get_shared_secret(const char* keyfile, const char* ssecret);
void extract_shared_secret(char* secret, unsigned char* key_data, char* iv);

// small file encrypt
__declspec( dllexport ) int EncryptFileX(unsigned char* data, unsigned long datasize, char* private_key, char* shared_secret, char* filename);
// large file encrypt
__declspec( dllexport ) int EncryptFileInit(char* private_key, char* shared_secret, char* filename);
__declspec( dllexport ) int EncryptFileUpdate(unsigned char* data, unsigned long datasize);
__declspec( dllexport ) int EncryptFileFinal();

__declspec( dllexport ) unsigned char* DecryptFileX(char* private_key, char* shared_secret, char* filename, int* decrypted_size);
__declspec( dllexport ) void FreeDecryptedMemory();
