#define AES_BLOCK_SIZE 16
/**
  The MIT License (MIT)
  Copyright (c) 2011-2017 Henry Tao

  The following is based on the work of Saju Pillai:
  https://github.com/saju/misc/blob/master/misc/openssl_aes.c

  Existing functions have been modified and additional functions added to support Windows and designed to run with C# applications.  
**/
#include "program.h"

const char* shared_secret = "audit24\\key-new.enc";
const char* private_key = "audit24\\privatekey.pem";

//global vars
unsigned char* decrypted_data = NULL;

// "opaque" encryption, decryption ctx structures that libcrypto uses to record status of enc/dec operations
EVP_CIPHER_CTX en, de;
unsigned char inbuf[131072];
unsigned char outbuf[131072 + EVP_MAX_BLOCK_LENGTH];
int inlen, outlen;
unsigned long bytesWritten;
	
//exported dll not working with FILE*
FILE* fp = NULL;

static HANDLE hFile = NULL;

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, char *hiv, EVP_CIPHER_CTX *e_ctx,  EVP_CIPHER_CTX *d_ctx) {
  int i, nrounds = 5;
  unsigned char key[32], iv[32];
  const EVP_MD* dgst = EVP_md5();
    
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  //i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  //to match source code: openssl enc ... 
  i = EVP_BytesToKey(EVP_aes_256_cbc(), dgst, salt, key_data, key_data_len, 1, key, iv);
  
  if (!set_hex(hiv,iv,sizeof(iv))) 
	  return -1;
  if (!set_hex((char*)key_data,key,sizeof(key)))
	  return -1;

  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len) {
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0, ret;
  unsigned char *ciphertext = (unsigned char*)malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  ret = EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  ret = EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  /* update ciphertext with the final remaining bytes */
  ret = EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);
  
  *len = c_len + f_len;
  return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len) {
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0, ret;
  unsigned char *plaintext = (unsigned char*) malloc(p_len);
  
  ret = EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  ret = EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  ret = EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);
  *len = ret == 1 ? (p_len + f_len) : 0;
  
  return plaintext;
}

int set_hex(char *in, unsigned char *out, int size) {
	int i,n;
	unsigned char j;

	n=strlen(in);
	if (n > (size*2))
		{
		printf("hex string is too long\n");
		return(0);
		}
	memset(out,0,size);
	for (i=0; i<n; i++)
	{
		j=(unsigned char)*in;
		*(in++)='\0';
		if (j == 0) break;
		if ((j >= '0') && (j <= '9'))
			j-='0';
		else if ((j >= 'A') && (j <= 'F'))
			j=j-'A'+10;
		else if ((j >= 'a') && (j <= 'f'))
			j=j-'a'+10;
		else
			{
			printf("non-hex digit\n");
			return(0);
			}
		if (i&1)
			out[i/2]|=j;
		else
			out[i/2]=(j<<4);
	}
	return(1);
}

char* get_shared_secret(const char* keyfile, const char* ssecret) {
	HANDLE hFile = NULL;
	unsigned long fsize = 0, bytes_processed = 0;
	unsigned char* keybuf = NULL;
	unsigned char* secbuf = NULL;
	char* retval = NULL;
	BIO* bio = NULL;
	RSA* rsa = NULL;
	BOOLEAN succeeded;
	int decrypted_sz = 0;

	//get the private key
	hFile = CreateFile(keyfile,                // name of the write
    GENERIC_WRITE|GENERIC_READ,  // open for writing/read
    FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,   // share all
    0,                   // new security
    OPEN_EXISTING,          // overwrite FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,  // normal file
    FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,
	  NULL
  );  // attr. template
  
  if (hFile == INVALID_HANDLE_VALUE) { 
    return retval;
  }

	fsize = GetFileSize(hFile, NULL);
	keybuf = (unsigned char*) malloc(fsize);
	succeeded = ReadFile(hFile, keybuf, fsize, &bytes_processed, NULL);
	CloseHandle(hFile);

	if (!succeeded)
		return retval;
	
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		goto Cleanup;

	BIO_write(bio, keybuf, fsize);
	
	rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	if (rsa == NULL)
		goto Cleanup;

	//do stuff with rsa and get the shared secret
	hFile = CreateFile(ssecret,                // name of the write
    GENERIC_WRITE|GENERIC_READ,  // open for writing/read
    FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,   // share all
    0,                   // new security
    OPEN_EXISTING,          // overwrite FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,  // normal file
    FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,
	  NULL
  );  // attr. template
  
  if (hFile == INVALID_HANDLE_VALUE) { 
    goto Cleanup;
  }

	fsize = GetFileSize(hFile, NULL);
	secbuf = (unsigned char*) malloc(fsize);
	succeeded = ReadFile(hFile, secbuf, fsize, &bytes_processed, NULL);
	CloseHandle(hFile);

	if (!succeeded) 
		goto Cleanup;

	retval = (char*) malloc(fsize);
	decrypted_sz = RSA_private_decrypt(fsize, secbuf, (unsigned char*)retval, rsa, RSA_PKCS1_PADDING); // != -1
	if (decrypted_sz != -1) retval[decrypted_sz] = 0;
	
Cleanup:
	if (rsa != NULL) RSA_free(rsa);
	if (bio != NULL) BIO_free(bio);
	if (keybuf != NULL) free(keybuf);
	if (secbuf != NULL) free(secbuf);

	return retval;
}

void extract_shared_secret(char* secret, unsigned char* key_data, char* iv) {
	char* str1 = NULL;
	
	/* extract first string from string sequence */
  str1 = strtok(secret, " ");
	strncpy((char*)key_data, str1, 64);
	key_data[64] = 0;
	
	// get the second
	str1 = strtok(NULL, " ");
	strncpy(iv, str1, 32);
	iv[32] = 0;    
}

void FreeDecryptedMemory() {
	if (decrypted_data != NULL) 
		free(decrypted_data);
}

unsigned char* DecryptFileX(char* private_key, char* shared_secret, char* filename, int* decrypted_size) {
	// "opaque" encryption, decryption ctx structures that libcrypto uses to record status of enc/dec operations
	EVP_CIPHER_CTX en, de;

	char* secret = NULL;
	char iv[33];
	unsigned char key_data[65];
	//unsigned char* decrypted = NULL;
	unsigned char* encrypted = NULL;
	BOOLEAN succeeded = FALSE;
	HANDLE hFile = NULL;
	int fsize;
	int key_data_len = 64; //must be 64 bytes
	unsigned long bytes_processed;
  
	secret = get_shared_secret(private_key, shared_secret);
	if (secret == NULL) return NULL;
	
	extract_shared_secret(secret, key_data, iv);
  
	//gen key and iv. init the cipher ctx object
	if (aes_init(key_data, key_data_len, NULL, iv, &en, &de)) {
		//printf("Couldn't initialize AES cipher\n");
		goto Cleanup;
	}

	hFile = CreateFile(filename,                // name of file
    GENERIC_WRITE|GENERIC_READ,  // open for writing/read
    FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,   // share all
    0,                   // new security
    OPEN_EXISTING,          // overwrite FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,  // normal file
    FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,
	  NULL
  );  // attr. template
    
	if (hFile == INVALID_HANDLE_VALUE) { 
    goto Cleanup;
  }
	
	fsize = GetFileSize(hFile, NULL);
	encrypted = (unsigned char*) malloc(fsize);
	succeeded = ReadFile(hFile, encrypted, fsize, &bytes_processed, NULL); 
	CloseHandle(hFile);
	
	if (!succeeded) 
		goto Cleanup;
	decrypted_data = (unsigned char *)aes_decrypt(&de, encrypted, &fsize);
	*decrypted_size = fsize;
	
Cleanup:
	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);
	if (encrypted != NULL) 
		free(encrypted);

	//the library ALWAYS needs to get unloaded or else there will be memory leak
	return decrypted_data;
}

int EncryptFileInit(char* private_key, char* shared_secret, char* filename) {
	char* secret = NULL;
	char iv[33];
	unsigned char key_data[65];
	BOOLEAN succeeded = FALSE;
	int key_data_len = 64; //must be 64 bytes
	int rc;

	secret = get_shared_secret(private_key, shared_secret);
	if (secret == NULL) { rc = 0; return; }
	
	extract_shared_secret(secret, key_data, iv);
  
	//gen key and iv. init the cipher ctx object
	if ((rc = aes_init(key_data, key_data_len, NULL, iv, &en, &de))) {
		goto Cleanup;
	}

	/* allows reusing of 'e' for multiple encryption cycles */
	rc = EVP_EncryptInit_ex(&en, NULL, NULL, NULL, NULL);

	hFile = CreateFile(filename,                // name of file
    GENERIC_WRITE|GENERIC_READ,  // open for writing/read
    FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,   // share all
    0,                   // new security
    CREATE_ALWAYS,          // overwrite FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,  // normal file
    FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,
	  NULL
  );  // attr. template
	
  if (hFile == NULL) rc = -1;
	CloseHandle(hFile);
	//open the file handle for append
	hFile = CreateFile(filename,                // name of file
    FILE_APPEND_DATA,  // open for writing/read
    FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,   // share all
    0,                   // new security
    OPEN_EXISTING,          // open of create
    FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,
	  NULL
  );  // attr. template
	
  if (hFile == NULL) rc = -2;
	return rc;
	
Cleanup:
	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);
	return;
}

int EncryptFileUpdate(unsigned char* data, unsigned long datasize) {
	int rc;

	if(!EVP_EncryptUpdate(&en, outbuf, &outlen, data, datasize))
    {
		/* Error */
		EVP_CIPHER_CTX_cleanup(&en);
		EVP_CIPHER_CTX_cleanup(&de);
        rc = -1;
		return;
    }
	
	WriteFile(hFile, outbuf, outlen, &bytesWritten, NULL);
	
	rc = bytesWritten;
	return rc;
}

int EncryptFileFinal() {
	int rc;
	if(!EVP_EncryptFinal_ex(&en, outbuf, &outlen)) {
		/* Error */
    EVP_CIPHER_CTX_cleanup(&en);
		EVP_CIPHER_CTX_cleanup(&de);
		rc = -1;
		return;
  }
  
  WriteFile(hFile, outbuf, outlen, &bytesWritten, NULL);
	CloseHandle(hFile);

	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);

	rc = bytesWritten;
	return rc;
}

int EncryptFileX(unsigned char* data, unsigned long datasize, char* private_key, char* shared_secret, char* filename) {
	// "opaque" encryption, decryption ctx structures that libcrypto uses to record status of enc/dec operations
	EVP_CIPHER_CTX en, de;

	char* secret = NULL;
	char iv[33];
	unsigned char key_data[65];
	//unsigned char* decrypted = NULL;
	unsigned char* encrypted = NULL;
	BOOLEAN succeeded = FALSE;
	HANDLE hFile = NULL;
	int dsize;
	int fsize = dsize = datasize;
	int key_data_len = 64; //must be 64 bytes
	unsigned long bytes_processed;
	
	secret = get_shared_secret(private_key, shared_secret);
	if (secret == NULL) return 0;
	
	extract_shared_secret(secret, key_data, iv);
  
	//gen key and iv. init the cipher ctx object
	if (aes_init(key_data, key_data_len, NULL, iv, &en, &de)) {
		goto Cleanup;
	}

  encrypted = aes_encrypt(&en, data, &fsize);
	
  //export the file
	hFile = CreateFile(filename,                // name of file
    GENERIC_WRITE|GENERIC_READ,  // open for writing/read
    FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,   // share all
    0,                   // new security
    CREATE_ALWAYS,          // overwrite FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,  // normal file
    FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,
	  NULL
  );  // attr. template
    
	if (hFile == INVALID_HANDLE_VALUE) { 
    goto Cleanup;
  }
	
	WriteFile(hFile, encrypted, fsize, &bytes_processed, NULL);	
	CloseHandle(hFile);
	
Cleanup:
	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);
	if (encrypted != NULL) 
		free(encrypted);

	//the library ALWAYS needs to get unloaded or else there will be memory leak
	return fsize;
}

int main(int argc, char **argv)
{
	/* "opaque" encryption, decryption ctx structures that libcrypto uses to record status of enc/dec operations */
	char* secret = NULL;
	unsigned char *key_data = NULL;
	unsigned char* decrypted;
	unsigned char* encrypted;
	int rc;

	char* iv = NULL;
	HANDLE hFile;
	int fsize;
	int key_data_len = 64, data_size; //, i;
	unsigned long bytes_processed;
  
	unsigned char* data = NULL;
	
	FILE* fp = NULL;
	FILE* fdone = NULL;

	goto test2;
	
  //TEST #1
	data = DecryptFileX((char*)private_key, (char*)shared_secret, "cred.enc", &data_size);

	fp = fopen("C:\\source\\bigfile.txt", "rb+");
	rc = EncryptFileInit((char*) private_key, (char*)shared_secret, "e-bigfile.dat");
	for (;;) {
		inlen = fread(inbuf, 1, 131072, fp);
        if(inlen <= 0) break;
		rc = EncryptFileUpdate(inbuf, inlen); 
	}
	rc = EncryptFileFinal();

	//fsize = EncryptFileX(encrypted, fsize, (char*) private_key, (char*)shared_secret, "e-bigfile.dat");
	
	data = DecryptFileX((char*)private_key, (char*)shared_secret, "e-bigfile.dat", &data_size);
	fdone = fopen("d-bigfile.txt", "wb");
	fwrite(data, 1, data_size, fdone);
	fclose(fdone);
	//-----------------------------------------------------------------------------------------------------------
test2:
	secret = get_shared_secret(private_key, shared_secret);
	
	if (secret == NULL) return -1;
	
	extract_shared_secret(secret, key_data, iv);
  
	/* gen key and iv. init the cipher ctx object */
	if (aes_init(key_data, key_data_len, NULL, iv, &en, &de)) {
		printf("Couldn't initialize AES cipher\n");
		return -1;
	}

	hFile = CreateFile("e-bigfile.dat",                // name of the write
    GENERIC_WRITE|GENERIC_READ,  // open for writing/read
    FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,   // share all
    0,                   // new security
    OPEN_EXISTING,          // overwrite FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,  // normal file
    FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,
	  NULL
  );  // attr. template
    
	if (hFile == INVALID_HANDLE_VALUE) { 
    //goto Cleanup;
  }
	
  fsize = GetFileSize(hFile, NULL);
	encrypted = (unsigned char*) malloc(fsize);
	ReadFile(hFile, encrypted, fsize, &bytes_processed, NULL); 
	CloseHandle(hFile);
	
	decrypted = (unsigned char *)aes_decrypt(&de, encrypted, &fsize);

	hFile = CreateFile("dd-bigfile.dat",                // name of the write
    GENERIC_WRITE|GENERIC_READ,  // open for writing/read
    FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,   // share all
    0,                   // new security
    CREATE_ALWAYS,          // overwrite FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,  // normal file
    FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,
	  NULL
  );  // attr. template
    
	WriteFile(hFile, decrypted, fsize, &bytes_processed, NULL);
	CloseHandle(hFile);

	free(encrypted);
  free(decrypted);

	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);

	return 0;
}
