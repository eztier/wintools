#include "program.h"

void test_1(const char* private_key, const char* shared_secret) {
  FILE* fdone = NULL;
  unsigned char* data = NULL;
  int rc, data_size;

  /*
  // Buffering encrypt.
  rc = EncryptFileInit((char*)private_key, (char*)shared_secret, "resources/security-enc-copy.xml");
  FILE* f = fopen("resources/security-plain.xml", "rb+");
  
  for (;;) {
    inlen = fread(inbuf, 1, 131072, f);
    if (inlen <= 0) break;
    rc = EncryptFileUpdate(inbuf, inlen);
  }
  
  rc = EncryptFileFinal();
  fclose(f);
  */

  // One shot read.
  unsigned char* inbytes;
  long fsize;
  fsize = read_all("resources/security-plain.xml", &inbytes);
  
  long fsize2 = EncryptFileX(inbytes, fsize, (char*) private_key, (char*)shared_secret, "resources/security-enc-copy.xml");
  
  // Test what was encrypted.
  data = DecryptFileX((char*)private_key, (char*)shared_secret, "resources/security-enc-copy.xml", &data_size);
  fdone = fopen("resources/security-plain-copy.xml", "wb");
  fwrite(data, 1, data_size, fdone);
  fclose(fdone);
}

void test_2(const char* private_key, const char* shared_secret, const char* encrypted_file) {
  /* "opaque" encryption, decryption ctx structures that libcrypto uses to record status of enc/dec operations */
  EVP_CIPHER_CTX en, de;

  char* secret = NULL;
  char* iv = malloc(33);
  unsigned char* key_data = malloc(65);
  unsigned char* decrypted;
  unsigned char* encrypted;
  int fsize;
  int key_data_len = 64;
  unsigned long bytes_processed;

  secret = get_shared_secret(private_key, shared_secret);

  printf("secret: %s\n", secret);
  
  if (secret == NULL) {
    fprintf(stderr, "Could not get secret.  Do these files exist? %s and %s\n", private_key, shared_secret);
    return -1;
  }

  extract_shared_secret(secret, &key_data, &iv);

  printf("key_data: %s\n\n iv: %s\n", key_data, iv);

  /* gen key and iv. init the cipher ctx object */
  if (aes_init(key_data, key_data_len, NULL, iv, &en, &de)) {
    printf("Couldn't initialize AES cipher\n");
    return -1;
  }


#ifdef _WIN32
  HANDLE hFile;
  hFile = CreateFile(encrypted_file,
    GENERIC_WRITE | GENERIC_READ,
    FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
    0,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
    NULL
  );

  if (hFile == INVALID_HANDLE_VALUE) {
    //
  }

  fsize = GetFileSize(hFile, NULL);
  encrypted = (unsigned char*)malloc(fsize);
  ReadFile(hFile, encrypted, fsize, &bytes_processed, NULL);
  CloseHandle(hFile);

  decrypted = (unsigned char *)aes_decrypt(&de, encrypted, &fsize);

  hFile = CreateFile("dd-bigfile.dat",
    GENERIC_WRITE | GENERIC_READ,
    FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
    0,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
    NULL
  );
  WriteFile(hFile, decrypted, fsize, &bytes_processed, NULL);
  CloseHandle(hFile);
#else
  printf("Reading encrypted file.\n%s\n\n", encrypted_file);
  fsize = read_all(encrypted_file, &encrypted);
  printf("fsize %d\n", fsize);

  int out_len;
  unsigned char* decoded = base64_decode(encrypted, fsize, &out_len);

  decrypted = (unsigned char *)aes_decrypt(&de, decoded, &out_len);

  printf("%s\n%d\n", decrypted, out_len);
  
  FILE* f;
  f = fopen("resources/security-plain.xml", "w");
  fwrite(decrypted, 1, out_len, f);
  fclose(f);
#endif

  free(encrypted);
  free(decrypted);

  EVP_CIPHER_CTX_cleanup(&en);
  EVP_CIPHER_CTX_cleanup(&de);

  if (iv != NULL) 
    free(iv);

  if (key_data != NULL)
    free(key_data);
}

void test_3(char* private_key, char* shared_secret, char* encrypted_file) {
  unsigned char* encrypted;

  long fsize = read_all(encrypted_file, &encrypted);

  int out_len;
  unsigned char* decoded = base64_decode(encrypted, fsize, &out_len);

  char* outfile = "resources/security-enc-decoded.xml";

  FILE* f;
  f = fopen(outfile, "w");
  fwrite(decoded, 1, out_len, f);
  fclose(f);

  int sz = 0;
  unsigned char* r = DecryptFileX(private_key, shared_secret, outfile, &sz);
  printf("%s\n", r);
}

int main(int argc, char **argv) {
  #ifdef _WIN32
  const char* shared_secret = "resources\\key-final.enc";
  const char* private_key = "resources\\privatekey.pem";
  const char* encrypted_file = "resources\\security-enc.xml";

  // test_1(private_key, shared_secret);
  test_2(private_key, shared_secret, encrypted_file);
  test_3(private_key, shared_secret, encrypted_file);
	#else
  const char* shared_secret = "resources/key-final.enc";
  const char* private_key = "resources/privatekey.pem";
  const char* encrypted_file = "resources/security-enc.xml";

  test_1(private_key, shared_secret);
  // test_2(private_key, shared_secret, encrypted_file);
  // test_3(private_key, shared_secret, encrypted_file);	
  #endif
  return 0;
}
