#ifndef _S3FS_RC4_H_
#define _S3FS_RC4_H_

#include <openssl/rc4.h>

class RC4Encryption{
  static unsigned char * key_data;
  static int key_length;

public:
  static int s3fs_decrypt_rc4(int fd);
  static int s3fs_encrypt_rc4(int fd);
  static int s3fs_init_key(unsigned char *key_data);
};

#endif // _S3FS_RC4_H_
