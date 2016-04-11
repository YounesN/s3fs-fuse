#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sstream>
#include <string>
#include <iostream>
#include <unistd.h>
#include <openssl/rc4.h>
#include "rc4.h"

using namespace std;

unsigned char * RC4Encryption::key_data = NULL;
int RC4Encryption::key_length = 0;

int RC4Encryption::s3fs_decrypt_rc4(int fd)
{
  RC4_KEY key;
  RC4_set_key(&key, key_length, key_data);
  int flength = lseek(fd, 0, SEEK_END);
  unsigned char *fciphr;
  unsigned char *fplain;
  fciphr = (unsigned char *) calloc(flength, sizeof(char));
  fplain = (unsigned char *) calloc(flength, sizeof(char));
  pread(fd, fciphr, flength, 0);
  RC4(&key, flength, fciphr, fplain);
  pwrite(fd, fplain, flength, 0);
  ftruncate(fd, flength);

  free(fplain);
  free(fciphr);
  return 0;
}

int RC4Encryption::s3fs_encrypt_rc4(int fd)
{
  RC4_KEY key;
  RC4_set_key(&key, key_length, key_data);
  int flength = lseek(fd, 0, SEEK_END);
  unsigned char *fplain;
  unsigned char *fciphr;
  fplain = (unsigned char *) calloc(flength, sizeof(char));
  fciphr = (unsigned char *) calloc(flength, sizeof(char));
  pread(fd, fplain, flength, 0);
  RC4(&key, flength, fplain, fciphr);
  pwrite(fd, fciphr, flength, 0);
  ftruncate(fd, flength);

  free(fplain);
  free(fciphr);
  return 0;
}

int RC4Encryption::s3fs_init_key(unsigned char *key)
{
  key_length = (int) strlen((char *)key);
  key_data = (unsigned char *) calloc(key_length, sizeof(char));
  strcpy((char *)key_data, (char *)key);

  return 0;
}
