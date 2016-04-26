#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sstream>
#include <string>
#include <iostream>
#include <unistd.h>
#include <zlib.h>
#include <openssl/rc4.h>
#include "rc4.h"

using namespace std;

unsigned char * RC4Encryption::key_data = NULL;
int RC4Encryption::key_length = 0;

int RC4Encryption::s3fs_decrypt_rc4(int fd)
{
  cerr << "Decrypting..." << endl;
  RC4_KEY key;
  RC4_set_key(&key, key_length, key_data);
  int flencompr = lseek(fd, 0, SEEK_END);
  int flength = 0;
  unsigned char *fciphr;
  unsigned char *fplain;
  unsigned char *fcompr;
  fciphr = (unsigned char *) malloc(flencompr * sizeof(char));
  fplain = (unsigned char *) malloc(flencompr * 50 * sizeof(char));
  fcompr = (unsigned char *) malloc(flencompr * sizeof(char));
  pread(fd, fciphr, flencompr, 0);
  RC4(&key, flencompr, fciphr, fcompr);
  cerr << "Compressed file size: " << flencompr << endl;

  z_stream infstream;
  infstream.zalloc = Z_NULL;
  infstream.zfree = Z_NULL;
  infstream.opaque = Z_NULL;
  // setup "fcompr" as the input and "fplain" as the compressed output
  infstream.avail_in = flencompr; // size of input
  infstream.next_in = (Bytef *)fcompr; // input char array
  infstream.avail_out = (uInt)flencompr * 50; // size of output
  infstream.next_out = (Bytef *)fplain; // output char array

  // the actual DE-compression work.
  inflateInit(&infstream);
  inflate(&infstream, Z_NO_FLUSH);
  inflateEnd(&infstream);
  flength = infstream.total_out;
  cerr << "Uncompressed file size: " << flength << endl;

  // write back to file
  pwrite(fd, fplain, flength, 0);
  ftruncate(fd, flength);

  free(fplain);
  free(fciphr);
  free(fcompr);
  return 0;
}

int RC4Encryption::s3fs_encrypt_rc4(int fd)
{
  cerr << "Encrpyting..." << endl;
  RC4_KEY key;
  RC4_set_key(&key, key_length, key_data);
  int flength = lseek(fd, 0, SEEK_END);
  cerr << "Original file size: " << flength << endl;
  int flencompr = 0;
  unsigned char *fplain;
  unsigned char *fciphr;
  unsigned char *fcompr;
  fplain = (unsigned char *) malloc(flength * sizeof(char));
  fciphr = (unsigned char *) malloc(flength * sizeof(char));
  fcompr = (unsigned char *) malloc(flength * 40 * sizeof(char));
  pread(fd, fplain, flength, 0);

  // zlib struct
  z_stream defstream;
  defstream.zalloc = Z_NULL;
  defstream.zfree = Z_NULL;
  defstream.opaque = Z_NULL;
  // setup "fplain" as the input and "fcompr" as the compressed output
  defstream.avail_in = flength; // size of input, string + terminator
  defstream.next_in = (Bytef *)fplain; // input char array
  defstream.avail_out = (uInt)flength * 40; // size of output
  defstream.next_out = (Bytef *)fcompr; // output char array
  // the actual compression work.
  deflateInit(&defstream, Z_BEST_COMPRESSION);
  deflate(&defstream, Z_FINISH);
  deflateEnd(&defstream);
  flencompr = defstream.total_out;
  cerr << "Compressed file size: " << flencompr << endl;

  RC4(&key, flencompr, fcompr, fciphr);
  pwrite(fd, fciphr, flencompr, 0);
  ftruncate(fd, flencompr);
  cerr << "Encrypted and compressed file size: " << flencompr << endl;

  free(fplain);
  free(fciphr);
  free(fcompr);
  return 0;
}

int RC4Encryption::s3fs_init_key(unsigned char *key)
{
  key_length = (int) strlen((char *)key);
  key_data = (unsigned char *) malloc(key_length * sizeof(char));
  strcpy((char *)key_data, (char *)key);

  return 0;
}
