#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include <openssl/sha.h>
#include <openssl/blowfish.h>
#include <openssl/evp.h>
#include "messages.h"
#include "b_messages.h"

#define FILE_HASH_SIZE 64

extern char *strdup(const char *str);

#ifndef SSL_CONNECT
#define SSL_CONNECT
struct ssl_connection {
	BIO *bio;
	SSL *ssl;
};

struct ssl_connection * connect_to(char *address, char *certpath, char *cacert, char *cert, char *privkey);
#endif

int op_LOGIN(BIO *bio, char *username, char *pword);
int unsigned_string_equals(unsigned char *s1, int l1, unsigned char *s2, int l2);
char * string_cat(int n, ...);
int get_char_buf(BIO* bio, const void *buf, int size);
int send_char_buf(BIO *bio, const void* buf, size_t size);
int get_c_message(BIO* bio, struct message_client *m);
int send_c_message(BIO *bio, struct message_client* m);
void ssl_error(char *message);
long size_of_file(char *filename);
int load_file(char *filename, const void *buf, int obj_size, int size);
int decrypt_encrypt_file(char *filein, char *fileout, unsigned char *key, int do_crypt);
char* decrypt_encrypt_buffer(char *inbuf, int inlen, int *len, unsigned char *key, int do_crypt);
int send_file(BIO *bio, char* filename);
int get_file(BIO* bio, char *filename, u_int file_perm, int filesize);
int send_string(BIO *bio,char *message);
int send_u_string(BIO *bio, unsigned char *s, int len);
int send_create_message(BIO *bio, enum message_c_ctrl ctrl, char *data1, char *data2, int data3, int data4);
char *get_str_message(BIO *bio);
unsigned char *sign_data(char *data, size_t len, EVP_PKEY* key, int *sig_len); 
int verify_signed_data(char *data, size_t data_len, unsigned char *orig_sig, size_t sig_len, EVP_PKEY *key);
unsigned char *digest_file(char* filename, int *md_len);
unsigned char *sha_hash(unsigned char* data, long len);
void print_hash(unsigned char* hash, int len);
unsigned char *create_v_key(char* data1, char *data2);
unsigned char *blowfish_enc(unsigned char *key, unsigned char *data, int size);
unsigned char *blowfish_dec(unsigned char *key, unsigned char* data, int size);
unsigned char *create_file_verification(unsigned char *key, char *filename, int *len);
