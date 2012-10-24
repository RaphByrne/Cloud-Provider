#include "utilities.h"



int unsigned_string_equals(unsigned char *s1, int l1, unsigned char *s2, int l2)
{
	if(l1 != l2)
		return 0;
	for(int i = 0; (i < l1) && (i < l2); i++) { //TODO possible buffer overflow problem
		if(s1[i] != s2[i])
			return 0;
	}
	return 1;
}

//testing function for printf 160bit hashes
void print_hash(unsigned char* hash, int len)
{
	char *print_out = calloc(20, sizeof(char));
	memcpy(print_out, hash, 20);
	print_out[19] = '\0';
	printf("Hash: %s\n", print_out);
	free(print_out);
}

unsigned char *sha_hash(unsigned char* data, long len)
{
	printf("Computing sha1 hash of %s\n",data);
	unsigned char* out = calloc(160, sizeof(unsigned char));
	SHA1(data, len, out);
	print_hash(out, len);
	return out;
}

unsigned char *create_v_key(char* data1, char *data2)
{
	char *tmp = string_cat(2,data1,data2); //TODO XOR these instead?
	unsigned char* key = sha_hash((unsigned char *)tmp, (long)strlen(tmp));
	free(tmp);
	return key;
}

#define B_KEYSIZE 160 //set for 160 bit keys
#define MAX_PAD_LEN 12

unsigned char *blowfish_enc(unsigned char *key, unsigned char *data, int size)
{
	unsigned char* out = malloc(size);
	int outlen;
	int tmplen;
	unsigned char iv[] = {0}; //TODO maybe not this?
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, EVP_bf_ecb(), NULL, key, iv);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	
	EVP_EncryptUpdate(&ctx, out, &outlen, data, size);

	if(!EVP_EncryptFinal_ex(&ctx, out + outlen, &tmplen)) {
		ssl_error("Didn't do encrypt final");
	}
	outlen += tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);

/*
	BF_KEY bfkey;
	BF_set_key(&bfkey, B_KEYSIZE, key);
	int num = 0;
	BF_cfb64_encrypt(data, out, size, &bfkey, &iv, &num, BF_ENCRYPT);
*/
	return out;
}

unsigned char *blowfish_dec(unsigned char *key, unsigned char* data, int size)
{
	printf("Blowfish Dec: decrypting into buffer of %d bytes\n",size);
	unsigned char* out = malloc(size);
	int outlen;
	int tmplen;
	unsigned char iv[] = {0}; //TODO maybe not this?
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_bf_ecb(), NULL, key, iv);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	
	EVP_DecryptUpdate(&ctx, out, &outlen, data, size);

	if(!EVP_DecryptFinal_ex(&ctx, out + outlen, &tmplen)) {
		ssl_error("Didn't do decrypt final");
	}
	outlen += tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	printf("Blowfish Dec: decrypted size %d\n",outlen);
/*	
	BF_KEY bfkey;
	BF_set_key(&bfkey, B_KEYSIZE,key);
	int num = 0;
	BF_cfb64_encrypt(data, out, size, &bfkey, &iv, &num, BF_DECRYPT);
*/
	return out;
}

int send_string(BIO *bio, char* message)
{
	printf("Sending %s\n", message);
	int result = send_char_buf(bio, message, strlen(message) + 1);
	return result;
}

int send_u_string(BIO *bio, unsigned char* s, int len)
{
	printf("Sending u_string: ");
	print_hash(s, len);
	return send_char_buf(bio, s, len);
}

//len is length of return result
unsigned char *digest_file(char* filename, int *md_len)
{
	printf("Digesting file %s\n", filename);
	FILE *f = fopen(filename, "r");
	if(f != NULL) {
		EVP_MD_CTX *ctx;
		unsigned char *md_value = calloc(EVP_MAX_MD_SIZE, sizeof(unsigned char));
		ctx = EVP_MD_CTX_create();
		EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
		while(feof(f) == 0) {
			char *buf = calloc(FILE_HASH_SIZE, sizeof(char));
			int amount = fread(buf, sizeof(char), FILE_HASH_SIZE, f);
			EVP_DigestUpdate(ctx, buf, amount);
			free(buf);
		}
		fclose(f);
		EVP_DigestFinal_ex(ctx, md_value, md_len);
		EVP_MD_CTX_destroy(ctx);
		//resize the md_value
		if(*md_len < EVP_MAX_MD_SIZE)	
			md_value = realloc(md_value, *md_len);
		print_hash(md_value, *md_len);
		return md_value;
	} else {
		fprintf(stderr, "Could not create digest of %s: %s\n",filename, strerror(errno));
		return NULL;
	}
}

//length of verification will be stored in len
unsigned char *create_file_verification(unsigned char *key, char *filename, int *len)
{
	printf("Creating file verification for %s\n", filename);
	unsigned char *digest = digest_file(filename, len);
	unsigned char *out = NULL;
	printf("%s DIGEST: ", filename);
	print_hash(digest, *len);
	if(digest != NULL) {
		out = blowfish_enc(key, digest, *len);
		printf("Enc Digest: ");
		print_hash(out, *len);
		free(digest);
	}
	return out;
}

long size_of_file(char *filename)
{
	struct stat s;
	if(stat(filename, &s) == -1) {
		perror("stat");
		return -1;
	} else {
		return s.st_size;
	}
}

//loads a file into a buffer. Only good for short files. Returns the amount of bytes read into buffer
int load_file(char *filename, const void *buf, int obj_size, int size)
{
	FILE *f = fopen(filename, "r");
	if(f != NULL) {
		int result = fread(buf, obj_size, size, f);
		fclose(f);
		printf("Load file put %d bytes into buffer\n", result);
		return result;
	} else
		return 0;
}

int send_file(BIO *bio, char* filename)
{
	int result = 0;
	printf("opening file: %s\n",filename);
	FILE *f = fopen(filename,"r");
	if(f != NULL) {
		//strip off local directories
		if(strrchr(filename, '/') != NULL)
			filename = strrchr(filename, '/')+1;

		//check that the other guy can store our file
		char *response = calloc(BUFSIZ, sizeof(char));
		if(get_char_buf(bio, response, BUFSIZ) > 0) {
			if(strncmp(response, "FILE_OK", strlen(response)) == 0) {
				//send the file
				char *buf = calloc(BUFSIZ, sizeof(char));
				while(feof(f) == 0) {
					int num_bytes = fread(buf, sizeof(char), BUFSIZ, f);
					printf("send %d bytes of %s\n",num_bytes, filename);
					if(BIO_write(bio, buf, num_bytes) <= 0)
						break;
					memset(buf, 0, BUFSIZ);
				}
				send_string(bio, "FILE_DONE"); //send message to say the file is finished
				free(buf);
				fclose(f);
				result = 1;
			} else
				printf("FILE SEND ERROR: %s\n", response);
		} else 
			printf("DID NOT SEND %s: Couldn't confirm file receiver\n", filename);
		free(response);
		
	} else {
		printf("problem opening file %s\n",filename);
		perror("");
	}
	return result;
}

//gets a file being send to us, does not request it. ABORTS IF FILESIZE EXCEEDS EXPECTED FILESIZE
int get_file(BIO* bio, char *filename, u_int file_perm, int filesize)
{
	int success = 0;
	printf("Getting to file %s\n", filename);
	FILE *f = fopen(filename, "w");
	if(f != NULL) {
		send_string(bio, "FILE_OK"); // say that we're ready to receive the file
		printf("Writing to %s\n", filename);
		char *buf = calloc(BUFSIZ, sizeof(char));
		int num_bytes = 0;
		int total = 0;
		while((num_bytes = BIO_read(bio, buf, BUFSIZ)) > 0) {
			if(strncmp(buf, "FILE_DONE", strlen("FILE_DONE")) == 0) { //TODO what if they send a file containing this text!
				success = 1;
				break;
			}	
			total += num_bytes;
			if(total <= filesize) {
				printf("writing %d bytes to %s\n",num_bytes,filename);
				fwrite(buf, sizeof(char), num_bytes, f);
			} else {
				printf("ABORTING FILEGET. EXPECTED SIZE: %d, CURRENT SIZE %d\n", filesize, total);
				success = -2;
				break; //don't keep getting stuff
			}
		}
		if(total < filesize) {
			printf("DIDN'T GET WHOLE FILE. EXPECTED SIZE: %d, CURRENT SIZE %d\n", filesize, total);
			success = -2;
		}
		if(success > 0)
			fchmod(fileno(f), file_perm);
		fclose(f);
		if(success <= 0)
			remove(filename);
		free(buf);
	} else {	
		printf("problem opening file %s\n",filename);
		perror("");
		success = -1;
	}
	return success;
}

void ssl_error(char *message)
{
	int err_code = ERR_get_error();
	printf("%s: Function: %s  :  %s\n",message,ERR_func_error_string(err_code),ERR_reason_error_string(err_code));
}

//concatenates 'n' strings together
char * string_cat(int n, ...)
{
	va_list args;

	va_start(args, n);
	char *out = calloc(n*BUFSIZ, sizeof(char));
	for(int i = 0; i < n; i++) {
		char *next = strdup(va_arg(args, char *));
		strncat(out,next,BUFSIZ);
	}
	va_end(args);
	return out;
}

char *get_str_message(BIO *bio)
{
	printf("Getting string message\n");
	char *buf = malloc(BUFSIZ);
	if(get_char_buf(bio, buf, BUFSIZ) <= 0) {
		//free(buf);
		buf = NULL;
	}
	if(buf != NULL)
		fprintf(stderr, "got message %s\n", buf);
	return buf;
}

int get_char_buf(BIO* bio, const void *buf, int size)
{
	int messlen = BIO_read(bio, buf, size);
	if(messlen < 0) {
		ssl_error("Error while getting message\n");
	}
	printf("GOT %d bytes from stream\n",messlen);
	return messlen;
}

int send_char_buf(BIO *bio, const void* buf, size_t size)
{
	//TODO more checks possibly
	int result = 1;
	int amount = 0;
	if((amount = BIO_write(bio, buf, size)) < 0) {
		result = -1;
		ssl_error("Problem sending char buf\n");
	}
	printf("send_char_buf: sent %d bytes\n",amount);
	if(amount < size)
		printf("Didn't send whole buf. Only sent %d\n",amount);
	return result;
}


//read a client message from the stream
int get_c_message(BIO* bio, struct message_client *m)
{
	int result = 0;
	char *buf = malloc(BUFSIZ*sizeof(char));
	result = get_char_buf(bio, buf, BUFSIZ);
	if(result > 0) {	
		XDR xdr;
		xdrmem_create(&xdr, buf, BUFSIZ, XDR_DECODE);
		if(!xdr_message_client(&xdr, m)) { 
			perror("COULD NOT LOAD MESSAGE FROM BUF\n");
			result = -1;
		}
		message_print_c(m);
		xdr_destroy(&xdr);
		free(buf);
	}
	return result;
}


int send_c_message(BIO *bio, struct message_client* m)
{
	printf("Preparing to send message to server:\n");
	message_print_c(m);
	char *buf = calloc(BUFSIZ, sizeof(char));
	XDR xdr;
	xdrmem_create(&xdr, buf, BUFSIZ, XDR_ENCODE);
	if(!xdr_message_client(&xdr, m)) {
		perror("could not encode message\n");
		return -1;
	}
	int result = send_char_buf(bio, buf, BUFSIZ);
	xdr_destroy(&xdr);
	free(buf);
	return result;
}

int send_create_message(BIO *bio, enum message_c_ctrl ctrl, char *data1, char *data2, int data3, int data4)
{
	struct message_client *m = message_create(ctrl, strdup(data1), strdup(data2), data3, data4);
	int result = send_c_message(bio, m);
	xdr_free((xdrproc_t) xdr_message_client, (char *)m);
	return result;
}
