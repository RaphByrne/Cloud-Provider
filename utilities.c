#include "utilities.h"

int get_rand(int n)
{
	/*
	FILE *f = fopen("/dev/random", "r");
	if(f != NULL) {
		int *seed = 0;
		fread(seed, sizeof(int), 1, f);
		srandom(seed);
		
	}
	*/
	return random()%n;
}

int op_LOGIN(BIO *bio, char *username, char *pword)
{
	int result = 0;
	if(send_create_message(bio, LOGIN, username, pword, 0, 0) == 1) {
		char *message = get_str_message(bio);	
		if(message != NULL) {
			printf("Server response: %s\n",message);
			if(strcmp(message, "CONN_OK") != 0) {
				printf("VERIFICATION DENIED\n");
			} else
				result = 1;
			free(message);
		} else {
			printf("No reponse from server\n");
		}
	} else
		printf("Send Login error\n");
	return result;
}

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

unsigned char *sign_data(char *data, size_t len, EVP_PKEY* key, int *sig_len) 
{
	EVP_PKEY_CTX *ctx;
	ctx = EVP_PKEY_CTX_new(key, NULL);
	EVP_PKEY_sign_init(ctx);
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());

	EVP_PKEY_sign(ctx, NULL, sig_len, data, len); //determines the sig_len
	printf("Sig_len %d\n", *sig_len);
	unsigned char * sig = OPENSSL_malloc(*sig_len);
	if(EVP_PKEY_sign(ctx, sig, sig_len, data, len <= 0)) {
		ssl_error("PKEY SIGN");
		sig = NULL;
	}
	return sig;
}

int verify_signed_data(char *data, size_t data_len, unsigned char *orig_sig, size_t sig_len, EVP_PKEY *key)
{
	EVP_PKEY_CTX *ctx;
	ctx = EVP_PKEY_CTX_new(key, NULL);
	EVP_PKEY_verify_init(ctx);
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());

	return EVP_PKEY_verify(ctx, orig_sig, sig_len, data, data_len);
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

int decrypt_encrypt_file(char *filein, char *fileout, unsigned char *key, int do_crypt)
{
	FILE *in = fopen(filein, "r");
	if(in == NULL) {
		fprintf(stderr, "Could not open %s to encrypt/decrypt\n", filein);
		return -1;
	}
	FILE *out = fopen(fileout, "w");
	if(out == NULL) {
		fprintf(stderr, "Could not open %s to encrypt/decrypt\n",fileout);
		return -1;
	}
	unsigned char inbuf[1024];
	unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	int inlen, outlen;
	unsigned char iv[] = "0";
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, key, iv, do_crypt); //do_crypt 1 for enc, 0 for dec
	while((inlen = fread(inbuf, 1, 1024, in)) > 0) {
		if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) {
			fprintf(stderr, "Cipher Update error on %s\n",filein);
			ssl_error("Cipher update");
			return -2;
		}
		fwrite(outbuf, 1, outlen, out);
	}

	if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen)) {
		ssl_error("cipher final");
		return -2;
	}
	fwrite(outbuf, 1, outlen, out);
	fclose(in);
	fclose(out);
	return 1;
}

char* decrypt_encrypt_buffer(char *inbuf, int inlen, int *len, unsigned char *key, int do_crypt)
{
	unsigned char *outbuf = malloc(1024 + EVP_MAX_BLOCK_LENGTH);
	int outlen;
	unsigned char iv[] = "0";
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, key, iv, do_crypt); //do_crypt 1 for enc, 0 for dec
	if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) {
		fprintf(stderr, "Cipher Update on buffer\n");
		ssl_error("Cipher update");
		return NULL;
	}

	if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen)) {
		ssl_error("cipher final");
		return NULL;
	}
	
	*len = outlen;
	return outbuf;
}

int send_file(BIO *bio, char* filename)
{
	int result = 0;
	printf("opening file: %s\n",filename);
	FILE *f = fopen(filename,"r");
	if(f != NULL) {

		//check that the other guy can store our file
		char *response = calloc(BUFSIZ, sizeof(char));
		if(get_char_buf(bio, response, BUFSIZ) > 0) {
			if(strncmp(response, "FILE_OK", strlen(response)) == 0) {
				//send the file
				char *buf = calloc(BUFSIZ, sizeof(char));
				while(feof(f) == 0) {
					int num_bytes = fread(buf, sizeof(char), BUFSIZ, f);
					printf("sent %d bytes of %s\n",num_bytes, filename);
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



struct ssl_connection * connect_to(char *address, char *certpath, char *cacert, char *cert, char *privkey)
{
	struct ssl_connection *conn = calloc(1, sizeof *conn);
	//BIO *bio;
	//SSL *ssl;
	SSL_CTX *ctx = (SSL_CTX *)SSL_CTX_new(SSLv23_client_method());

	printf("LOADING CA CERT\n");
	//load our ca certificate
	if(SSL_CTX_load_verify_locations(ctx, string_cat(3,certpath,"/",cacert), NULL) == 0) 
	{
		printf("FAILING\n");
		ssl_error("Server cert load fail");
		exit(1);
	}

	printf("LOADING CLIENT CERT\n");
	//load our certificate used to send files
	if(SSL_CTX_use_certificate_file(ctx, string_cat(3,certpath,"/",cert), SSL_FILETYPE_PEM) < 1)
	{
		ssl_error("failed to load client cert");
		exit(1);
	}
	
	
	printf("LOADING PRIVATE KEY\n");
	//load our private key
	if(SSL_CTX_use_PrivateKey_file(ctx, string_cat(3,certpath,"/",privkey), SSL_FILETYPE_PEM) < 1)
	{
		ssl_error("failed to load private key");
		exit(1);
	}
	
	SSL_CTX_set_timeout(ctx, 5);

	conn->bio = BIO_new_ssl_connect(ctx);
	if(conn->bio == NULL)
	{
		ssl_error("bio creation fail");
		exit(1);
	}

	//set up connection
	BIO_get_ssl(conn->bio, &conn->ssl);
	SSL_set_mode(conn->ssl, SSL_MODE_AUTO_RETRY);
	SSL_set_verify(conn->ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	

	//client stuff goes here
	//set server hostname
	if(BIO_set_conn_hostname(conn->bio, address) <= 0)
	{
		printf("Address error\n");
		ssl_error("BIO connect error");
		exit(1);

	}
	printf("attempting to connect to %s\n",address);
	//test connection
	if(BIO_do_connect(conn->bio) <= 0)
	{
		printf("CONNECTION ERROR!?!?!?\n");
		ssl_error("BIO connect error");
		exit(1);
	}
	
	

	//verify the certificate
	if(BIO_do_handshake(conn->bio) > 0) {
		printf("HANDSHAKE SUCCESS\n");
		if(SSL_get_verify_result(conn->ssl) == X509_V_OK) {
			X509 *server_cert = SSL_get_peer_certificate(conn->ssl);
			if(server_cert == NULL) {
				printf("Didn't get a server certificate\n");
				return NULL;
			}
			return conn;
		} else
			printf("CANNOT VERIFY SERVER CERTIFICATE! SHUTTING DOWN!!!\n");
	} else
		printf("HANDSHAKE FAIL\n");
	return NULL; //FAILURE
}


