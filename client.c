#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <unistd.h>
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
#include "messages.h"
#include "utilities.h"

#define	OPTLIST	""
#define CERTPATH "certs"
#define FILEPATH "files"
#define TMPPATH "tmp"

extern char *strdup(const char *str);
//extern int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);

char *argv0 = NULL;


void set_up_SSL(SSL_CTX *ctx, SSL* ssl, BIO* bio, char * username);
int op_REGISTER(BIO *bio, char *username, char *pword);
void op_ADD(BIO *bio, int num_files, char** files, mode_t perms, unsigned char* key);
int op_LOGIN(BIO *bio, char *username, char* pword);
void op_FETCH(BIO *bio, int num_files, char** files, unsigned char *key);
void op_DELETE(BIO *bio, int num_files, char **files);
void op_UPDATE(BIO *bio, int num_files, char **files, mode_t perms, unsigned char* key);
void op_LIST(BIO *bio);
void send_verification(BIO *bio, char *filename, unsigned char *key);
void op_VERIFY(BIO *bio, int num_files, char **files, unsigned char* key);
int verify_remote_file(BIO *bio, char *filename, unsigned char *key);
void op_B_QUERY(BIO *bio);

static void usage(int status)
{
	fprintf(stderr, "Usage: %s SERVER_ADDRESS OPERATION <FILES>\n", argv0);
	fprintf(stderr, "Where:\n \tSERVER_ADDRESS is the address of the bank or provider\n\tOPERATION for Provider: ADD, DELETE, REGISTER, UPDATE, FETCH, LIST, VERIFY\n\tOPERATION for Bank: QUERY, REGISTER\n\t\tIf REGISTER <FILES> should be your desired USERNAME PASSWORD\n\t\tOtherwise <FILES> is one or more files to perform the desired operation on\n\n\tYou will be prompted for your username and password when contacting the server when not REIGSTER\n");

	exit(status);
}

void init_SSL() 
{
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
}

int test_privkey(char *username)
{
	char *keyname = string_cat(4,CERTPATH,"/",username,"-key.pem");
	FILE *f = fopen(keyname, "r");
	if(f == NULL)
		return -1;
	int result = 1;
	EVP_PKEY *key = PEM_read_PrivateKey(f, NULL, 0, "");
	if(key != NULL) //if we can open this with a blank password then reject it
		result = 0;
	fclose(f);
	free(keyname);
	return result;
}


int main(int argc, char **argv) {	
	
	init_SSL();

	argv0	= (argv0 = strrchr(argv[0],'/')) ? argv0+1 : argv[0];
	opterr	= 0;

	int opt;

	while((opt = getopt(argc, argv, OPTLIST)) != -1) {
		switch (opt) {
			
			default : fprintf(stderr,"%s : illegal option -%c\n", argv0,optopt);
				argc = -1;
				break;
		}
	}
	argv += optind;
	argc -= optind;
	//  CHECK THAT ALL PROVIDED ARGUMENTS WERE VALID
	if(argc < 2)
		usage(1);
	
	//get the inputs
	char *conn_string = argv[0];

	char *operation = argv[1];
	enum message_c_ctrl ctrl = string_to_ctrl(operation); //TODO check this
	printf("Got operation: %s\n",operation);
	printf("Doing: %s\n", ctrl_to_string(ctrl));	
	
	argv += 2;
	argc -= 2;
	char **files = argv;
	int num_files = argc;


	struct ssl_connection *conn = NULL;

	if((conn = connect_to(conn_string, CERTPATH, "ca-cert.pem", "client.pem", "client-key.pem")) != NULL) {
		BIO *bio = conn->bio;
		if(bio == NULL) {
			printf("WTF\n");
			exit(1);
		}
		if(ctrl == REGISTER) {
			printf("Registering\n");
			if(op_REGISTER(bio, argv[0], argv[1]) > 0) {
				printf("REGISTRY SUCCESS\n");
			} else {
				printf("REGISTRY FAIL\n");
			}
		} else { 
			printf("Please enter your cloud-provider username: ");
			char *username = malloc(100); //TODO not safe? might overflow this buffer
			scanf("%s",username);
			char *tmp = getpass("Enter Password:");
			char *pword = strdup(tmp);
			if(op_LOGIN(bio, username, pword)) {
				unsigned char* key = create_v_key(username, pword);
				
				memset(pword, 0, strlen(pword)); //0 our password buffer
				free(pword);
				switch(ctrl) {
					case ADD:
						op_ADD(bio, num_files, files,  S_IRUSR|S_IWUSR, key);
						break;
					case FETCH:
						op_FETCH(bio, num_files, files, key);
						break;
					case DELETE:
						op_DELETE(bio, num_files, files);
						break;
					case UPDATE:
						op_UPDATE(bio, num_files, files, S_IRUSR|S_IWUSR, key);
						break;
					case LIST:
						op_LIST(bio);
						break;
					case VERIFY:
						op_VERIFY(bio, num_files, files, key);
						break;
					case B_QUERY:
						op_B_QUERY(bio);
						break;
					default : //TODO should check this before making connection
						printf("Unknown command\n");
						break;
				}
			} else
				printf("COULD NOT VERIFY OURSELVES WITH SERVER\n");
		}
		BIO_free_all(bio);
	}
	//close the connection

	//free the CTX

	return 0;
}

int op_REGISTER(BIO *bio, char *username, char *pword)
{
	int result = -1;
	if(send_create_message(bio, REGISTER, username, pword, 0, 0) == 1) {
		char *message = calloc(BUFSIZ, sizeof(char));
		if(BIO_read(bio, message, BUFSIZ) <= 0) {
			ssl_error("could not confirm registration");
		} else {
			if(strcmp(message, "REG_SUCCESS") != 0) {
				printf("VERIFICATION DENIED: %s\n", message);
			} else
				result = 1;
		}
		free(message);
	}
	return result;
}


void send_verification(BIO *bio, char *filename, unsigned char *key)
{
	int len;
	unsigned char *v = create_file_verification(key, filename, &len); //TODO not entirely sure that this is the same every time
	fprintf(stderr, "Sending file verification\n");
	if(v != NULL) {
		send_u_string(bio, v, len);
		send_string(bio, "FILE_DONE"); //pretend that we're sending a whole file
	} else
		printf("Could not send verification, NULL ver string\n");
}

struct trans_tok * get_cheque(char *bank_add, char *username, char *pword, int value)
{
	struct ssl_connection *conn = NULL;
	if((conn = connect_to(bank_add, CERTPATH, "ca-cert.pem", "client.pem", "client-key.pem")) != NULL) {
		BIO *bio = conn->bio;
		struct trans_tok *t = NULL;
		if(op_LOGIN(bio, username, pword)) {
			memset(pword, 0, strlen(pword));
			send_create_message(bio, B_WITHDRAW, "", "", 0, 0);
			send_create_trans_req(bio, username, value);
			char *res = get_str_message(bio);
			if(res != NULL) {
				if(strncmp(res, "TRANS_OK", strlen("TRANS_OK")) == 0) {
					t = calloc(1, sizeof(*t));
					if(get_trans_tok(bio, t) <= 0) {
						t = NULL;
						free(t);
					}
				} else {
					printf("TRANS FAIL: %s\n",res);
				}
			} else
				printf("No response from bank to WITHDRAW req\n");
		} else
			printf("couldn't verify ourselves with bank at %s\n", bank_add);
		BIO_free_all(bio);
		return t;
	} else {
		printf("couldn't connect to %s\n", bank_add);
	}
	return NULL;
}

struct trans_tok * contact_bank(char *bank_add, int value)
{
	printf("Please enter your banking username: ");
	char *username = malloc(100); //TODO not safe? might overflow this buffer
	scanf("%s",username);
	char *pword = getpass("Please enter your banking password: ");
	struct trans_tok *t = get_cheque(bank_add, username, pword, value);
	free(username);
	return t;
}

//bio is the provider BIO
int send_payment(BIO *bio, char *bank_add, long filesize)
{
	float fvalue = (filesize/(1024*1024)); //TODO convert to megabytes properly. Not handling 1.0 MB case
	int value = (int)(fvalue + 1);
	printf("Trying to get %d fluffy bucks from bank\n", value);
	struct trans_tok *t = contact_bank(bank_add, value);
	if(t != NULL) {
		printf("Withdrew from bank\n");
		print_trans_tok(t);
		send_string(bio, "SENDING_PAYMENT");
		send_trans_tok(bio, t);
		return 1;
	} else {
		send_string(bio, "PAYMENT_FAIL");
		printf("Withdraw refused\n");
		return -1;
	}
}

void op_ADD(BIO *bio, int num_files, char** files, mode_t perms, unsigned char *key) 
{
	for(int i = 0; i < num_files; i++) {
		char *filename = files[i];
		char *tmpname = string_cat(3,TMPPATH,"/",filename);
		decrypt_encrypt_file(filename, tmpname, key, 1); //encrypt the file

		long filesize = size_of_file(tmpname);
		send_create_message(bio, ADD, filename, "", perms, filesize);
		
		//get the response
		char *res = get_str_message(bio);
		if(res != NULL) {
			if(strncmp(res, "FILE_OK", strlen("FILE_OK")) == 0) {
				//get and send the money
				printf("Please enter address of cloud-bank: ");
				char *bank_add = malloc(100); //TODO not safe? might overflow this buffer
				scanf("%s",bank_add);
				if(send_payment(bio, bank_add, filesize)) {
					if(send_file(bio, tmpname))
						send_verification(bio, tmpname, key);
				}
			} else
				printf("FILE ADD ERROR ON %s: %s\n", tmpname, res);
			free(res);
		}
		remove(tmpname);
	 }
}

void op_FETCH(BIO *bio, int num_files, char** files, unsigned char *key)
{
	for(int i = 0; i < num_files; i++) {
		char * filename = files[i];	

		send_create_message(bio, FETCH, filename, "", 0, 0);
		//need to wait for ok first. It has to check whether the file currently exists
		struct message_client *m = calloc(1, sizeof(*m));
		get_c_message(bio, m);
		if(m->ctrl == FETCH) {
			if(verify_remote_file(bio, filename, key)) {
				char *tmpname = string_cat(3,TMPPATH,"/",filename);
				get_file(bio, tmpname, m->file_perm, m->file_size);
				
				char *store_name = string_cat(3,FILEPATH,"/",m->name);
				decrypt_encrypt_file(tmpname, store_name, key, 0); //decrypt the file
				free(store_name);
				printf("Remote file %s fetched to %s\n",m->name, filename);
				remove(tmpname);
			} else
				printf("Could not verify %s\n", filename);
		} else
			printf("Couldn't get %s: %s\n", filename, m->name);
		free(m);
	}
}

void op_DELETE(BIO *bio, int num_files, char **files)
{
	for(int i = 0; i < num_files; i++) {
		char * filename = files[i];
		if(send_create_message(bio, DELETE, filename, "", 0, 0) == 1) {
			char *message = get_str_message(bio);
			if(message != NULL) {
				if(strncmp(message, "DELETE_OK", strlen("DELETE_OK")) == 0)
					printf("Deleted remote copy of %s\n", filename);
				else
					printf("Deletion problem: %s\n", message);
			} else
				printf("No response from server\n");
		} else 
			printf("Message send error\n");
	}
}

void op_LIST(BIO *bio)
{
	printf("User File List:\n");
	if(send_create_message(bio, LIST, "", "", 0, 0) == 1) {
		struct message_client *m = calloc(1,sizeof(*m));
		while(get_c_message(bio, m) > 0) {
			if(strncmp(m->pword, "DONE", strlen("DONE")) != 0)
				printf("%s\n",m->name);
			else 
				break;
		}
	} else
		printf("Message send error\n");
}

int compare_hashes(unsigned char *key, unsigned char *enc_hash, int enc_len, unsigned char *p_hash, int p_len)
{
	unsigned char *hash = blowfish_dec(key, enc_hash, enc_len);
	printf("ENC_HASH: ");
	print_hash(enc_hash, enc_len);
	printf("DEC_HASH: ");
	print_hash(hash, enc_len);
	printf("P_HASH: ");
	print_hash(p_hash, p_len);
	return unsigned_string_equals(hash, enc_len, p_hash, p_len);
}

int verify_remote_file(BIO *bio, char *filename, unsigned char *key)
{
	int result = 0;
	printf("Verifying %s\n",filename);
	if(send_create_message(bio, VERIFY, filename, "", 0, 0) == 1) {
		char *response = get_str_message(bio);
		if(strncmp(response, "VERIFY_FILE_EXISTS", strlen("VERIFY_FILE_EXISTS")) == 0) {
			unsigned char *enc_hash = calloc(FILE_HASH_SIZE, sizeof(unsigned char));
			int enc_len = get_char_buf(bio, enc_hash, BUFSIZ);
			
			unsigned char *p_hash = calloc(FILE_HASH_SIZE, sizeof(unsigned char));
			int p_len = get_char_buf(bio, p_hash, FILE_HASH_SIZE);
			
			if((enc_len > 0) && (p_len > 0)) { //TODO can check that sizes are smaller than expect hash size (aka 160bits)
				result = compare_hashes(key, enc_hash, enc_len, p_hash, p_len);
			} else
				printf("Didn't get both hashes. ENC_LEN: %d, P_LEN: %d\n",enc_len, p_len);
			free(enc_hash);
			free(p_hash);
		} else
			printf("No verification file found for %s\n",filename);
		free(response);
	} else 
		printf("Message send error\n");
	return result;
}

void op_VERIFY(BIO *bio, int num_files, char **files, unsigned char* key)
{
	for(int i = 0; i < num_files; i++) {
		char * filename = files[i];
		if(verify_remote_file(bio, filename, key))
			printf("%s VERIFIED\n",filename);
		else
			printf("%s NOT VERIFIED\n", filename);
	}
}

void op_UPDATE(BIO *bio, int num_files, char **files, mode_t perms, unsigned char* key)
{
	//TODO
	op_DELETE(bio, num_files, files);
	op_ADD(bio, num_files, files, perms, key);
}

void op_B_QUERY(BIO *bio)
{	
	if(send_create_message(bio, B_QUERY, "", "", 0, 0) == 1) {
		//receive our balance
		char *message = get_str_message(bio);
		if(message != NULL) {
			if(strncmp(message, "QUERY_OK", strlen("QUERY_OK")) == 0) {
				char *bal = get_str_message(bio);
				printf("Your Balance is %s fluffy bucks\n",bal);
				free(bal);
			} else {
				printf("Problem from bank: %s\n",message);
			}
			free(message);
		} else
			printf("No response from bank\n");
		//TODO receive our active transactions
	} else {
		printf("Message send error\n");
	}
}
