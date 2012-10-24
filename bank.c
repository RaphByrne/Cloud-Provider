#include <errno.h>
#include <stdbool.h>
#include <ctype.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/pem.h>
#include <rpc/xdr.h>
#include <dirent.h>
#include "utilities.h"
#include "messages.h"
#include "gensalt.h"
#include "accounts.h"

#define OPTLIST	""
#define PASS_SIZE 1024
#define CERTPATH "certs"
#define PFILE "passwd"


char *argv0 = NULL;
char *password;
int num_users = 0;


void send_query_response(BIO *bio, char *username);
void withdraw_response(BIO *bio, char *username);
void verify_response(BIO *bio);

static void usage(int status)
{
	fprintf(stderr, "Usage: %s [options]\n", argv0);
	fprintf(stderr, "options are:\n");

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

void load_password(char* password_file)
{
	char *password2 = malloc(sizeof(char)*PASS_SIZE);
	FILE *f = fopen(password_file, "r");
	if(f == NULL) {
		fprintf(stderr, "Password file %s COULD NOT BE OPENED\n", password_file);
		perror("");
		exit(1);
	}
	fgets(password2, PASS_SIZE, f);
	//remove the newline
	char *newline = strchr(password2,'\n');
	*newline = '\0';
	password = password2;
}

int password_callback(char *buf, int size, int rwflag, void *userdata)
{
	if(size < strlen(password)) {
		return 0;
	}
	strcpy(buf, password);
	return strlen(buf);
}


int verify_pword(char *username, char *pword)
{
	chmod(PFILE, S_IRUSR); //let us read the PFILE
	FILE *f = fopen(PFILE, "r");
	if(f != NULL) {
		printf("Opened password file\n");
		char *line = calloc(BUFSIZ, sizeof(char));
		while(fgets(line, BUFSIZ, f) != NULL) {
			char *name = strtok(line, " ");
			printf("Checking %s against %s\n",name, username);
			if(strncmp(username, name, strlen(username)) == 0) {
				char *salt = strtok(NULL, " "); //TODO check all this shit
				char *hash = strtok(NULL, " "); //comes with '\n'
				char *newline = strchr(hash, '\n'); //TODO hash might contain newlines?
				if(newline)
					newline = '\0';
				printf("USER: %s, SALT: %s, HASH %s\n", username, salt, hash);
				char *uhash = crypt(pword, salt);
				printf("UHASH: %s\n", uhash);
				if(strncmp(hash, uhash, strlen(uhash)) == 0) {
					printf("Hashes match!\n");
					return 1;
				}
			}
		}
		free(line);
		fchmod(fileno(f), 0); //reset the passfile's permissions
		fclose(f);
		return 0;
	} else {
		chmod(PFILE, 0);
		perror("Could not open PFILE");
		return errno;
	}
}

int verify_client(X509 *cert, char *username, char *pword)
{
	if(cert == NULL) {
		printf("No certificate received from client\n");
		return -1;
	} else {
		int result = 0;
		if(verify_pword(username, pword) == 1)
			result = 1;
		else {
			printf("Could not verify password of %s\n",username);
			result = 0;
		}
		return result;
	}
}

int user_exists(char *username)
{
	chmod(PFILE, S_IRUSR); //let us read the PFILE
	FILE *f = fopen(PFILE, "r");
	if(f != NULL) {
		while(feof(f) == 0) {
			char *line = calloc(BUFSIZ, sizeof(char));
			if(fgets(line, BUFSIZ, f) != NULL) {
				char *name = strtok(line, " ");
				if(name != NULL) {
					if(strncmp(username, name, strlen(username)) == 0) {
						return 1;
					}
					free(name);
				}
			}
			//free(line);
		}
		fchmod(fileno(f), 0); //reset the passfile's permissions
		fclose(f);
		return 0;
	} else {
		chmod(PFILE, 0);
		perror("Could not open PFILE");
		return errno;
	}
}

int add_user(char *username, char *pword)
{
	printf("Adding user %s\n", username);
	char *salt = gensalt(NULL, NULL);
	char *phash = crypt(pword, salt); //TODO not using a great random function here
	//memset(pword, 0, strlen(pword)); //ZEROS THE PASSWORD AFTER HASHING IT
	chmod(PFILE, S_IWUSR); //let us write to the PFILE
	FILE *f = fopen(PFILE, "a");
	int result = 0;
	if(f != NULL) {
		if(fprintf(f,"%s %s %s\n", username, salt, phash) > 0)
			result = 1;
	} else
		printf("Could not open PFILE to add a user");
	fclose(f);
	chmod(PFILE, 0);
	memset(phash, 0, strlen(phash));
	free(salt);
	//free(phash);
	return result;
}

void register_user(BIO *bio, char *username, char *pword)
{
	char *message = strdup("REG_FAIL");
	if(user_exists(username)) {
		message = strdup("USER_EXISTS");
	} else {
		if(add_user(username, pword)) {
			message = strdup("REG_SUCCESS");
		}
	}
	send_char_buf(bio, message, strlen(message));
	free(message);
}

struct a_list *accounts;
#define ACCOUNTS_FILE "accounts"

void init_accounts()
{
	accounts = init_account_list();
	FILE *f = fopen(ACCOUNTS_FILE, "r");
	if(f != NULL) {
		char *buf = malloc(BUFSIZ);
		while(fgets(buf, BUFSIZ, f) != NULL) {
			char *name = strtok(buf, " ");
			int balance = atoi(strtok(NULL, " "));
			add_account(accounts, create_account(name, balance));
		}
		account_list_print(accounts);
	} else {
		perror("Couldn't open accounts file\n");
		exit(0);
	}
}

int main(int argc, char **argv) {	


	init_SSL();
	init_accounts();

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
	if(argc < 1)
		usage(1);
	
	char *port = argv[0];

	SSL_CTX *ctx = (SSL_CTX *)SSL_CTX_new(SSLv23_server_method());
	SSL *ssl;

	//TODO THIS IS REALLY BAD, READING THE PRIVKEY PASSWORD FROM A FILE
	if(argc > 1) {
		char *pass_file = argv[1];
		load_password(pass_file);
		SSL_CTX_set_default_passwd_cb(ctx, &password_callback);
	}

	printf("LOADING CA CERT\n");
	//load our ca certificate
	if(SSL_CTX_load_verify_locations(ctx, string_cat(3,CERTPATH, "/", "ca-cert.pem"), NULL) == 0) 
	{
		printf("%s\n",string_cat(3,CERTPATH, "/", "cacert.pem"));
		ssl_error("CA cert load fail");
		exit(1);
	}

	printf("LOADING SERVER CERT\n");
	//load our certificate used to send files
	if(SSL_CTX_use_certificate_file(ctx, string_cat(3,CERTPATH, "/", "provider.pem"), SSL_FILETYPE_PEM) < 1)
	{
		ssl_error("failed to load server cert");
		exit(1);
	}

	printf("LOADING PRIVATE KEY\n");
	//load our private key
	if(SSL_CTX_use_PrivateKey_file(ctx, string_cat(3, CERTPATH,"/", "provider-key.pem"), SSL_FILETYPE_PEM) < 1)
	{
		ssl_error("failed to load private key");
		exit(1);
	}


	BIO *bio, *abio, *out;

	bio = BIO_new_ssl(ctx,0);
	if(bio == NULL)
	{
		ssl_error("bio creation fail");
		exit(1);
	}

	//set up connection
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	SSL_set_verify(ssl, SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER, NULL);

	abio = BIO_new_accept(port);
	BIO_set_accept_bios(abio, bio);
	BIO_set_bind_mode(abio, BIO_BIND_REUSEADDR);
	//test connection
	if(BIO_do_accept(abio) <= 0)
	{
		ssl_error("BIO test problem");
		exit(1);
	}

	while(true) {
		printf("waiting for new connection\n");
		BIO_do_accept(abio);
		printf("SOMEONE CONNECTED, TESTING CREDENTIALS\n");
		out = BIO_pop(abio);
		if(BIO_do_handshake(out) > 0) {
			SSL* tmpssl;
			BIO_get_ssl(out, &tmpssl);
			if(SSL_get_verify_result(tmpssl) == X509_V_OK) {
				//get their username
				struct message_client *mess = calloc(1,sizeof(*mess));
				get_c_message(out, mess);
				if(mess->ctrl == REGISTER) {
					register_user(out, mess->name, mess->pword);
					xdr_free((xdrproc_t)xdr_message_client, (char *)mess);
					continue;
				}
				//verify the client
				X509 *client_cert = SSL_get_peer_certificate(tmpssl);
				char* username = calloc(strlen(mess->name)+1,sizeof(char));
				strncpy(username, mess->name, strlen(mess->name));
				char* pword = calloc(strlen(mess->pword)+1, sizeof(char));
				strncpy(pword, mess->pword, strlen(mess->pword));
				xdr_free((xdrproc_t)xdr_message_client, (char *)mess);
				
				if(verify_client(client_cert, username, pword)) {
					//memset(pword, 0 , strlen(pword));
					printf("VERIFIED SUCCESSFULLY\n");
					send_string(out, "CONN_OK");
					
					printf("Waiting for client request\n");
					//get control message from client
					struct message_client *m = calloc(1,sizeof(*m));
					int messlen = 0;
					while((messlen = get_c_message(out, m)) != 0) {
						if(messlen < 0) {
							printf("Message decoding error\n");
						}  else {
							switch (m->ctrl) {
								case B_QUERY :
									send_query_response(out, username);
									break;
								case B_WITHDRAW :
									withdraw_response(out, username);
									break;
								case B_VERIFY :
									verify_response(out);
									break;
								default :
									printf("UNKNOWN CLIENT COMMAND\n");
							}
						}
						free(m);
						m = calloc(1,sizeof(*m));
					}
					printf("Client closed the connect\n");
					free(m);
				} else {
					printf("COULD NOT VERIFY CLIENT\n");
				}
				free(username);
			} else {
				printf("COULD NOT VERIFY CLIENT\n");
				ssl_error("client verification");
			}
			BIO_free(out);
		} else {
			printf("HANDSHAKE FAILED\n");
		}
	}

	return 0;
}

void verify_response(BIO *bio)
{
	struct trans_tok *t = calloc(1, sizeof *t);
	get_trans_tok(bio, t);
	if(t != NULL) {
		printf("verifying token\n");
		unsigned char *orig_sig = t->bank_sig;
		t->bank_sig = (unsigned char*)"AVERYSMALLAMOUNTOFPADDING"; //reset the message
		unsigned char *buf = buffer_trans_tok(t, 200);
		FILE *f = fopen(string_cat(3, CERTPATH,"/", "provider-key.pem"), "r");
		if(f != NULL) {
			RSA* rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
			int s1 =  RSA_size(rsa);
			if(RSA_verify(NID_sha1, buf, 200, orig_sig, &s1, rsa)) {
				printf("VERIFY SUCCESS\n");
				send_string(bio, "VALIDATION_SUCCESS");
			} else {
				ssl_error("Could not create signature");
				send_string(bio, "VALIDATION ERROR");
			}
		} else {
			perror("Could not open private key file");
			send_string(bio, "VALIDATION ERROR");
		}
	} else {
		fprintf(stderr, "CANNOT VERIFY NULL TOKEN\n");
		send_string(bio, "TOKEN RECEIVE ERROR");
	}
}

struct trans_tok * create_token(char *username, int value)
{	
	//TODO get serial from trans_list
	struct trans_tok *t = create_trans_tok(username, 1, value, (unsigned char*)"AVERYSMALLAMOUNTOFPADDING");
	unsigned char *buf = buffer_trans_tok(t, 200);
	FILE *f = fopen(string_cat(3, CERTPATH,"/", "provider-key.pem"), "r");
	if(f != NULL) {
		RSA* rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
		unsigned char *sig = malloc(RSA_size(rsa));
		int s1 =  RSA_size(rsa);
		if(RSA_sign(NID_sha1, buf, 200, sig, &s1, rsa)) {
			t->bank_sig = sig;
			return t;
		} else {
			ssl_error("Could not create signature");
			return NULL;
		}
	} else {
		perror("Could not open private key file");
		return NULL;
	}
}

void withdraw_response(BIO *bio, char *username)
{
	printf("processing withdrawal for %s\n",username);
	struct trans_req *r = calloc(1,sizeof *r);
	if(get_trans_req(bio, r) > 0) {
		struct account *a = account_get(accounts, username);
		account_print(a);
		if(a->balance >= r->value) {
			if(send_string(bio, "TRANS_OK") <= 0) {
				printf("couldn't send withdrawal response\n");
			} else {
				//TODO serials and sigs
				struct trans_tok *t = create_token(username, r->value);
				if(t != NULL) {
					print_trans_tok(t);
					if(send_trans_tok(bio, t) > 0)
						a->balance = a->balance - r->value;
					else
						fprintf(stderr,"Trans Tok not sent, not deducting balance\n");
				} else
					fprintf(stderr, "Token creation fail\n");
			}
		} else {
			printf("not enough money to complete request\n");
			send_string(bio, "BALANCE TOO LOW");
		}
	} else {
		printf("didn't get trans req\n");
	}
	printf("Finised withdraw\n");
	free(r);
}

void send_query_response(BIO *bio, char *username)
{
	if(contains_account(accounts, username)) {
		send_string(bio, "QUERY_OK");
		struct account *a = account_get(accounts, username);
		char *str_bal = malloc(sizeof(char)*10);
		sprintf(str_bal, "%d", a->balance);
		//char *message = string_cat(3,username,": ", str_bal);
		send_string(bio, str_bal);
		free(str_bal);
		//free(message);
	} else {
		send_string(bio, "User not found");
	}
}
