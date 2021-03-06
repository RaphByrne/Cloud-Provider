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
int num_users = 0;
bool dflag;

struct a_list *accounts;
#define ACCOUNTS_FILE "accounts"

void send_query_response(BIO *bio, char *username);
void withdraw_response(BIO *bio, char *username);
void verify_response(BIO *bio, char *payee);

static void usage(int status)
{
	fprintf(stderr, "Usage: %s <ADDR>\n", argv0);
	fprintf(stderr, "Where\t<ADDR> is the address and port for this server to operate on in <ADDR>:<PORT> format\n");

	exit(status);
}


//initialise some openssl stuff
//load libraries, error strings etc.
void init_SSL() 
{
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
}

//verify "username"'s password 'pword' against their password
//in the password file
int verify_pword(char *username, char *pword)
{
	chmod(PFILE, S_IRUSR); //let us read the PFILE
	FILE *f = fopen(PFILE, "r");
	if(f != NULL) {
		char *line = calloc(BUFSIZ, sizeof(char));
		while(fgets(line, BUFSIZ, f) != NULL) {
			char *name = strtok(line, " ");
			if(strncmp(username, name, strlen(username)) == 0) { //find their username
				char *salt = strtok(NULL, " ");
				char *hash = strtok(NULL, " "); //comes with '\n'
				char *newline = strchr(hash, '\n'); //TODO hash might contain newlines?
				if(newline)
					newline = '\0';
				char *uhash = crypt(pword, salt);
				if(strncmp(hash, uhash, strlen(uhash)) == 0) { //compare the hashes
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

//Verifies a client, ensure they actually sent us a certificate
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

//checks whether a user has an account with us
//uses the passwd file as an accounts file
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
		chmod(PFILE, 0); //reset the password file perms to zero
		perror("Could not open PFILE");
		return errno;
	}
}

//adds a user to the passwd file. Hash their passwd using crypt
int add_user(char *username, char *pword)
{
	char *salt = gensalt(NULL, get_rand);
	char *phash = crypt(pword, salt); //TODO not using a great random function here
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
	free(salt);
	//THIS IS MAINLY FOR TESTING (SO WE DON'T HAVE TO RE-REGISTER EVERYONE)
	f = fopen(ACCOUNTS_FILE,"a");
	if(f != NULL) {
		if(fprintf(f,"%s %d\n", username, 20) > 0) //give everyone 20 to start (mainly for testing)
			result = 1;
	} else
		printf("Could not open ACCOUNTS_FILE to add a user");
	fclose(f);
	//TESTING PORTION OVER
	return result;
}

//adds a new user to the bank
//mainly added for testing, the registration process would be more robust
//in a real application. Ideally this is an out of band communication with proper
//user identification
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

//Initialises the accounts list
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

struct t_list *whitelist; //The transaction token whitelist

//Initialise the whitelist
void init_transactions()
{
	whitelist = init_trans_list();

}

int main(int argc, char **argv) {	


	init_SSL();
	init_accounts();
	init_transactions();

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
	if(SSL_CTX_use_certificate_file(ctx, string_cat(3,CERTPATH, "/", "bank.pem"), SSL_FILETYPE_PEM) < 1)
	{
		ssl_error("failed to load server cert");
		exit(1);
	}

	printf("LOADING PRIVATE KEY\n");
	//load our private key
	if(SSL_CTX_use_PrivateKey_file(ctx, string_cat(3, CERTPATH,"/", "bank-key.pem"), SSL_FILETYPE_PEM) < 1)
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

	//the accept loop
	while(true) {
		printf("waiting for new connection\n");
		BIO_do_accept(abio);
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
					init_accounts(); //we will have updated the file (FOR TESTING PURPOSES)
					xdr_free((xdrproc_t)xdr_message_client, (char *)mess);
					BIO_free(out);
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
					send_string(out, "CONN_OK");
					
					//get control message from client
					struct message_client *m = calloc(1,sizeof(*m));
					int messlen = 0;
					while((messlen = get_c_message(out, m)) != 0) {
						if(messlen < 0) {
							perror("Message decoding error");
						}  else {
							switch (m->ctrl) {
								case B_QUERY :
									send_query_response(out, username);
									break;
								case B_WITHDRAW :
									withdraw_response(out, username);
									break;
								case B_VERIFY :
									verify_response(out, username);
									break;
								default :
									printf("UNKNOWN CLIENT COMMAND\n");
							}
						}
						free(m);
						m = calloc(1,sizeof(*m));
					}
					printf("Client closed the connect\n");
					account_list_print(accounts);
					trans_tok_list_print(whitelist);
					free(m);
				} else {
					printf("COULD NOT VERIFY CLIENT\n");
					send_string(out, "COULD NOT VERIFY");
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


//respond to a payment verification request
void verify_response(BIO *bio, char* payee)
{
	struct trans_tok *t = calloc(1, sizeof *t);
	get_trans_tok(bio, t);
	if(t != NULL) {
		u_int orig_sig_len = t->sig_len;
		t->sig_len = 0;
		unsigned char *orig_sig = malloc(orig_sig_len);
		memcpy(orig_sig, t->bank_sig, orig_sig_len);
		t->bank_sig = "ABC"; //reset the message
		int buf_size = 256;
		//char *buf = buffer_trans_tok(t, &buf_size); this was for verifying with sig
		FILE *f = fopen(string_cat(3, CERTPATH,"/", "bank.pem"), "r");
		if(f != NULL) {
			//X509 *x = PEM_read_X509(f, NULL, NULL, NULL); get the pub key for verifying the signature
			//EVP_PKEY *pkey = X509_get_pubkey(x);
			if(contains_trans_tok(whitelist, t)) {
				//verify_signed_data(buf, buf_size, orig_sig, orig_sig_len, pkey)
					if(!trans_tok_remove(whitelist, t))
						printf("DIDN'T REMOVE TRANSACTION\n");
					//transfer the funds
					struct account *payer_acc = account_get(accounts, t->payer);
					if(payer_acc->balance >= t->value) {
						payer_acc->balance = payer_acc->balance - t->value;
						struct account *payee_acc = account_get(accounts, payee);
						payee_acc->balance += t->value;
						send_string(bio, "VALIDATION_SUCCESS");
					} else
						send_string(bio, "INSUFFICIENT FUNDS");		
				/* THIS HAS BEEN REMOVED BECAUASE I CAN'T IMPLEMENT IT
				} else {
					ssl_error("Could not create signature");
					send_string(bio, "VALIDATION ERROR");
				}
				*/
			} else {
				printf("Transaction not in list\n");
				send_string(bio, "TRANSACTION NOT ON WHITELIST\n");
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

//Create a new transaction token for the payer 'username' for
//'value' fluffy bucks
struct trans_tok * create_token(char *username, int value)
{	
	struct trans_tok *t = create_trans_tok(username, 1, value, "ABC");
	
	while(contains_trans_tok(whitelist, t)) {
		//TODO random serials
		t->serial += 1; //find a serial we can use
	}
	return t;
	/*
	* THE BELOW INVOLVES SIGNING OUR TRANSACTION REQUEST WITH OUR PRIVATE KEY
	* BUT WAS REMOVED DUE TO IMPLEMENTATION DIFFICULTIES
	int buf_size = 256;
	char *buf = buffer_trans_tok(t, &buf_size);
	FILE *f = fopen(string_cat(3, CERTPATH,"/", "bank-key.pem"), "r");
	if(f != NULL) {
		EVP_PKEY* privkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
		int len = 0;
		unsigned char *sig = sign_data(buf, buf_size, privkey, &len);
		if(sig != NULL) {
			t->bank_sig = sig;
			t->sig_len = len;
			return t;
		} else {
			ssl_error("Could not create signature");
			return NULL;
		}
	} else {
		perror("Could not open private key file");
		return NULL;
	}
	*/
}

//respond to a withdraw request. create a token if the user has enough
//money. Sends the token back if they do and add it to the whitelist
void withdraw_response(BIO *bio, char *username)
{
	printf("processing withdrawal for %s\n",username);
	struct trans_req *r = calloc(1,sizeof *r);
	if(get_trans_req(bio, r) > 0) { //load the request
		struct account *a = account_get(accounts, username);
		account_print(a);
		if(a->balance >= r->value) { //check the balance
			if(send_string(bio, "TRANS_OK") <= 0) { //respond
				printf("couldn't send withdrawal response\n");
			} else {
				struct trans_tok *t = create_token(username, r->value);
				if(t != NULL) {
					if(send_trans_tok(bio, t) > 0) { //send the new token back
						add_trans(whitelist, t); //add it to the whitelist
					} else
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

//send back the user's balance
void send_query_response(BIO *bio, char *username)
{
	if(contains_account(accounts, username)) {
		send_string(bio, "QUERY_OK");
		struct account *a = account_get(accounts, username);
		char *str_bal = malloc(sizeof(char)*10);
		sprintf(str_bal, "%d", a->balance);
		send_string(bio, str_bal);
		free(str_bal);
	} else {
		send_string(bio, "User not found");
	}
}
