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
#include <rpc/xdr.h>
#include <dirent.h>
#include "utilities.h"
#include "messages.h"
#include "gensalt.h"

#define	OPTLIST	""
#define PASS_SIZE 1024
#define FILEPATH "providerfiles"
#define CERTPATH "certs"
#define USERPATH "users"
#define PFILE "passwd"
#define PERMPATH "perms"
#define VERIPATH "veri"
#define USERDIR string_cat(3, USERPATH, "/", username)
#define PERMDIR string_cat(5, USERPATH,"/",username,"/", PERMPATH)
#define VERIDIR string_cat(5, USERPATH, "/", username, "/", VERIPATH)

extern char *strdup(const char *str);

char *argv0 = NULL;
int num_users = 0;


void verify_file(BIO *bio, char *username, char* filename);

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


int mk_user_dir(char *username)
{
	char *filepath = USERDIR;
	char *permfolder = PERMDIR;
	char *verifolder = VERIDIR;
	int result = mkdir(filepath, S_IRWXU);
	result |= mkdir(permfolder, S_IRWXU); //or the bits together. If both return 0 then success otherwise report failure
	result |= mkdir(verifolder, S_IRWXU);
	free(verifolder);
	free(filepath);
	free(permfolder);
	return result;
}

int user_dir_exists(char *username)
{
	DIR *dir;
	struct dirent *ent;
	dir = opendir(USERPATH);
	if(dir != NULL) {
		while((ent = readdir(dir)) != NULL) {
			printf("DIR: %s\n", ent->d_name);
			if(strncmp(username, ent->d_name, strlen(username)) == 0) {
				closedir(dir);
				return 1;
			}
		}
		closedir(dir);
		return 0;
	} else {
		perror("Could not open users directory\n");
		return 0;
	}
}

mode_t get_permissions(char *filename)
{
	XDR xdr;
	FILE *f = fopen(filename, "r"); //TODO should check this too
	xdrstdio_create(&xdr, f, XDR_DECODE);
	mode_t perms = 0;
	xdr_u_int(&xdr, &perms); //TODO check that this worked
	xdr_destroy(&xdr);
	fclose(f);
	return perms;
}

void store_permissions(char* filename, mode_t perms)
{
	FILE *f = fopen(filename, "w");
	if(f != NULL) {
		printf("Writing permissions to %s\n",filename);
		XDR xdr;
		xdrstdio_create(&xdr, f, XDR_ENCODE);
		xdr_u_int(&xdr, &perms);
		xdr_destroy(&xdr);
		fchmod(fileno(f), S_IRUSR);
		fclose(f);
	} else {
		printf("Couldn't write perms to %s\n",filename);
		perror("Problems writing permissions");
	}
}


int verify_pword(char *username, char *pword)
{
	chmod(PFILE, S_IRUSR); //let us read the PFILE
	FILE *f = fopen(PFILE, "r");
	if(f != NULL) {
		char *line = calloc(BUFSIZ, sizeof(char));
		while(fgets(line, BUFSIZ, f) != NULL) {
			char *name = strtok(line, " ");
			if(strncmp(username, name, strlen(username)) == 0) {
				char *salt = strtok(NULL, " "); //TODO check all this shit
				char *hash = strtok(NULL, " "); //comes with '\n'
				char *newline = strchr(hash, '\n');
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

FILE *find_file(char *username, char *filename)
{
	char *user_file = string_cat(3,USERDIR,"/",filename);	
	FILE *f = NULL;
	f = fopen(user_file, "r");
	free(user_file);
	return f;
}

//read a user's stored file and send it back to them
void fetch_file(BIO *bio, char* username, char* filename)
{
	char *user_file = string_cat(3,USERDIR,"/",filename);	
	char *perm_file = string_cat(3,PERMDIR,"/",filename);
	FILE *f = fopen(user_file, "r");
	if(f != NULL) {
		long filesize = size_of_file(user_file);
		send_create_message(bio, FETCH, filename, "", get_permissions(perm_file), filesize);
		verify_file(bio, username, filename);
		send_file(bio, user_file);
	} else {
		perror("File fetch problem");
		send_create_message(bio, FETCH_FAIL, strerror(errno), "", 0, 0);
	}
	free(user_file);
	free(perm_file);
}

int delete_file(BIO *bio, char* username, char* filename)
{
	int result = 0;
	char *userdir = USERDIR;
	char *permdir = PERMDIR;
	char *veridir = VERIDIR;
	char *user_file = string_cat(3,userdir,"/",filename);	
	char *perm_file = string_cat(3,permdir,"/",filename);
	char *veri_file = string_cat(3,veridir,"/",filename);
	chmod(user_file, S_IWUSR);
	FILE *f = fopen(user_file, "w"); //only checking user file, if everything set up then all other files should be there
	//TODO check other files and/or ensure that if they can't be made then orig file is removed
	if(f != NULL) {
		fclose(f);
		if((remove(user_file) == 0) && (remove(perm_file) == 0) &&(remove(veri_file) == 0)) { //TODO not atomic/reversible
			send_string(bio, "DELETE_OK");
			result = 1;
		} else
			send_string(bio, string_cat(2,"DELETE_FAIL: ",strerror(errno)));
	} else
		send_string(bio, string_cat(2,"DELETE_FAIL: ",strerror(errno)));
	chmod(user_file, S_IRUSR);
	free(user_file);
	free(perm_file);
	free(veri_file);
	free(veridir);
	free(userdir);
	free(permdir);
	return result;
}

int verify_token(struct trans_tok *t)
{
	//TODO need to log in to bank
	struct ssl_connection *conn = connect_to("127.0.0.1:1111",CERTPATH,"ca-cert.pem","provider.pem","provider-key.pem");
	if(conn != NULL) {
		BIO *bio = conn->bio;
		int result = 0;
		if(op_LOGIN(bio, "provider", "provider")) {
			send_create_message(bio, B_VERIFY, "", "", 0, 0);
			send_trans_tok(bio, t);
			char *res = get_str_message(bio);
			if(res != NULL) {
				if(strncmp(res,"VALIDATION_SUCCESS", strlen("VALIDATION_SUCCESS")) == 0) {
					printf("Validated money!\n");
					free(res);
					result = 1;
				} else {
					fprintf(stderr, "Validation Failure: %s\n", res);
					free(res);
				}				
			} else {
				fprintf(stderr, "No response from bank\n");
			}
		} else {
			fprintf(stderr, "Could not verify ourselves with bank\n");
		}
		BIO_free_all(bio);
		return result;
	} else {
		ssl_error("couldn't connect to bank to verify token");
		return 0;
	}
}

//read and store a file from the stream
int add_file(BIO * out, char *username, char* filename, mode_t file_mask, long filesize)
{
	char *userdir = USERDIR;
	printf("userdir: %s\n",userdir);
	
	
	char *user_filename = string_cat(3,userdir,"/", filename);
	int result = 1;
	//check if file exists and report to client
	if(access(user_filename, R_OK) != 0) { //if the file doesn't already exist
		printf("preparing to write to %s\n",user_filename);
		if(access(user_filename, W_OK) != 0) {
			send_string(out, "FILE_OK");
			char *money_res = get_str_message(out);
			if(money_res != NULL) {
				if(strncmp(money_res, "SENDING_PAYMENT", strlen("SENDING_PAYMENT")) == 0) {
					struct trans_tok *t = calloc(1, sizeof *t );
					if(get_trans_tok(out, t) > 0) {	
						if(verify_token(t)) {
							int err_code = 0;
							err_code = get_file(out, user_filename, S_IRUSR, filesize);
							if(err_code > 0) {
								//encode the file's permissions into another file
								char *permdir = PERMDIR;
								char *perm_file = string_cat(3,permdir,"/",filename);
								store_permissions(perm_file, file_mask);
								free(perm_file);
								free(permdir);
								
								//get the verification file
								char *veridir = VERIDIR;
								char *veri_file = string_cat(3, veridir, "/", filename);
								get_file(out, veri_file, S_IRUSR, FILE_HASH_SIZE); //TODO same check as above here
								free(veridir);
								free(veri_file);

								printf("Finished writing\n");	
							} else if (err_code == -2) {
								printf("FILE ADD FAIL\n");
								send_string(out, "FILESIZE AND REPORTED FILESIZE INCONSISTANT");
								result = -5;
							} else {
								result = -1;
								printf("FILE ADD FAIL\n");
								send_string(out, "FILE WRITE ERROR");
							}
						} else {
							send_string(out, "PAYMENT DENIED");
							result = -5;
						}
					} else {
						printf("Error receiving payment\n");
						result = -5; //-5 means untrustworthy connection, do not continue communication	
					}
				} else {
					printf("No payment received\n");
					result = -5; //-5 means untrustworthy connection, do not continue communication
				}
			} else {
				printf("No money confirmation received\n");
				result = -2;
			}
			
		} else {
			send_string(out, "COULD NOT WRITE TO SPECIFIED FILE");
			fprintf(stderr, "could not write to %s\n", user_filename);
			result =  -1;
		}
	} else {
		send_string(out, "FILE_EXISTS");
		result = -1;
	}
	//this is successful exiting
	free(userdir);
	free(user_filename);
	return result;
}

void update_file(BIO *bio, char *username, char *filename, mode_t perms, long filesize)
{
	if(delete_file(bio, username, filename))
		add_file(bio, username, filename, perms, filesize);
}

void list_files(BIO *bio, char *username)
{	
	DIR *dir;
	struct dirent *ent;
	char *userdir = USERDIR;
	dir = opendir(userdir);
	if(dir != NULL) {
		while((ent = readdir(dir)) != NULL) {
			if(ent->d_type != DT_DIR) {
				send_create_message(bio, LIST, ent->d_name, "", 0, 0);
			}
		}
		closedir(dir);
		send_create_message(bio, LIST, "", "DONE", 0, 0);
	} else {
		fprintf(stderr,"Could not open %s's directory for listing: %s\n",username, strerror(errno));
	}
	free(userdir);
}

//takes a users name and their filename
void verify_file(BIO *bio, char *username, char* filename)
{
	char *veridir = VERIDIR;
	char *userdir = USERDIR;
	char *veri_file = string_cat(3,veridir, "/", filename);
	char *user_file = string_cat(3,userdir, "/", filename);
	if(access(veri_file, R_OK) == 0) { //if we can access the verification file
		send_string(bio, "VERIFY_FILE_EXISTS");
		//send the user's hash first
		unsigned char* buf = calloc(FILE_HASH_SIZE, sizeof(unsigned char));
		int bytes = 0;
		bytes = load_file(veri_file, buf, sizeof(unsigned char), FILE_HASH_SIZE);
		send_char_buf(bio, buf, bytes);
		free(buf);
		//then send our generated hash
		bytes = 0;
		buf = digest_file(user_file, &bytes);
		send_char_buf(bio, buf, bytes);
		free(buf);
	} else
		send_string(bio, "NO_VERIFY_FILE");
	free(veri_file);
	free(veridir);
	free(userdir);
	free(user_file);
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
	char *salt = gensalt(NULL, NULL);
	char *phash = crypt(pword, salt); //TODO not using a great random function here
	memset(pword, 0, strlen(pword)); //ZEROS THE PASSWORD AFTER HASHING IT
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
	//memset(phash, 0, strlen(phash));
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
			mk_user_dir(username);
			message = strdup("REG_SUCCESS");
		}
	}
	send_char_buf(bio, message, strlen(message));
	free(message);
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
					BIO_free(out);
					continue;
				}
				//verify the client
				X509 *client_cert = SSL_get_peer_certificate(tmpssl);
				char* username = calloc(strlen(mess->name)+1,sizeof(char));
				strncpy(username, mess->name, strlen(mess->name));
				char* pword = calloc(strlen(mess->pword)+1, sizeof(char));
				strncpy(pword, mess->pword, strlen(mess->pword));
				//xdr_free((xdrproc_t)xdr_message_client, (char *)mess);
				
				if(verify_client(client_cert, username, pword) == 1) {
					memset(pword, 0, strlen(pword));
					free(pword);
					printf("VERIFIED SUCCESSFULLY\n");
					send_string(out, "CONN_OK");
					
					printf("Waiting for client request\n");
					//get control message from client
					struct message_client *m = calloc(1,sizeof(*m));
					int messlen = 0;
					bool exit = false;
					while(!exit && ((messlen = get_c_message(out, m)) != 0)) {
					
						if(messlen < 0) {
							printf("Message decoding error\n");
						}  else {
							switch (m->ctrl) {
								case ADD :
									if(add_file(out, username, m->name, m->file_perm, m->file_size) == -5)
										exit = true; //if add throws exit error, stop accepting messages
									break;
								case FETCH:
									fetch_file(out, username, m->name);
									break;
								case DELETE:
									delete_file(out, username, m->name);
									break;
								case UPDATE:
									update_file(out, username, m->name, m->file_perm, m->file_size);
									break;
								case LIST:
									list_files(out, username);
									break;
								case VERIFY:
									verify_file(out, username, m->name);
									break;
								default :
									printf("UNKNOWN CLIENT COMMAND\n");
							}
						}
						xdr_free((xdrproc_t)xdr_message_client, (char *)mess);
						m = calloc(1,sizeof(*m));
					}
					if(!exit)
						printf("Client closed the connect\n");
					else
						printf("Aborted due to untrustworthy client\n");
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
			//SSL_free(&tmpssl);
		} else {
			printf("HANDSHAKE FAILED\n");
		}
		//BIO_free(out);
	}

	return 0;
}

/*
int load_users()
{
	FILE *f = fopen(USERSFILE, "r");
	users = init_user_list();	
	if(f != NULL) {
		char *buf = malloc(sizeof(char)*BUFSIZ);
		fgets(buf, BUFSIZ, f);
		users->num = atoi(buf);
		while(feof(f) == 0) {
			fgets(buf, BUFSIZ, f);
			add_user(users, create_user(buf));
		}
		return 1;
	}
	return 0;
}
*/
