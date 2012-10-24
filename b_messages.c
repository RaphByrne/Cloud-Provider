/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "b_messages.h"

bool_t
xdr_trans_req (XDR *xdrs, trans_req *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->payer, 100))
		 return FALSE;
	 if (!xdr_u_int (xdrs, &objp->value))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_trans_tok (XDR *xdrs, trans_tok *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->payer, 100))
		 return FALSE;
	 if (!xdr_u_int (xdrs, &objp->serial))
		 return FALSE;
	 if (!xdr_u_int (xdrs, &objp->value))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->bank_sig, 64))
		 return FALSE;
	return TRUE;
}

struct trans_req *create_trans_req(char *payer, u_int value)
{
	struct trans_req *out = calloc(1, sizeof *out);
	out->payer = malloc(100);
	memcpy(out->payer, payer, 100);
	out->value = value;
	return out;
}

struct trans_tok *create_trans_tok(char *payer, u_int serial, u_int value, unsigned char *bank_sig)
{
	printf("CREATING TRANS TOK\n");
	struct trans_tok *out = calloc(1, sizeof *out);
	out->payer = malloc(100);
	strncpy(out->payer, payer, 100);
	out->serial = serial;
	out->value = value;
	out->bank_sig = malloc(64);
	memcpy(out->bank_sig, bank_sig, 64);
	printf("SUCCESSFULLY CREATED TRANS TOK\n");
	return out;
}

int trans_tok_equals(struct trans_tok *t1, struct trans_tok *t2)
{
	if(strcmp(t1->payer, t2->payer) == 0)  {
		if(t1->serial == t2->serial) { 
			if(t1->value == t2->value) {
				if(unsigned_string_equals(t1->bank_sig, 64, t2->bank_sig, 64))
					return 1;
			}
		}
	}
	return 0;
}

void print_trans_tok(struct trans_tok *t)
{
	if(t == NULL) {
		printf("PRINTING NULL TOKEN\n");
		return;
	}
	printf("TRANS TOKEN:\n");
	printf("\tPAYER: ");
	if(t->payer != NULL)
		printf("%s",t->payer);
	else
		printf("NULL");
	printf("\t SERIAL: %u\t VALUE: %u",t->serial, t->value);	
	printf("\n");
	
}

int get_trans_tok(BIO* bio, struct trans_tok *t)
{
	int result = 0;
	char *buf = calloc(BUFSIZ, sizeof(char));
	result = get_char_buf(bio, buf, BUFSIZ);
	if(result > 0) {	
		XDR xdr;
		xdrmem_create(&xdr, buf, BUFSIZ, XDR_DECODE);
		if(!xdr_trans_tok(&xdr, t)) { 
			perror("COULD NOT LOAD TRANS TOK FROM BUF\n");
			result = -1;
		}
		print_trans_tok(t);
		xdr_destroy(&xdr);
		free(buf);
	}
	return result;
}

unsigned char* buffer_trans_tok(struct trans_tok *t, size_t size)
{
	char *buf = malloc(size);
	XDR xdr;
	xdrmem_create(&xdr, buf, size, XDR_ENCODE);
	if(!xdr_trans_tok(&xdr, t)) {
		perror("could not encode trans tok\n");
		return NULL;
	}
	xdr_destroy(&xdr);
	return buf;
}

int send_trans_tok(BIO *bio, struct trans_tok *t)
{
	char *buf = calloc(BUFSIZ, sizeof(char));
	XDR xdr;
	xdrmem_create(&xdr, buf, BUFSIZ, XDR_ENCODE);
	if(!xdr_trans_tok(&xdr, t)) {
		perror("could not encode trans tok\n");
		return -1;
	}
	int result = send_char_buf(bio, buf, BUFSIZ);
	xdr_destroy(&xdr);
	free(buf);
	return result;
}

int send_create_trans_tok(BIO *bio, char* payer, u_int serial, u_int value, unsigned char *sig)
{
	struct trans_tok *t = create_trans_tok(payer, serial, value, sig);
	printf("Sending: \n");
	print_trans_tok(t);
	int result = send_trans_tok(bio, t);
	xdr_free((xdrproc_t) xdr_trans_tok, (char *)t);
	return result;
}

int get_trans_req(BIO* bio, struct trans_req *r)
{
	int result = 0;
	char *buf = calloc(BUFSIZ, sizeof(char));
	result = get_char_buf(bio, buf, BUFSIZ);
	if(result > 0) {	
		XDR xdr;
		xdrmem_create(&xdr, buf, BUFSIZ, XDR_DECODE);
		if(!xdr_trans_req(&xdr, r)) { 
			perror("COULD NOT LOAD TRANS TOK FROM BUF\n");
			result = -1;
		}
		print_trans_req(r);
		xdr_destroy(&xdr);
		free(buf);
	}
	return result;
}

int send_trans_req(BIO *bio, struct trans_req* r)
{
	char *buf = calloc(BUFSIZ, sizeof(char));
	XDR xdr;
	xdrmem_create(&xdr, buf, BUFSIZ, XDR_ENCODE);
	if(!xdr_trans_req(&xdr, r)) {
		perror("could not encode message\n");
		return -1;
	}
	int result = send_char_buf(bio, buf, BUFSIZ);
	xdr_destroy(&xdr);
	free(buf);
	return result;
}

int send_create_trans_req(BIO *bio, char* payer, u_int value)
{
	struct trans_req *t = create_trans_req(payer, value);
	int result = send_trans_req(bio, t);
	xdr_free((xdrproc_t) xdr_trans_req, (char *)t);
	return result;
}

void print_trans_req(struct trans_req *r)
{
	if(r == NULL) {
		printf("PRINTING NULL TRANS REQ\n");
		return;
	}
	printf("TRANS REQ:\n");
	printf("\tPAYER: ");
	if(r->payer != NULL)
		printf("%s",r->payer);
	else
		printf("NULL");
	printf("\t VALUE: %u", r->value);	
	printf("\n");
	
}
