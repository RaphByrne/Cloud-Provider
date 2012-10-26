/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "messages.h"

bool_t
xdr_message_c_ctrl (XDR *xdrs, message_c_ctrl *objp)
{
	register int32_t *buf;

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_message_client (XDR *xdrs, message_client *objp)
{
	register int32_t *buf;

	 if (!xdr_message_c_ctrl (xdrs, &objp->ctrl))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->name, 80))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->pword, 80))
		 return FALSE;
	 if (!xdr_u_int (xdrs, &objp->file_perm))
		 return FALSE;
	 if (!xdr_long (xdrs, &objp->file_size))
		 return FALSE;
	return TRUE;
}

struct message_client * message_create(enum message_c_ctrl ctrl, char* name, char*pword, int file_perm, long file_size)
{
	//printf("CREATING MESSAGE\n");
	struct message_client *m = calloc(1, sizeof *m);
	m->ctrl = ctrl;
	if(name != NULL) {
		m->name = malloc(80*sizeof(char));
		strncpy(m->name, name, 80);
	} else
		m->name = NULL;
	
	if(pword != NULL) {
		m->pword = malloc(80*sizeof(char));
		strncpy(m->pword, pword, 80);
	} else
		m->pword = NULL;
	m->file_perm = file_perm;
	m->file_size = file_size;
	//printf("SUCCESSFULLY CREATED MESSAGE\n");
	return m;
}

#define NUMVALS 13

//get the ctrl enum from a ctrl enum
int string_to_ctrl(char *s)
{
	enum message_c_ctrl vals[NUMVALS] = {ADD, DELETE, UPDATE, VERIFY, LIST, FETCH, FETCH_FAIL, LOGIN, LOGOUT, REGISTER, B_QUERY, B_WITHDRAW, B_VERIFY};
	for(int i = 0; i < NUMVALS; i++) {
		char *ctrl = ctrl_to_string(vals[i]);
		if(strcmp(ctrl,s) == 0)
			return vals[i];
		free(ctrl);
	}
	return -1;
}

//get the string representation of a ctrl enum
char *ctrl_to_string(enum message_c_ctrl c)
{
	switch (c) {
		case ADD:
			return strdup("ADD");
		case UPDATE:
			return strdup("UPDATE");
		case DELETE:
			return strdup("DELETE");
		case FETCH:
			return strdup("FETCH");
		case LIST:
			return strdup("LIST");
		case VERIFY:
			return strdup("VERIFY");
		case LOGIN:
			return strdup("LOGIN");
		case REGISTER :
			return strdup("REGISTER");
		case FETCH_FAIL :
			return strdup("FETCH_FAIL");
		case B_QUERY :
			return strdup("QUERY");
		case B_WITHDRAW :
			return strdup("WITHDRAW");
		case B_VERIFY :
			return strdup("B_VERIFY");
		default :
			return strdup("UNKNOWN");
	}
	return strdup("UNKNOWN");
}

//print a message
void message_print_c(struct message_client* m)
{
	if(m == NULL) {
		printf("PRINTING NULL MESSAGE\n");
		return;
	}
	printf("MESSAGE:\n");
	printf("\tTYPE: %s\n",ctrl_to_string(m->ctrl));
	printf("\tNAME: ");
	if(m->name != NULL)
		printf("%s",m->name);
	else
		printf("NULL");
	printf("\tPWORD: ");
	if(m->pword != NULL)
		printf("%s",m->pword);
	else
		printf("NULL");
	printf("\t FILE PERM: %d\t FILE SIZE: %ld",m->file_perm, m->file_size);
	printf("\n");
}
