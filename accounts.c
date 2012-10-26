#include "accounts.h"
#include "utilities.h"

/* This file contains the functions to manipulate the accounts and transaction token lists. Both are just
 * simple linked lists.
 *
 */

struct a_list* init_account_list()
{
	struct a_list* list;
	list = malloc(sizeof(struct a_list));
	list->first = NULL;
	list->last = NULL;
	list->num = 0;
	return list;
}

void add_account(struct a_list *list, struct account* newaccount)
{
	struct a_node *node = malloc(sizeof(struct a_node));
	node->a = newaccount;
	node->next = NULL;
	if(list->last == NULL) {
		list->last = node;
	} else {
		list->last->next = node;
		list->last = node;
	}
	if(list->first == NULL) {
		list->first = list->last;
	}
}

struct account *create_account(char *account_name, int balance)
{
	struct account *newaccount = malloc(sizeof(struct account));
	newaccount->a_name = malloc(sizeof(char)*(strlen(account_name)+1));
	strcpy(newaccount->a_name, account_name);
	newaccount->balance = balance;
	return newaccount;
}

int contains_account(struct a_list *list, char *name)
{
	struct a_node *cursor = list->first;
	if(cursor != NULL) {
		while(cursor != NULL) {
			if(strcmp(name,cursor->a->a_name) == 0)
				return 1;
			cursor = cursor->next;
		}
	}
	return 0;
}

void account_print(struct account *a)
{
	printf("%s:\t %d\n",a->a_name, a->balance);
}

void account_list_print(struct a_list *list)
{
	struct a_node *cursor = list->first;
	if(cursor != NULL) {
		while(cursor != NULL) {
			account_print(cursor->a);
			cursor = cursor->next;
		}
	}
}

struct account * account_get(struct a_list *list, char *name)
{	
	//printf("Getting account for %s\n", name);
	struct a_node *cursor = list->first;
	while(cursor != NULL) {
		//printf("checking %s\n", cursor->a->a_name);
		if(strncmp(name,cursor->a->a_name, strlen(cursor->a->a_name)) == 0)
			return cursor->a;
		cursor = cursor->next;
	}
	return NULL;
}

void set_balance(struct a_list *list, char *name, int value)
{
	struct account *a = account_get(list, name);
	if(value > 0)
		a->balance = value;
}

struct t_list* init_trans_list()
{
	struct t_list* list;
	list = malloc(sizeof(struct t_list));
	list->first = NULL;
	list->last = NULL;
	list->num = 0;
	return list;
}

void add_trans(struct t_list *list, struct trans_tok* tok)
{
	struct t_node *node = malloc(sizeof(struct t_node));
	node->tok = tok;
	node->next = NULL;
	if(list->last == NULL) {
		list->last = node;
	} else {
		list->last->next = node;
		list->last = node;
	}
	if(list->first == NULL) {
		list->first = list->last;
	}
}

int contains_trans_tok(struct t_list *list, struct trans_tok *tok)
{
	struct t_node *cursor = list->first;
	while(cursor != NULL) {
		if(trans_tok_equals(cursor->tok, tok))
			return 1;
		cursor = cursor->next;
	}
	return 0;
}

void trans_tok_list_print(struct t_list *list)
{
	struct t_node *cursor = list->first;
	if(cursor != NULL) {
		while(cursor != NULL) {
			printf("%s: SERIAL: %d VALUE: %d\n",cursor->tok->payer, cursor->tok->serial, cursor->tok->value);
			cursor = cursor->next;
		}
	}
}

int trans_tok_remove(struct t_list *list, struct trans_tok *tok)
{	
	struct t_node *cursor = list->first;
	if(cursor != NULL) {
		if(trans_tok_equals(tok, cursor->tok)) {
			list->first = list->first->next;
			return 1;
			//free(cursor); //TODO
		} else
			while(cursor->next != NULL) {
				if(trans_tok_equals(tok,cursor->next->tok) == 0) {
					cursor->next = cursor->next->next;
					//free(cursor) //TODO
					return 1;
				}
				cursor = cursor->next;
			}
	}
	return 0;
}
