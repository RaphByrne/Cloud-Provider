#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "b_messages.h"

/*
 * Definitions for the account list and transaction token list
 * Both are just linked lists
 */

struct account {
	char *a_name;
	int balance;
};

struct a_node{
	struct account *a;
	struct a_node *next;
};

struct a_list{
	struct a_node *first;
	struct a_node *last;
	int num;
};

struct a_list *init_account_list();
void add_account(struct a_list *list, struct account* newaccount);
struct account *create_account(char *account_name, int balance);
int contains_account(struct a_list *list, char *name);
void account_print(struct account *a);
void account_list_print(struct a_list *list);
struct account * account_get(struct a_list *list, char *name);

struct t_node {
	struct trans_tok* tok;
	struct t_node *next;
};

struct t_list {
	struct t_node *first;
	struct t_node *last;
	int num;
};

struct t_list* init_trans_list();
void add_trans(struct t_list *list, struct trans_tok* tok);
int contains_trans_tok(struct t_list *list, struct trans_tok *tok);
void trans_tok_list_print(struct t_list *list);
int trans_tok_remove(struct t_list *list, struct trans_tok *tok);
