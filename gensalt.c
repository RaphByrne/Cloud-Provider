/*
 * gensalt.c -- generate random salt for crypt()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "gensalt.h"

/* both lexer and parser states are listed here */
enum {
	STATE_START,		/* idle state */
	STATE_IN_GENERATOR,	/* between [ and ] */
	STATE_SAW_FIRST,	/* saw first char of possible range */
	STATE_SAW_THROUGH,	/* saw the - in a range */
	STATE_SAW_GENERATOR,	/* saw the ] of a generator */
	STATE_IN_COUNT,		/* saw {, accumulating count */
	STATE_SAW_COUNT,	/* saw } */
	STATE_SAW_ESCAPE,	/* for gettok() */
	STATE_IN_OCTAL,		/* for gettok() */
	STATE_EOF
};

/* token types returned by lexer */
enum {
	TOK_ERR,		/* error in lexer */
	TOK_EOF,
	TOK_GEN_START,		/* [ */
	TOK_GEN_END,		/* ] */
	TOK_THROUGH,		/* - */
	TOK_COUNT_START,	/* { */
	TOK_COUNT_END,		/* } */
	TOK_LITERAL,		/* a normal character */
	TOK_EMPTY		/* empty pushback indicator */
};

enum {
	STRFIRST = 100		/* initial size of dynamic strings */
};

/* output of lexer is a token */
struct token {
	int type;
	int val;
};

/* dynamic string */
struct str {
	char *buf;		/* malloc()'ed buffer */
	int size;		/* allocated size */
	int len;		/* length of string */
};

/* parser pushback buffer */
static struct token pushback = { TOK_EMPTY, 0 };

/* current input buffer; never written to */
static char *input;

/* points to next char to be read from input */
static char *ptr;

/* current random character selector; returns a random number [0..n-1] */
static int (*pick)(int);

/* error message buffer */
static char *msg = "";

static struct str range = { NULL, 0, 0 };
static struct str salt = { NULL, 0, 0 };

/* clear a dynamic string */
static void
strclear(struct str *sp)
{
	sp->len = 0;
}

/* append char to dynamic string */
static int
append(struct str *sp, int c)
{
	char *p;

	if (sp->buf == NULL) {
		if ((sp->buf = malloc(STRFIRST)) == NULL)
			return 0;
		sp->size = STRFIRST;
		sp->len = 0;
	} else if (sp->len >= sp->size) {
		if ((p = realloc(sp->buf, 2 * sp->size)) == NULL)
			return 0;
		sp->buf = p;
		sp->size *= 2;
	}
	sp->buf[sp->len++] = c;
	return 1;
}

/* default random character selector */
static int
pick_default(int n)
{
	return rand() % n;
}


/* true if c is an octal digit */
static int
isoct(int c)
{
	switch (c) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
		return 1;
	default:
		return 0;
	}
}


/* get next char from input */
static int
getnext(void)
{
	return (*ptr == '\0') ? '\0' : *ptr++;
}


/* move input pointer back one character */
static int
unget(void)
{
	if (ptr == input) {
		msg = "too many chars pushed back";
		return 0;
	}
	--ptr;
	return 1;
}


/* read next token from input, returns token type */
static int
gettok(struct token *t)
{
	int state;
	int c;
	int digits_seen = 0;	/* count octal digits in \nnn */
	
	if (pushback.type != TOK_EMPTY) {
		t->type = pushback.type;
		t->val = pushback.val;
		pushback.type = TOK_EMPTY;
		return t->type;
	}

	state = STATE_START;
	for (;;) {
		c = getnext();

		switch (state) {
		case STATE_START:
			if (c == '\0')
				return t->type = TOK_EOF;
			if (c == '\\')
				state = STATE_SAW_ESCAPE;
			else if (c == '[') {
				t->val = '[';
				return t->type = TOK_GEN_START;
			} else if (c == '-') {
				t->val = '-';
				return t->type = TOK_THROUGH;
			} else if (c == ']') {
				t->val = ']';
				return t->type = TOK_GEN_END;
			} else if (c == '{') {
				t->val = '{';
				return t->type = TOK_COUNT_START;
			} else if (c == '}') {
				t->val = '}';
				return t->type = TOK_COUNT_END;
			} else {
				t->val = c;
				return t->type = TOK_LITERAL;
			}
			break;

		case STATE_SAW_ESCAPE:
			if (c == '\0') {
				t->val = '\\';
				return t->type = TOK_LITERAL;
			}
			if (c == '0' || c == '1' || c == '2' || c == '3') {
				t->val = c - '0';
				digits_seen = 1;
				state = STATE_IN_OCTAL;
			} else {
				/* might as well make it ok to escape
				 * anything
				 */
				t->val = c;
				return t->type = TOK_LITERAL;
			}
			break;

		case STATE_IN_OCTAL:
			if (c == '\0') {
				/* t->val has already been built-up */
				return t->type = TOK_LITERAL;
			}
			if (!isoct(c)) {
				if (!unget())
					return t->type = TOK_ERR;
				return t->type = TOK_LITERAL;
			}
			if (digits_seen == 3) {
				if (!unget())
					return t->type = TOK_ERR;
				/* t->val has already been built up */
				return t->type = TOK_LITERAL;
			}
			++digits_seen;
			t->val = t->val * 8 + c - '0';
			break;

		default:
			msg = "gettok: can't happen";
			return TOK_ERR;
			break;
		}
	}
}


/* push token back on input stream */
static int
ungettok(struct token *t)
{
	if (pushback.type != TOK_EMPTY) {
		msg = "too many tokens pushed back";
		return 0;
	}
	pushback.type = t->type;
	pushback.val = t->val;
	return 1;
}


char *
gensalt(char *template, int (*pick_f)(int))
{
	struct token tok;
	int state = STATE_START;
	int first = 0;
	int last = 0;
	int count = 0;
	int i;

        input = (template == NULL) ? "[A-Za-z0-9./]{2}" : template;
        ptr = input;
        pushback.type = TOK_EMPTY;
        pushback.val = 0;
        pick = (pick_f == NULL) ? pick_default : pick_f;
	strclear(&range);
	strclear(&salt);
	msg = "";

	for (;;) {
		if (gettok(&tok) == TOK_ERR)
			return NULL;

		switch (state) {
		case STATE_START:
			if (tok.type == TOK_EOF) {
				if (append(&salt, '\0'))
					return salt.buf;
				else {
					msg = "out of memory";
					return NULL;
				}
			}
			/* cheat and allow {, } and ] outside of generators */
			if (tok.type == TOK_LITERAL ||
			    tok.type == TOK_COUNT_START ||
			    tok.type == TOK_COUNT_END ||
			    tok.type == TOK_GEN_END ||
			    tok.type == TOK_THROUGH) {
				if (!append(&salt, tok.val)) {
					msg = "out of memory";
					return NULL;
				}
			} else if (tok.type == TOK_GEN_START) {
				strclear(&range);
				state = STATE_IN_GENERATOR;
			} else {
				msg = "expected literal or '['";
				return NULL;
			}
			break;

		case STATE_IN_GENERATOR:
			if (tok.type == TOK_GEN_END)
				state = STATE_SAW_GENERATOR;
			else if (tok.type == TOK_LITERAL
			    || tok.type == TOK_GEN_START
			    || tok.type == TOK_THROUGH
			    || tok.type == TOK_COUNT_START
			    || tok.type == TOK_COUNT_END) {
				first = tok.val;
				state = STATE_SAW_FIRST;
			} else {
				msg = "expected literal or ']'";
				return NULL;
			}
			break;

		case STATE_SAW_FIRST:
			if (tok.type == TOK_THROUGH)
				state = STATE_SAW_THROUGH;
			else if (!ungettok(&tok))
				return NULL;
			else if (!append(&range, first)) {
				msg = "out of memory";
				return NULL;
			} else
				state = STATE_IN_GENERATOR;
			break;

		case STATE_SAW_THROUGH:
			if (tok.type == TOK_EOF
			 || tok.type == TOK_GEN_END) {
				msg = "expected end of range";
				return NULL;
			}
			last = tok.val;
			if (last < first) {
				msg = "backwards range";
				return NULL;
			}
			for (i = first; i <= last; ++i)
				if (!append(&range, i)) {
					msg = "out of memory";
					return NULL;
				}
			state = STATE_IN_GENERATOR;
			break;

		case STATE_SAW_GENERATOR:
			if (tok.type == TOK_COUNT_START) {
				count = 0;
				state = STATE_IN_COUNT;
			} else if (!ungettok(&tok))
				return NULL;
			else {
				count = 1;
				state = STATE_SAW_COUNT;
			}
			break;

		case STATE_IN_COUNT:
			if (tok.type == TOK_COUNT_END)
				state = STATE_SAW_COUNT;
			else if (tok.type == TOK_LITERAL && isdigit(tok.val))
				count = count * 10 + tok.val - '0';
			else {
				msg = "expected digit or '}'";
				return NULL;
			}
			break;

		case STATE_SAW_COUNT:
			if (!ungettok(&tok))
				return NULL;
			if (range.len > 0)
				for (i = 0; i < count; ++i)
					if (!append(&salt, range.buf[(pick)(range.len)])) {
						msg = "out of memory";
						return NULL;
					}
			state = STATE_START;
			break;

		default:
			msg = "can't happen";
			return NULL;
			break;
		}
	}
}


/* return error message */
char *
gensalt_msg(void)
{
	return msg;
}
