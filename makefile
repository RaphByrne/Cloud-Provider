OPTS = -Wall -pedantic -std=c99 -g -D_POSIX_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE
LINKS = -lssl -lrpcsvc -lcrypt
UTIL = utilities.c

all : provider client bank

clean :
	rm *.o

provider : gensalt.o b_messages.o messages.o utilities.o provider.o
	gcc $(OPTS) -o provider/provider gensalt.o messages.o b_messages.o provider.o utilities.o $(LINKS)

client : messages.o b_messages.o utilities.o client.o
	gcc $(OPTS) -o client/client client.o messages.o b_messages.o utilities.o $(LINKS)

bank : bank.o utilities.o b_messages.o messages.o gensalt.o accounts.o
	gcc $(OPTS) -o bank/bank gensalt.o messages.o b_messages.o bank.o accounts.o utilities.o $(LINKS)

accounts.o : accounts.c accounts.h
	gcc $(OPTS) -c accounts.c $(LINKS)

bank.o : bank.c
	gcc $(OPTS) -c bank.c $(LINKS)

gensalt.o : gensalt.h gensalt.c
	gcc -Wall -c gensalt.c

provider.o : provider.c
	gcc $(OPTS) -c provider.c $(LINKS)

messages.o : messages.h messages.c
	gcc -g -std=c99 -c messages.c $(LINKS)

b_messages.o : b_messages.h b_messages.c
	gcc -g -std=c99 -c b_messages.c $(LINKS)

utilities.o : utilities.c utilities.h messages.h
	gcc $(OPTS) -c utilities.c $(LINKS)

client.o : client.c
	gcc $(OPTS) -c client.c $(LINKS)
