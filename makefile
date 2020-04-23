
CC = gcc

CFLAGS = -std=gnu99 -g -lssl -lcrypto

all: hashing.o cryptography.o explorer

hashing.o: hashing.c
	$(CC) -g -c  hashing.c

cryptography.o: cryptography.c
	$(CC) -g -c cryptography.c

explorer: explorer.c
	$(CC) hashing.o cryptography.o explorer.c -o explorer $(CFLAGS) -w

clean:
	rm -f explorer hashing.o cryptography.o
