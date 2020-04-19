CC = gcc
CFLAGS = -g -lssl -lcrypto

all: 

hashing.o: hashing.c

	$(CC) -c  hashing.c

cryptography.o: cryptography.c

	$(CC) -g -c cryptography.c

test: test.c
	$(CC)  hashing.o cryptography.o test.c -o test $(CFLAGS)   

clean:
	rm -rf test hashing.o cryptography.o
