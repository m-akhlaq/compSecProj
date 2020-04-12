CC = gcc
CFLAGS = -g -lssl -lcrypto

all: 

hashing.o: hashing.c

	$(CC) -c  hashing.c

test: test.c
	$(CC)  hashing.o test.c -o test $(CFLAGS)   

clean:
	rm -rf test hashing.o
