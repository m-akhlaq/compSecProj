.POSIX:
.SUFFIXES:

CFLAGS = -std=gnu99

all: explorer
explorer: explorer.c
	$(CC) explorer.c -o explorer $(CFLAGS)
clean:
	rm -f explorer
