#include <stdio.h>
#include "hashing.h"

int main(){
	password* pass = generatePasswordHash("pass", NULL);
	printf("Password: pass\nPassword hash: ");
	printf("%s\n", pass->hash);
	printf("Salt: ");
	printf("%s\n", pass->salt);
	printf("Test Login Success (pass): %d", verifyPassword("pass", pass));
	printf("\nTest Login Failure (password): %d", verifyPassword("password", pass));
	printf("\nTest Login Failure (p@ss): %d", verifyPassword("p@ss", pass));
	printf("\nTest Login Success (pass): %d", verifyPassword("pass", pass));

	int fd = open("testfile.txt", O_RDWR);
	addHMACToFile(fd);
	printf("\nCheck HMAC on unmodified file (testfile.txt): %d\n", verifyHMAC(fd));
	write(fd, "F", 1);
	printf("Check HMAC on modified file (testfile.txt): %d\n", verifyHMAC(fd));
	close(fd);
	fd = open("testfile2.txt", O_RDWR);
	addHMACToFile(fd);
	printf("Check HMAC on unmodified file (testfile2.txt): %d\n", verifyHMAC(fd));
	write(fd, " ", 1);
	printf("Check HMAC on modified file (testfile2.txt): %d\n", verifyHMAC(fd));
	close(fd);
	return 0;
}
