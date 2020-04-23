#include <stdio.h>
#include "cryptography.h"

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
	fd = open("testfile.txt", O_RDWR);
	addHMACToFile(fd);
	if (encryptToFile(fd) == 1) {
		printf("testfile.txt Encrypted!\n");
		//Enable these to simulate modifying the file
		//lseek(fd, -5,SEEK_END);
		//lseek(fd, 5, SEEK_SET);
		//write(fd, "G", 1);
		crypto* data = genCryptoFromFile(fd);
		unsigned char* dec = decryptString(data);
		if (dec != NULL) {
			printf("testfile.txt Decrypted!\n");
			printf("%s\n", getStringWithoutHMAC(dec, strlen(dec)));
			printf("HMAC Valid: %d\n", verifyHMACString(dec, strlen(dec)));
		}
	}
	close(fd);
	fd = open("testfile2.txt", O_RDWR);
	addHMACToFile(fd);
	if (encryptToFile(fd) == 1) {
		printf("testfile2.txt Encrypted!\n");
		close(fd);
		fd = open("testfile2.txt", O_RDWR);
		crypto* data = genCryptoFromFile(fd);
		unsigned char* dec = decryptString(data);
		if (dec != NULL) {
			printf("testfile2.txt Decrypted!\n");
			printf("%s\n", getStringWithoutHMAC(dec, strlen(dec)));
			printf("HMAC Valid: %d\n", verifyHMACString(dec, strlen(dec)));
		}
	}
	close(fd);
	return 0;
}
