#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#define HASH_SIZE 64 //512-bit
#define SALT_SIZE 16
#define PEPPER_SIZE 8
/*When displayed as a Hex string, the values are doubled because two hex digits are a byte*/

/*salt/hash pair for storage in Hex string form*/
typedef struct password {
	unsigned char* salt;
	unsigned char* hash;
}password;

/*Performes the SSL SHA-3-512 Hashing algorithm*/
unsigned char* doSHA512(unsigned char*);

/*Returns the contents of the file as a string*/
unsigned char* getFileData(int);

/*Returns the contents of the file as a string without the HMAC*/
unsigned char* getFileContentsWithoutHMAC(int);

/*Similar to getFileContentsWithoutHMAC, but removes the HMAC from a string*/
unsigned char* getStringWithoutHMAC(unsigned char*, unsigned);

/*Generates and returns a salt
NULL returned on error*/
unsigned char* genSalt();

/*Combines the specified salt, pepper, and password then returns the hash
The formula in this specific application is salt+password+pepper
returns NULL on error
specify arg2 as NULL if its a new password
specify the salt from the password file if you're loggin in*/
password* generatePasswordHash(char*, unsigned char*);

/*verifies the password and salt match the one on the file
1: matches
0: incorrect*/
int verifyPassword(char *, password*);

/*Generates and returns HMAC hash*/
unsigned char* generateHMAC(int);

/*Adds a HMAC to the beginning of a file for data integrity verification
Added to the end of the file
0: return success
1: return failure
2: bad file descriptor*/
int addHMACToFile(int);

/*Verifies the file contents with the HMAC, returns True on verified integrity and False on a hash-filetext mismatch*/
int verifyHMAC(int);

/*Similar to verifyHMAC but for a string, returns True on verified integrity and False on a hash-filetext mismatch*/
int verifyHMACString(unsigned char*, unsigned);
