#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include "hashing.h"

#define KEY_SIZE 32 //256-bit = 32-byte
#define IV_SIZE 16 //128-bit = 16-byte
#define AES_BLOCK_SIZE 32

/*
	For the purposes of this program, the IV will function like a salt, and the key like a pepper
*/

typedef struct fileCrypto {
	unsigned char* IV; //Functions like a salt
	unsigned char* ciphertext;
	unsigned ct_len;
}crypto;

/*add padding to the last block*/
unsigned char* addPadding(unsigned char*, unsigned*);

/*remove padding from the last block*/
unsigned char* removePadding(unsigned char*, unsigned);

/*Generates and returns a random string to be used by initialization vector and encryption key*/
unsigned char* genRandBytes(int);

/*Given a string and an encryption key, it will return the crypto struct which is a AES-cbc ciphertext and the initialization vector*/
crypto* encryptString(unsigned char*, unsigned);

/*Given an AES-cbc encrypted string and an encryption key, it will return the decrypted string*/
unsigned char* decryptString(crypto*);

/*Given a file descriptor and an encryption key, it will encrypt a file and write back the encrypted data
true for success
false for failure (like permission issues)
SHOULD BE OPENED WITH RW*/
int encryptToFile(int);

/*creates a crypto structure based on the ciphertext file*/
crypto* genCryptoFromFile(int);

/*decryptToFile like function is not implemented as it is not recommended, then a superuser could inspect the plaintext while the user reads, just use the string itself*/