#include "hashing.h"


/*Hardcoded Pepper*/
unsigned const char pepper[PEPPER_SIZE + 1] = "4Ch*zmhP";

password * generatePasswordHash(char * pass, unsigned char * salt)
{
	password * pair = (password*)malloc(sizeof(password));
	if (pair == NULL)
		return NULL;
	int x;
	unsigned char* seasonedPassword = (unsigned char*)malloc(strlen(pass) + SALT_SIZE + 8 + 1);
	if (seasonedPassword == NULL)
		return NULL;

	if(salt == NULL) //new password
		salt = genSalt();
	else {

		//convert back from hex
		unsigned char buf[SALT_SIZE];
		for (x = 0; x < SALT_SIZE; x++) {
			unsigned char nibble1, nibble2;
			nibble1 = *(salt + (2 * x));
			if (nibble1 > 47 && nibble1 < 58) //number
				nibble1 -= 48;
			else //letter
				nibble1 -= (97 - 10);
			nibble2 = *(salt + (2 * x) + 1);
			if (nibble2 > 47 && nibble2 < 58) //number
				nibble2 -= 48;
			else //letter
				nibble2 -= (97 - 10);
			buf[x] = nibble1 << 4 | nibble2;
		}
		salt = buf;
	}

	if (salt == NULL)
		return NULL;
	memcpy(seasonedPassword, salt, SALT_SIZE);
	memcpy((unsigned char*)&seasonedPassword[SALT_SIZE], pass, strlen(pass));
	memcpy((unsigned char*)&seasonedPassword[SALT_SIZE + strlen(pass)], pepper, PEPPER_SIZE + 1);
	unsigned char* rawData = doSHA512(seasonedPassword);
	if(rawData == NULL)
		return NULL;
	pair->salt = (unsigned char*)malloc(SALT_SIZE * 2);
	for (x = 0; x < SALT_SIZE; x++)
		sprintf(pair->salt + (2 * x), "%02x", salt[x]);
	pair->hash = (unsigned char*)malloc(HASH_SIZE * 2);
	for (x = 0; x < HASH_SIZE; x++)
		sprintf(pair->hash + (2 * x), "%02x", rawData[x]);
	free(rawData);
	return pair;
}

unsigned char* doSHA512(unsigned char* string){
	EVP_MD_CTX * context;
	const EVP_MD * md;
	unsigned char* digest = (unsigned char*)malloc(HASH_SIZE);
	if (digest == NULL)
		return NULL;
	md = EVP_sha512();

	/*IMPORTANT NOTE: This code is designed to run on OpenSSL 1.0.2k which is present on the iLab machines. As of today there are versions beyond that
	which use different functions EVP_MD_CTX_new and EVP_MD_CTX_free
	If you upgrade openSSL these need to be changed*/

	context = EVP_MD_CTX_create();
	if (context != NULL) {
		if (EVP_DigestInit_ex(context, md, NULL)) {
			if (EVP_DigestUpdate(context, string, strlen(string))) {
				unsigned hashLen = 0;

				if (EVP_DigestFinal_ex(context, digest, &hashLen)) {
					EVP_MD_CTX_destroy(context);
					return digest;
				}
			}
		}
	}
	return NULL;
}

int verifyPassword(char * pass, password* savedHash)
{
	if (pass == NULL || savedHash == NULL)
		return 0;
	password* pair = generatePasswordHash(pass, savedHash->salt);
	if (pair == NULL)
		return 0;
	if (!strcmp(pair->hash, savedHash->hash)) {
		free(pair->hash);
		free(pair->salt);
		free(pair);
		return 1;
	}
	free(pair->hash);
	free(pair->salt);
	free(pair);
	return 0;
}

unsigned char * genSalt()
{
	unsigned char *salt = (unsigned char*)malloc(SALT_SIZE);
	if (salt == NULL)
		return NULL;
	int rand = RAND_bytes(salt, SALT_SIZE);
	if (rand == 0)
		return NULL; //error occurred
	return salt;
}

unsigned char* getFileData(int fileDescriptor) {
	if (fileDescriptor == -1)
		return NULL;
	int fileSize = lseek(fileDescriptor, 0, SEEK_END);
	lseek(fileDescriptor, 0, 0);
	char* fileContents = (char*)malloc(fileSize);
	if (fileContents == NULL)
		return NULL;
	int remaining = fileSize, offset = 0;
	while (remaining > 0) {
		int ret = read(fileDescriptor, fileContents + offset, remaining);
		if (ret < 0)
			return NULL;
		remaining -= ret;
		offset += ret;
	}
	return fileContents;
}

unsigned char * generateHMAC(int fileDescriptor)
{
	unsigned char * data = getFileData(fileDescriptor);
	if(data == NULL)
		return NULL;
	unsigned char * HMAC = doSHA512(data);
	free(data);
	if (HMAC == NULL)
		return NULL;
	unsigned char * hexDigest = (unsigned char*)malloc(HASH_SIZE * 2 + 1);
	int x;
	for (x = 0; x < HASH_SIZE; x++)
		sprintf(hexDigest + (2 * x), "%02x", HMAC[x]);
	return hexDigest;
}

int addHMACToFile(int fileDescriptor)
{
	unsigned char* data = getFileData(fileDescriptor);
	if (data == NULL)
		return 1;
	int fileSize = lseek(fileDescriptor, 0, SEEK_END);
	int remaining = HASH_SIZE*2, offset = 0;
	unsigned char * HMAC = generateHMAC(fileDescriptor);
	if (HMAC == NULL)
		return 1;
	while (remaining > 0) {
		int ret = write(fileDescriptor, HMAC + offset, remaining);
		if (ret < 0)
			return 2;
		remaining -= ret;
		offset += ret;
	}

	return 0;
}

unsigned char* getFileContentsWithoutHMAC(int fileDescriptor) {
	/*HASH_SIZE *2 because its written has hex*/
	unsigned char* data = getFileData(fileDescriptor); //with hash
	if (data == NULL)
		return 0;
	unsigned fileSize = lseek(fileDescriptor, 0, SEEK_END);
	unsigned char* fileData = getStringWithoutHMAC(data, fileSize);
	free(data);
	return fileData;
}

unsigned char * getStringWithoutHMAC(unsigned char * data, unsigned size){
	unsigned char* fileData = (unsigned char*)malloc(size - HASH_SIZE * 2); //without hash
	memcpy(fileData, data, size - HASH_SIZE * 2);
	return fileData;
}

int verifyHMAC(int fileDescriptor)
{
	unsigned char* data = getFileData(fileDescriptor); //with hash
	unsigned fileSize = lseek(fileDescriptor, 0, SEEK_END);
	if (verifyHMACString(data, fileSize)) {
		free(data);
		return 1;
	}
	return 0;
}

int verifyHMACString(unsigned char* withHash, unsigned size){
	unsigned char* noHash = getStringWithoutHMAC(withHash, size);
	unsigned char* newHMAC = doSHA512(noHash);
	unsigned char * hexDigest = (unsigned char*)malloc(HASH_SIZE * 2 + 1);
	int x;
	for (x = 0; x < HASH_SIZE; x++)
		sprintf(hexDigest + (2 * x), "%02x", newHMAC[x]);

	unsigned char oldHMAC[HASH_SIZE * 2];
	memcpy(oldHMAC, withHash + (size - HASH_SIZE * 2), HASH_SIZE * 2);
	for (x = 0; x < HASH_SIZE * 2; x++)
		if (oldHMAC[x] != hexDigest[x]) {
			free(hexDigest);
			free(newHMAC);
			free(noHash);
			return 0;
		}
	free(hexDigest);
	free(newHMAC);
	free(noHash);
	return 1;
}
