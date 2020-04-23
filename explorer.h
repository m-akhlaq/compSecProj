
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include "dirent.h"
#include "cryptography.h"


int addUser(char*, char*);
void list();
int getLine (char *, char *, size_t );
int checkCredentials(char* , char* );
int booya();
