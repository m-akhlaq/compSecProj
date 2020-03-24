#include<stdlib.h>
#include <stdio.h>
#include<ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#define OK       0
#define NO_INPUT 1
#define TOO_LONG 2
char* ROOTDIR = "./root/";
char* PROTECTEDDIR =  "/./";
char* USERS = "users.txt";

int main(int argc, char const *argv[]) {

  // Loads in user by their username
  if (argc != 3){
    printf("Please run the program with username password\n");
    return 1;
  }
  int response = checkCredentials(argv[1],argv[2]);

  if (response == 0){
    printf("There is no user with this information. Please try again\n");
    return 1;
  }else{
    printf("Welcome %s\n",argv[1]);
  }

  int rc;

  while(1){

    //the buffer which contains the command
    char buff[50];
    //this function get the command and makes sure everything is fine
    rc = getLine ("Command>  ", buff, sizeof(buff));
    if (rc == NO_INPUT) {
        continue;
    }

    if (rc == TOO_LONG) {
        printf ("Input too long [%s]\n", buff);
        continue;
    }

    //we copy the command buffer and split it by space
    char bufferCpy[50];
    char* pch = (char*)malloc(sizeof(char*)*100);
    strcpy(bufferCpy,buff);
    pch = strtok (bufferCpy," ");
    while (pch != NULL){

      //this is where we check for commands
      if (strcmp(pch, "ls") == 0){
          list();
      }

    //this just goes through the string, space by space
    pch = strtok (NULL, " ");

    }


  }
  return 0;
}


 int getLine (char *prmpt, char *buff, size_t sz) {
    int ch, extra;

    // Get line with buffer overrun protection.
    if (prmpt != NULL) {
        printf ("%s", prmpt);
        fflush (stdout);
    }
    if (fgets (buff, sz, stdin) == NULL)
        return NO_INPUT;

    // If it was too long, there'll be no newline. In that case, we flush
    // to end of line so that excess doesn't affect the next call.
    if (buff[strlen(buff)-1] != '\n') {
        extra = 0;
        while (((ch = getchar()) != '\n') && (ch != EOF))
            extra = 1;
        return (extra == 1) ? TOO_LONG : OK;
    }

    // Otherwise remove newline and give string back to caller.
    buff[strlen(buff)-1] = '\0';
    return OK;
}

  void list(){
    struct dirent *de;
    DIR *dr = opendir(ROOTDIR);
    if (dr == NULL) {
       printf("Could not open current directory" );
    }

    while ((de = readdir(dr)) != NULL)
           printf("%s\n", de->d_name);

    closedir(dr);
  }

    int checkCredentials(char* username, char* password){
      char * buffer = 0;
      long length;
      FILE * f = fopen (USERS, "rb");

      if (f){
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        buffer = malloc (length+1);
        buffer[length-1] = '\0';
        if (buffer){
          fread (buffer, 1, length, f);
        }
        fclose (f);
      }

      if (buffer){
        char bufferCpy[length+1];
        char* commaSeperatedValues = (char*)malloc(sizeof(char*)*(length+1));
        strcpy(bufferCpy,buffer);
        char *end_str;
        char *token = strtok_r(bufferCpy, ",", &end_str);
        while (token != NULL){
          char *end_token;
          char *token2 = strtok_r(token, ":", &end_token);
          int counter = 0;
          int usernameFound = 0;
          while (token2 != NULL){
            if (counter == 0 && strcmp(username,token2) == 0){
              usernameFound= 1;
            }
            if (counter == 1 && usernameFound == 1 && strcmp(password,token2) == 0){
              //both username and password match. return 1;
              return 1;
            }
            token2 = strtok_r(NULL, ":", &end_token);
            counter++;
          }
          token = strtok_r(NULL, ",", &end_str);
        }

        return 0;




      }

  }
