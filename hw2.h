#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<openssl/md5.h>

#define STREAM  "stream"
#define ENCRYPT "encrypt"
#define MERGE   "merge"
#define DECRYPT "decrypt"

#define WHITE   0
#define BLACK   1

/*
 * Table for encrypting black and white pixels into share files
 */
int white_share_1[2][4] = { {BLACK, WHITE, WHITE, BLACK}, {WHITE, BLACK, BLACK, WHITE} };
int black_share_1[2][4] = { {BLACK, WHITE, WHITE, BLACK}, {WHITE, BLACK, BLACK, WHITE} };
int white_share_2[2][4] = { {BLACK, WHITE, WHITE, BLACK}, {WHITE, BLACK, BLACK, WHITE} };
int black_share_2[2][4] = { {WHITE, BLACK, BLACK, WHITE}, {BLACK, WHITE, WHITE, BLACK} };

void getStreamCipherByte(char* , char* );
void printSimpleStreamCipher(char* , int);
int getMSB(unsigned char ch);
void encrypt(char *, char *, char *, int);
void merge(char *, char *);
void decrypt(char *);
