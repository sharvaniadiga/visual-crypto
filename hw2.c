#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<openssl/md5.h>

#include "hw2.h"

/*
 * Function to get stream cipher
 */
void getStreamCipherByte(char* passphrase, char* md5_buf)
{
	static int firstTime = 1;
	static int i    = 0;
	if(firstTime) {
		MD5((unsigned char *)passphrase, strlen(passphrase), (unsigned char*)md5_buf);
		firstTime = 0;
	} 
	int len  = strlen(passphrase) + 2 + MD5_DIGEST_LENGTH;
	char *s  = malloc(len + 1);
	sprintf(&s[MD5_DIGEST_LENGTH], "%02d%s", i, passphrase);
	memcpy(s, md5_buf, MD5_DIGEST_LENGTH);
	MD5((unsigned char*)s, len, (unsigned char*)md5_buf);
	if (++i == 100) i = 0;
	free(s);
	return;
}

/*
 * Function to print 'outlen' bytes of stream cipher
 */
void printSimpleStreamCipher(char* passphrase, int outlen)
{
	char md5_buf[MD5_DIGEST_LENGTH];
	int plen = 0;
	int blen = 0;
	while(plen < outlen) {
		getStreamCipherByte(passphrase, md5_buf);
		blen = sizeof(md5_buf) >> 1;
		if((outlen - plen) < blen)
			blen = outlen - plen;
		fwrite(md5_buf, 1, blen, stdout);
		plen += 8;
	}
	return;
}

/*
 * Function to open file - filename
 */
FILE* openFile(char* filename)
{
	FILE* fp = NULL;
	if(filename == NULL)
	{
		fp = stdin;
	} else {
		fp = fopen(filename, "r");
	}
	if(fp == NULL)
	{
		perror("ERROR");
		exit(1);    
	}
	return fp;
}

/*
 * Begin code I did not write
 * The following code was obtained from http://stackoverflow.com/questions/2372813/reading-one-line-at-a-time-in-c
 */
int readLine(FILE *fp, char *buffer, size_t len)
{
	int i;
	memset(buffer, 0, len);
	for(i = 0; i < len; i++) {
		int ch = fgetc(fp);
		if(!feof(fp)) {
			if(ch == '\n') {
				buffer[i] = '\0';
				return i + 1;
			}
			else
				buffer[i] = ch;
		} else {
			return -1;
		}
	}
	return -1;
}
/*
 * End code I did not write
 */

/*
 * Function to get Most Significant bit of 'ch'
 */
int getMSB(unsigned char ch)
{
	int mask = 1 << (8 - 1);
	return ((ch & mask) >> (8 - 1));
}

/*
 * Function to write PBM file headers
 */
void writeHeaders(FILE *fp, int width, int height)
{
	fwrite("P4", 1, 2, fp);
	fprintf(fp, "\n%d %d\n", width, height);
	return;
}

/*
 * Function to create share files
 */
FILE* createAndWriteHeaders(char *name, int share_i, int width, int height)
{
	FILE* fp = NULL;
	char str[sizeof(name) + 7];
	strcpy(str, name);
	if(share_i == 1)
		fp = fopen(strcat(str, ".1.pbm\0"), "wb");
	else
		fp = fopen(strcat(str, ".2.pbm\0"), "wb");
	if(fp == NULL)
		return fp;
	writeHeaders(fp, width, height);
	return fp;
}

/*
 * Function to update 'key_ch' if required
 */
void updateKeyChar(char* passphrase, char* md5_buf, int* md5_i, unsigned char* key_ch)
{

	if(*md5_i == (MD5_DIGEST_LENGTH / 2)) { // TODO 
		getStreamCipherByte(passphrase, md5_buf);
		*md5_i = 0;
	}
	if(*key_ch == 0) {
		*key_ch = md5_buf[*md5_i];
		*md5_i += 1;
	}
}

/*
 * Function to get entry from the table based on 'pixel', 'key' and 'share_i'
 */
int* getAppropriateShareArray(int pixel, int key, int share_i)
{
	int *share_array;
	if(pixel == WHITE) { // white pixel
		if(share_i == 1)
			share_array = white_share_1[key];
		else
			share_array = white_share_2[key];
	} else { // black pixel
		if(share_i == 1)
			share_array = black_share_1[key];
		else
			share_array = black_share_2[key];
	}
	return share_array;
}

/*
 * Function to update lines with output characters obtained after encryption
 */
void putCharactersToLines(unsigned char *out_ch1, unsigned char *out_ch2, int *outch_count, unsigned char *line1, unsigned char *line2, int *line_i)
{
	*(line1 + *line_i) = *out_ch1;
	*(line2 + *line_i) = *out_ch2;
	*line_i += 1;
	*out_ch1 = 0;
	*out_ch2 = 0;
	*outch_count = 0;
	return;
}

void buildOutputChar(int curbit, int key, int share_i, unsigned char* out_ch1, unsigned char *out_ch2, int *outch_count, unsigned char *line1, unsigned char * line2, int* line_i)
{
	int* share_array = getAppropriateShareArray(curbit, key, share_i);
	*out_ch1 = *out_ch1 << 1 | share_array[0];
	*out_ch2 = *out_ch2 << 1 | share_array[2];
	*outch_count += 1;
	*out_ch1 = *out_ch1 << 1 | share_array[1];
	*out_ch2 = *out_ch2 << 1 | share_array[3];
	*outch_count += 1;
	return;
}

/*
 * Function to encrypt
 */
void encrypt(char *passphrase, char *name, char *inputfile, int share_i)
{
	FILE* fp = openFile(inputfile);
	FILE* outfp = NULL;
	FILE* outfp2 = NULL;
	char line[15];
	int nbytes = readLine(fp, line, 15);
	if(nbytes == 0) {
		fprintf(stderr, "%s\n", "Error in reading a line from file");
		exit(1);
	}
	if(strncmp(line, "P4", 2) != 0)
	{
		fprintf(stderr, "%s\n", "Error in input file line 1");
		exit(1);
	}
	nbytes = readLine(fp, line, 15);
	char *pline = line;
	int width = strtol(line, &pline, 10);
	int height = strtol(pline, NULL, 10);
	int i = 0, j = 0;
	int outbwidth = 0;
	if(((2 * width) % 8) == 0)
		outbwidth = (2 * width) / 8;
	else
		outbwidth = ((2 * width) / 8) + 1;
	int line_i = 0;
	int o2line_i = 0;
	int curbit;
	char md5_buf[MD5_DIGEST_LENGTH];
	int md5_i = 0;
	getStreamCipherByte(passphrase, md5_buf);
	unsigned char key_ch = 0;
	int key;
	char cur_ch = 0;
	unsigned char out_ch1 = 0;
	unsigned char out_ch2 = 0;
	int outch_count = 0;
	unsigned char out2_ch1 = 0;
	unsigned char out2_ch2 = 0;
	int outch2_count = 0;
	int kbits_used  = 0;
	unsigned char line1[outbwidth + 1], line2[outbwidth + 1];
	line1[outbwidth] = '\0';
	line2[outbwidth] = '\0';
	unsigned char o2line1[outbwidth + 1], o2line2[outbwidth + 1];
	o2line1[outbwidth] = '\0';
	o2line2[outbwidth] = '\0';
	for(i = 0; i < height; i++) {
		for(j = 0; j < width; j++) {
			if(j % 8 == 0) {
				unsigned char temp[2];
				temp[1] = '\0';
				//if((nbytes = fread(temp, 1, 1, fp)) == 0)
					//break;
				fread(temp, 1, 1, fp);
				cur_ch = temp[0];
				//cur_ch = fgetc(fp);
			}
			curbit = getMSB(cur_ch);
			cur_ch = cur_ch << 1;
			if((kbits_used % 8) == 0)
				updateKeyChar(passphrase, md5_buf, &md5_i, &key_ch);
			key = getMSB(key_ch);
			key_ch = key_ch << 1;
			kbits_used++;
			buildOutputChar(curbit, key, 1, &out_ch1, &out_ch2, &outch_count, line1, line2, &line_i);
			if(outch_count == 8) {
				putCharactersToLines(&out_ch1, &out_ch2, &outch_count, line1, line2, &line_i);			
			}
			buildOutputChar(curbit, key, 2, &out2_ch1, &out2_ch2, &outch2_count, o2line1, o2line2, &o2line_i);
			if(outch2_count == 8) {
				putCharactersToLines(&out2_ch1, &out2_ch2, &outch2_count, o2line1, o2line2, &o2line_i);			
			}
		}
		int rem = 8 - (2  * (j % 8));
		out_ch1 = out_ch1 << rem;
		out_ch2 = out_ch2 << rem;
		putCharactersToLines(&out_ch1, &out_ch2, &outch_count, line1, line2, &line_i);			
		if(outfp == NULL)
			outfp = createAndWriteHeaders(name, 1, 2 * width, 2 * height);
		fwrite(line1, 1, outbwidth, outfp);
		fwrite(line2, 1, outbwidth, outfp);
		line_i = 0;
		out2_ch1 = out2_ch1 << rem;
		out2_ch2 = out2_ch2 << rem;
		putCharactersToLines(&out2_ch1, &out2_ch2, &outch2_count, o2line1, o2line2, &o2line_i);			
		if(outfp2 == NULL)
			outfp2 = createAndWriteHeaders(name, 2, 2 * width, 2 * height);
		fwrite(o2line1, 1, outbwidth, outfp2);
		fwrite(o2line2, 1, outbwidth, outfp2);
		o2line_i = 0;
		memset(line1, 0, sizeof(line1));
		memset(line2, 0, sizeof(line2));
		memset(o2line1, 0, sizeof(o2line1));
		memset(o2line2, 0, sizeof(o2line2));
	}
	if(outfp)
		fclose(outfp);
	fclose(fp);
	return;
}

/* 
 * Function to merge
 */
void merge(char *pbmfile1, char *pbmfile2)
{
	FILE *fp1 = fopen(pbmfile1, "r");
	if(fp1 == NULL) {
		fprintf(stderr, "%s\n", "Unable to open file 1");
		exit(1);
	}
	char line1[15];
	int nbytes = readLine(fp1, line1, 3);
	if(nbytes == 0) {
		fprintf(stderr, "%s\n", "Error in reading a line from file1");
		exit(1);
	}
	if(strncmp(line1, "P4", 2) != 0)
	{
		fprintf(stderr, "%s\n", "Error in input file 1: line 1");
		fclose(fp1);
		exit(1);
	}
	nbytes = readLine(fp1, line1, 15);
	char *pline1 = line1;
	int w1 = strtol(line1, &pline1, 10);
	int h1 = strtol(pline1, NULL, 10);
	FILE *fp2 = fopen(pbmfile2, "r");
	if(fp2 == NULL) {
		fclose(fp1);
		fprintf(stderr, "%s\n", "Unable to open file 2");
		exit(1);
	}
	char line2[15];
	nbytes = readLine(fp2, line2, 15);
	if(strncmp(line2, "P4", 2) != 0)
	{
		fprintf(stderr, "%s\n", "Error in input file 2: line 1");
		fclose(fp1);
		fclose(fp2);
		exit(1);
	}
	nbytes = readLine(fp2, line2, 15);
	char *pline2 = line2;
	int w2 = strtol(line2, &pline2, 10);
	int h2 = strtol(pline2, NULL, 10);
	if((w1 != w2) || (h1 != h2)) {
		fprintf(stderr, "%s\n", "Heights and widths of files to be merged differ");
		exit(1);
	}
	FILE *outfp = stdout;
	writeHeaders(outfp, w1, h1);
	int bwidth = 0;
	if(((w1) % 8) == 0)
		bwidth = (w1) / 8;
	else
		bwidth = ((w1) / 8) + 1;
	int i = 0;
	unsigned char outline[bwidth + 1];
	outline[bwidth] = '\0';
	int k = 0;
	for(k = 0; k < h1; k++) {
		memset(outline, 0, bwidth);
		for(i = 0; i < bwidth; i++) {
			unsigned char ch1 = fgetc(fp1);
			unsigned char ch2 = fgetc(fp2);
			int j = 0;
			unsigned char outch = 0;
			for(j = 0; j < 8; j++) {
				outch = outch << 1 | (getMSB(ch1) | getMSB(ch2));
				ch1 = ch1 << 1;
				ch2 = ch2 << 1;
			}
			outline[i] = outch;
		}
		fwrite(outline, 1, bwidth, outfp);
	}
	fclose(fp2);
	fclose(fp1);
	return;
}

/* 
 * Function to Decrypt 
 */
void decrypt(char *filename)
{
	FILE *fp = openFile(filename);
	if(fp == NULL) {
		fprintf(stderr, "%s\n", "Unable to open file 1");
		exit(1);
	}
	char line[15];
	int nbytes = readLine(fp, line, 15);
	if(nbytes == 0) {
		fprintf(stderr, "%s\n", "Error in reading a line form file");
		exit(1);
	}
	if(strncmp(line, "P4", 2) != 0)
	{
		fprintf(stderr, "%s\n", "Error in input file: line 1");
		exit(1);
	}
	nbytes = readLine(fp, line, 15);
	char *pline = line;
	int width = strtol(line, &pline, 10);
	int height = strtol(pline, NULL, 10);
	FILE *outfp = stdout;
	writeHeaders(outfp, width / 2, height / 2);
	int bwidth = 0;
	if(((width / 2) % 8) == 0)
		bwidth = (width / 2) / 8;
	else
		bwidth = ((width / 2) / 8) + 1;
	unsigned char outline[bwidth + 1];
	outline[bwidth] = '\0';
	int out_i = 0;
	int in_bwidth = 0;
	if((width % 8) == 0) {
		in_bwidth = width / 8;
	} else {
		in_bwidth = (width / 8) + 1;
	}
	unsigned char in_line[in_bwidth + 1];
	in_line[in_bwidth] = '\0';
	unsigned char outch = 0;
	int outch_count = 0;
	int i = 0;
	for(i = 0; i < (height / 2); i++) {
		fread(in_line, 1, in_bwidth, fp);
		//fgets(in_line, in_bwidth, fp);
		int j = 0;
		for(j = 0; j < in_bwidth; j++) {
			unsigned char ch = in_line[j];
			int k = 0;
			while(k < 8) {
				int key1 = getMSB(ch);
				ch = ch << 1;
				k++;
				int key2 = getMSB(ch);
				ch = ch << 1;
				k++;
				if((key1 == BLACK) && (key2 == BLACK)) {
					outch = outch << 1 | BLACK;
					outch_count++;
				} else if(((key1  == WHITE) && (key2 == BLACK)) || ((key1 == BLACK) && (key2 == WHITE))){
					outch = outch << 1 | WHITE;
					outch_count++;
				} else {
					break;
				}
			}
			if(k != 8) {
				outch = outch << (8 - outch_count);
				outch_count = 8;
			} 
			if(outch_count == 8) {
				outline[out_i++] = outch;
				if((out_i % bwidth) == 0) {
					fwrite(outline, 1, bwidth, outfp);
					memset(outline, 0, bwidth);
					out_i = 0;
				}
				outch = 0;
				outch_count = 0;
			}
		}
		if(((width % 8) == 0) && (outch_count != 8)) {
			outch = outch << (8 - outch_count);
			outch_count = 8;
			outline[out_i++] = outch;
			if((out_i % bwidth) == 0) {
				fwrite(outline, 1, bwidth, outfp);
				memset(outline, 0, bwidth);
				out_i = 0;
			}
			outch = 0;
			outch_count = 0;
		} 
		fread(in_line, 1, in_bwidth, fp);
	}
	fclose(fp);
	return;
}

/* main */
int main(int argc, char* argv[])
{
	if(argc < 2) {
		fprintf(stderr, "%s\n", "Malformed command. Please specify the operation to be performed");
		exit(1);
	}
	if(!strcmp(argv[1], STREAM)) {
		char *passphrase = NULL;
		int length       = 0;
		int index        = 2;
		while(index < argc) {
			char *token = strtok(argv[index], "=");
			if(!strcmp(token, "-p"))
				passphrase = strtok(NULL, "=");
			else if(!strcmp(token, "-l"))
				length = atoi(strtok(NULL, "="));
			else {
				fprintf(stderr, "%s\n", "Malformed command. Usage: hw2 stream -p=pphrase -l=len"); 
				exit(1);
			}
			index++;
		}
		if(passphrase == NULL) {
			fprintf(stderr, "%s\n", "Malformed command. Please specify passphrase.");
			exit(1);
		}
		if(length == 0) {
			fprintf(stderr, "%s\n", "Malformed command. Please specify length");
			exit(1);
		}
		printSimpleStreamCipher(passphrase, length);
	} else if(!strcmp(argv[1], ENCRYPT)) {
		char *passphrase = NULL;
		char *name       = NULL;
		char *filename   = NULL;
		int index        = 2;
		while(index < argc) {
			char *token = strtok(argv[index], "=");
			if(!strcmp(token, "-p"))
				passphrase = strtok(NULL, "=");
			else if(!strcmp(token, "-out"))
				name = strtok(NULL, "=");
			else if(filename == NULL) {
				filename = token;
			} else {
				fprintf(stderr, "%s\n", "Malformed command. Usage: hw2 encrypt -p=pphrase -out=name [pbmfile]");
				exit(1);
			}
			index++;
		}
		if(passphrase == NULL) {
			fprintf(stderr, "%s\n", "Malformed command. Please specify passphrase");
			exit(1);
		}
		if(name == NULL) {
			fprintf(stderr, "%s\n", "Malformed command. Please specify expected name of output file");
			exit(1);
		}
		encrypt(passphrase, name, filename, 1);
	} else if(!strcmp(argv[1], MERGE)) {
		if(argc != 4) {
			fprintf(stderr, "%s\n", "Malformed command. Usage: hw2 merge pbmfile1 pbmfile2");
			exit(1);
		}
		int index = 2;
		while(index < argc) {
			char *token = strtok(argv[index], "=");
			if(!strcmp(token, "-p")) {
				fprintf(stderr, "%s\n", "Malformed command. Usage hw2 merge pbmfile1 pbmfile2");
				exit(1);
			} else if(!strcmp(token, "-out")) {
				fprintf(stderr, "%s\n", "Malformed command. Usage hw2 merge pbmfile1 pbmfile2");
				exit(1);
			}
			index++;
		}
		char *pbmfile1 = argv[2];
		char *pbmfile2 = argv[3];
		merge(pbmfile1, pbmfile2);
	} else if(!strcmp(argv[1], DECRYPT)) {
		decrypt(argv[2]);
	} else {
		fprintf(stderr, "%s\n", "Malformed command."); 
		exit(1);
	}
	return 0;
}
