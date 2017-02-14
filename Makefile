hw2: hw2.o 
	gcc -o hw2 -g hw2.o -L/home/scf-22/csci551b/openssl/lib -lcrypto -lm

hw2.o: hw2.c hw2.h 
	gcc -g -c -Wall hw2.c

clean:
	rm -f *.o hw2
