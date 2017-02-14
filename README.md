# visual-crypto

To get executable (install openssl-lib) : make clean; make

To execute use the following commandline syntax : 
   hw2 stream -p=pphrase -l=len
   hw2 encrypt -p=pphrase -out=name [pbmfile]
   hw2 merge pbmfile1 pbmfile2
   hw2 decrypt [pbmfile]

Details :
   stream - generates key using MD5 algorithm of 'len' bytes using 'pphrase' as passphrase
   encrypt - encrypts the input file 'pbmfile' with simple stream cipher and creates two files 'name'.1.pbm 'name'.2.pbm
   merge - creates an output file by merging two input pbmfiles
   decrypt - the input file which is a result of merge is provided as input and decrypts the input resulting in a pbmfile with lower resolution.
