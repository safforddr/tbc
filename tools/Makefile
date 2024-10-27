
all: cel_verify certgen

cel_verify: cel_verify.c 
	gcc -Wall -g -o cel_verify cel_verify.c -lssl -lcrypto

certgen: certgen.c
	gcc -Wall -g -o certgen certgen.c -lssl -lcrypto
clean:
	rm -f *.o cel_verify certgen
