all: polypasswordhasher_example.c
	gcc -g -Wall -o polypasswordhasher_example polypasswordhasher_example.c -lcrypto -lpolypasswordhasher
clean:
	$(RM) polypasswordhasher_example
