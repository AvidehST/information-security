all: alice bob

alice:
	gcc alice.c -o alice -lssl -lcrypto

bob:
	gcc bob.c -o bob -lssl -lcrypto

clean:
	rm alice bob