all: alice bob eve

alice:
	gcc alice.c -o alice -lssl -lcrypto

bob:
	gcc bob.c -o bob -lssl -lcrypto

eve:
	gcc eve.c -o eve -lssl -lcrypto

clean:
	rm alice bob eve