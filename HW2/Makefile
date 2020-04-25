all: main client

CC = gcc -Wall -o
main: main.c
	$(CC) main main.c -L/usr/lib -lssl -lcrypto
client: client.c
	$(CC) client client.c -L/usr/lib -lssl -lcrypto

.PHONY: del,run,test
del:
	rm main client
run:
	sudo ./main 1024
test:
	./client localhost 1024
