all: server

CC = gcc -Wall -o

server: server.c
	$(CC) server server.c -L/usr/lib -lssl -lcrypto

.PHONY: clean,run
clean:
	rm server
run:
	sudo ./server