all: main program insert host view

CC = g++ -std=c++11
main: main.cpp
	$(CC) main.cpp -o main

program: program.c
	$(CC) program.c -o program.cgi

insert: insert.c
	$(CC) insert.c -o insert.cgi

host: host.c
	$(CC) host.c -o host.cgi

view: view.c
	$(CC) view.c -o view.cgi

.PHONY: clean,run
clean:
	rm main program.cgi insert.cgi host.cgi insert_cgi.txt view.cgi

test:
	./main
