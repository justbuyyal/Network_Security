#include <stdlib.h>
#include <stdio.h>
#include <error.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <string>

using namespace std;

int main(void){
    int unread;
    char *buf;

    // wait for stdin
    while(unread<1){
        if(ioctl(STDIN_FILENO, FIONREAD,&unread)){
            perror("ioctl");
            exit(EXIT_FAILURE);
        }
    }
    buf = (char*)malloc(sizeof(char)*(unread+1));

    // read from stdin fd
    read(STDIN_FILENO, buf, unread);

    // output to stdout
    printf("<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n");
    printf("<TITLE>I'm a example</TITLE>\n");
    printf("<BODY>parameter: %s</BODY></HTML>\n",buf);
}