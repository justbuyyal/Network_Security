#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sstream>
#include <iostream>
#include <string>

 
using namespace std;
#define BUFFER_SIZE 512
#define DEBUG
 
int Socket(int,int,int);
void Bind(int ,const struct sockaddr*sa,socklen_t salen);
void Listen(int ,int);
int Accept(int,struct sockaddr*,socklen_t*);
void handleAccept(int);
void handleHttp(int);
int getRequest(int);
 
 
int main(int argc,char **argv)
{
    const int port = 1024; //listen port
    int listenfd= Socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in serverAddr;
    serverAddr.sin_family=AF_INET;
    serverAddr.sin_addr.s_addr=INADDR_ANY;
    serverAddr.sin_port=htons(port);
    Bind(listenfd,(struct sockaddr*)&serverAddr,sizeof(serverAddr));
    Listen(listenfd,5);
 
    while(true)
    {
        handleAccept(listenfd);
    }
}
 
int Socket(int family , int type,int protocol)
{
    int n;
    if ( (n = socket(family, type, protocol)) < 0)
    {
        printf("socket error\r\n");
        return -1;
    }
    return(n);
 
}
void
Bind(int fd, const struct sockaddr *sa, socklen_t salen)
{
    if (bind(fd, sa, salen) < 0)
    {
        printf("bind error\r\n");
        exit(-1);
    }
}
void
Listen(int fd, int backlog)
{
    char *ptr;
 
    /*4can override 2nd argument with environment variable */
    if ( (ptr = getenv("LISTENQ")) != NULL)
        backlog = atoi(ptr);
 
    if (listen(fd, backlog) < 0)
    {
        printf("listen error\r\n");
        return ;
    }
}
int
Accept(int fd, struct sockaddr *sa, socklen_t *salenptr)
{
    int n;
again:
    if ( (n = accept(fd, sa, salenptr)) < 0) {
#ifdef  EPROTO
        if (errno == EPROTO || errno == ECONNABORTED)
#else
        if (errno == ECONNABORTED)
#endif
            goto again;
        else
        {
            printf("accept error\r\n");
            return -1;
        }
    }
    return(n);
}
 
void handleAccept(int listenfd)
{
    sockaddr_in clientAddr;
    socklen_t clientLen=sizeof(clientAddr);
    int connfd=Accept(listenfd,(sockaddr *)&clientAddr,&clientLen);
    handleHttp(connfd);
    close(connfd);
}
 
void handleHttp(int connfd)
{
    if(getRequest(connfd)<0)
    {
        perror("http request get error");
        exit(-1);
    }
}
int getRequest(int socket)
{
    int msgLen=0;
    char buffer[BUFFER_SIZE];
    memset (buffer,'\0', BUFFER_SIZE);
    if ((msgLen = recv(socket, buffer, BUFFER_SIZE, 0)) == -1)
    {
        printf("Error handling incoming request");
        return -1;
    }

    stringstream ss;
    ss<<buffer;
    string method;
    ss>>method;
    string uri;
    ss>>uri;
    string version;
    ss>>version;

    string statusCode("200 OK");
    string contentType("text/html");
    string contentSize;
    string head("\r\nHTTP/1.1 ");
    string ContentType("\r\nContent-Type: ");
    string ServerHead("\r\nServer: localhost");
    string ContentLength("\r\nContent-Length: ");
    string Date("\r\nDate: ");
    string Newline("\r\n");
    time_t rawtime;
    time(&rawtime);
    string message;

    int n;
    string urls[4] ={"./", "./program.cgi", "./insert.cgi", "./view.cgi"};

    message+=head;
    message+=statusCode;
    message+=ContentType;
    message+=contentType;
    message+=ServerHead;
    message+=ContentLength;
    message+=contentSize;
    message+=Date;
    message+=(string)ctime(&rawtime);
    message+=Newline;

    int messageLength=message.size();
    n=send(socket,message.c_str(),messageLength,0);

    /*
        CGI_program, host.c
    */
    int cgiInput[2];
    int cgiOutput[2];
    int status;

    /*
        Get socket and change to char* sending to CGI
    */
    stringstream strs;
    strs << socket;
    string temp_str = strs.str();
    char* Wsk = (char*) temp_str.c_str();

    pid_t cpid;
    char c;
    /* 
        Use pipe to create a data channel betweeen two process
        'cgiInput'  handle  data from 'host' to 'CGI'
        'cgiOutput' handle data from 'CGI' to 'host'
    */
    if(pipe(cgiInput)<0){
        perror("pipe");
        exit(EXIT_FAILURE);
    }
    if(pipe(cgiOutput)<0){
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    /* Creates a new process to execute cgi program */
    if((cpid = fork()) < 0){
        perror("fork");
        exit(EXIT_FAILURE);
    }
    /* child process */
    if(cpid == 0){
        printf("This is child process\n");
        // close unused fd
        close(cgiInput[1]);
        close(cgiOutput[0]);

        // redirect the output from stdout to cgiOutput
        dup2(cgiOutput[1], STDOUT_FILENO);

        // redirect the input from stdin to cgiInput
        dup2(cgiInput[0], STDIN_FILENO);

        // after redirect we don't need the old fd
        close(cgiInput[0]);
        close(cgiOutput[1]);

        /*
            execute cgi program
            the stdout of CGI program is redirect to cgiOutput
            the stdin of CGI program is redirect to cgiInput
        */
        uri.insert(uri.begin(), '.');
        bool flag = false;
        // Find the correspond cgi program from urls array
        for(int i = 0; i < sizeof(urls)/sizeof(urls[0]); i++){
            if(strcmp(uri.c_str(), urls[i].c_str()) == 0){
                flag = true;
                if(i == 0){
                    execlp("./host.cgi", "./host.cgi", NULL);
                }
                else{
                    execlp(uri.c_str(), uri.c_str(), NULL);
                }
                break;
            }
        }
        // Error URL
        if(!flag){
            std::string error("Status: 404 Not found\r\n\r\n");
            n = send(socket, error.c_str(), error.size(), 0);
        }
        exit(0);
    }
    /* parent process */
    else{
        printf("This is parent process\n");
        // close unused fd
        close(cgiOutput[1]);
        close(cgiInput[0]);

        // send the message to the CGI program
        write(cgiInput[1], Wsk, strlen(Wsk));

        // receive the message from the CGI program
        while (read(cgiOutput[0], &c, 1) > 0)
        {
            /* output the message to socket(web) */
            write(socket, &c, 1);
        }

        send(STDIN_FILENO, "\n", 1, 0);

        // connection finish
        close(cgiOutput[0]);
        close(cgiInput[1]);
        waitpid(cpid, &status, 0);
        
    }
    return n;
}