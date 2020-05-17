#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <netinet/in.h>

#include "webtext.h"

#define PORT 8081
#define BUFFER 1024

int isRoot(){return (getuid() != 0) ? 0:1;}
void Listen(int fd, int backlog)
{
    char *ptr;
    if((ptr = getenv("LISTENQ")) != NULL)
        backlog = atoi(ptr);
    if(listen(fd, backlog) < 0)
    {
        printf("listen error\r\n");
        return;
    }
}
void Bind(int fd, struct sockaddr* sa, socklen_t sa_len)
{
    if(bind(fd, sa, sa_len) < 0)
    {
        printf("bind error\t\n");
        exit(-1);
    }
}
int Accept(int fd, struct sockaddr* sa, socklen_t* sa_len)
{
    int n;
    if((n = accept(fd, sa, sa_len)) < 0)
    {
        return -1;
    }
    return n;
}
int create_socket(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port=htons(PORT);
    Bind(fd, (struct sockaddr_in*) &serverAddr, sizeof(serverAddr));
    Listen(fd, 5); // backlog: maximum capacity a server can handle at once
    return fd;
}
SSL_CTX* InitServerCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX* ctx;

    OpenSSL_add_all_algorithms(); // load & register all crpytos, etc.
    SSL_load_error_strings(); // load all error message
    method = TLSv1_2_server_method(); // create new server-method instance
    ctx = SSL_CTX_new(method); // create new context from method 
    if(ctx == NULL)
    {
        perror("SSL create failed");
        exit(EXIT_FAILURE);
    }
    // SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    SSL_library_init();
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* certFile, char* keyFile)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);
    if ( SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if(!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
SSL* ssl_create_connection(int fd, SSL_CTX* ctx)
{
    /* SSL creation initialization */
    SSL* c_ssl;
    c_ssl = SSL_new(ctx);
    // SSL setting
    SSL_set_fd(c_ssl, fd);
    SSL_set_verify_depth(c_ssl, 1);
    return c_ssl;
}
void ShowCerts(SSL* c_ssl) // show client certificates
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(c_ssl); // Get certificates (if available)
    if(cert != NULL)
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
    {
        printf("No cretificates.\n");
    }
}
void handleHttps(int c_fd, SSL* c_ssl)
{
    char buf[BUFFER];
    int bytes = SSL_read(c_ssl, buf, BUFFER); // get request
    if(bytes > 0)
    {
        buf[bytes] = 0;
        printf("client msg = \"%s\"\n", buf);
        // handling web request
        pid_t pid;
        int status;
        int cgiInput[2], cgiOutput[2];
        if(pipe(cgiInput) < 0)  perror("pipe error");
        if(pipe(cgiOutput) < 0) perror("pipe error");
        if((pid = fork()) < 0)
        {
            perror("fork error");
            exit(EXIT_FAILURE);
        }
        if(pid == 0) // child process
        {
            printf("child process\n");
            // close unused fd
            close(cgiInput[1]);
            close(cgiOutput[0]);
            printf("before redir\n");
            // redirect the input from stdin to cgiInput
            // dup2(cgiInput[0], STDIN_FILENO);
            // redirect the output from stdout to cgiOutput
            // dup2(cgiOutput[1], STDOUT_FILENO);
            printf("after redir\n");
            // after redirect we don't need the old fd
            close(cgiInput[0]);
            close(cgiOutput[1]);
            
            // execute cgi program
            if(strncmp(buf, "GET / ", 6) == 0)
            {
                // sending web page information
                SSL_write(c_ssl, Response, strlen(Response));
                SSL_write(c_ssl, webPage, strlen(webPage));
            }
            else if(strncmp(buf,"GET /view.cgi", 13) == 0)
            {
                SSL_write(c_ssl, Response, strlen(Response));
                SSL_write(c_ssl, viewPage_1, strlen(viewPage_1));
                SSL_write(c_ssl, "123456", 6);
                SSL_write(c_ssl, viewPage_2, strlen(viewPage_2));
            }
            close(c_fd);
        }
        else
        {
            printf("parent process\n");
            waitpid(pid, &status, 0);
        }
        
    }
}
int main(int argc, char** argv)
{
    int fd;
    SSL_CTX *ctx;
    setvbuf(stdout, NULL, _IONBF, 0);
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!\n");
        exit(0);
    }
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ctx = InitServerCTX(); // initialize SSL
    LoadCertificates(ctx, "server.crt", "server.key"); // load certification file and private key
    fd = create_socket(PORT); // create server socket
    while(1)
    {
        int client_fd;
        struct sockaddr_in client_addr;
        socklen_t c_addr_len = sizeof(client_addr);
        pid_t pid;
        int status;
        
        // create client socket connection
        client_fd = Accept(fd, (struct sockaddr *)&client_addr, &c_addr_len);
        if(client_fd < 0)
        {
            perror("client socket accept error");
            exit(EXIT_FAILURE);
        }
        SSL* ssl;
        ssl = ssl_create_connection(client_fd, ctx);
        int ac = SSL_accept(ssl);
        printf("ac = %d\n", ac);
        if(ac <= 0)
        {
            if(SSL_get_verify_result(ssl) != X509_V_OK)
            {
                perror("client verification failed");
                exit(EXIT_FAILURE);
            }
            else
                perror("unexpected accept error");
        }
        else
        {
            printf("SSL accept\n");
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            ShowCerts(ssl);
            // handle request
            handleHttps(client_fd, ssl);
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
    close(fd);
    SSL_CTX_free(ctx);
    return 0;
}