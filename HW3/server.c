#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <netinet/in.h>

#define PORT 8081

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
    SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* certFile, char* keyFile)
{
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
    SSL *ssl;
    ssl = SSL_new(ctx);
    if(ssl= NULL)
    {
        perror("ssl error");
        exit(EXIT_FAILURE);
    }
    // SSL setting
    SSL_set_fd(ssl, fd);
    SSL_set_verify_depth(ssl, 1);
    // handshake handling
    int k = SSL_accept(ssl);
    if(k <= 0)
    {
        if(SSL_get_verify_result(ssl) != X509_V_OK)
        {
            perror("client verification failed");
        }
        else
        {
            perror("unexpected accept error");
        }
        exit(EXIT_FAILURE);
    }
    else if(k == 1)
    {
        printf("Connected Successfully\t\n");
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    }
    else
    {
        printf("shutdown\n");
    }
    return ssl;
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
            perror("accept error");
            exit(EXIT_FAILURE);
        }

        // create a new process handling request
        if((pid = fork()) < 0)
        {
            perror("fork error\t\n");
            exit(EXIT_FAILURE);
        }
        // child process
        else if(pid == 0)
        {
            printf("child process\n");
            // prctl(PR_SET_PDEATHSIG, SIGHUP); // while parent exit, child exit
            SSL* ssl = ssl_create_connection(client_fd, ctx);
            // handle request

            SSL_free(ssl);
            exit(0);
        }
        else
        {
            printf("parent process\n");
            waitpid(pid, &status, 0);
        }
        close(client_fd);
    }
    close(fd);
    SSL_CTX_free(ctx);
    return 0;
}