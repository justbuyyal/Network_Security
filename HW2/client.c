//SSL-Client.c
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL* ssl, SSL_CTX *ctx)
{   X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[4096] = "";
    int bytes;
    char *hostname, *portnum;

    if ( argc != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", argv[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=argv[1];
    portnum=argv[2];
    ctx = InitCTX();
    LoadCertificates(ctx, "client.crt", "client.key"); /* load certs */
    while(1)
    {
        server = OpenConnection(hostname, atoi(portnum));
        ssl = SSL_new(ctx);      /* create new SSL connection state */
        SSL_set_fd(ssl, server);    /* attach the socket descriptor */
        if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        {
            ERR_print_errors_fp(stderr);
            exit(0);
        }
        else
        {   
            printf("\nConnected with %s encryption\n", SSL_get_cipher(ssl));
            if(SSL_connect(ssl) == 1)
            {
                char msg[1024];
                ShowCerts(ssl, ctx); /* get any certs */
                /* Simple Shell */
                printf("Input Your shell command below :\n");
                fgets(msg, 1024, stdin);
                SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
                // check recieve message
                int flag, copy;
                char *fileName;
                char *cpy;
                flag = copy = 0;
                char *ptr = strtok(msg, " ");
                while(ptr != NULL)
                {
                    flag += 1;
                    if(flag == 1 && strcmp(ptr, "cp") == 0) copy = 1;
                    if(flag == 2 && copy == 1){
                        fileName = malloc(sizeof(char) * strlen(ptr));
                        strcpy(fileName, ptr);
                    }                
                    ptr = strtok(NULL, " ");
                }
                free(ptr);
                bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
                buf[bytes] = 0;
                if(flag == 2 && copy)
                {
                    /* File Copy */
                    cpy = malloc(sizeof(char) * (strlen(fileName) + 5));
                    strcpy(cpy, "copy_");
                    printf("filena = %s\n", cpy);
                    strcat(cpy, fileName); // Create new fileName
                    cpy = strtok(cpy, "\n");
                    printf("file name = \"%s\"\n", cpy); // debug
                    FILE *output;
                    output = fopen(cpy, "w+b");
                    fwrite(buf, strlen(buf), 1, output);
                    fclose(output);
                    printf("Copy Done !\n");
                }
                else
                {
                    printf("%s\n", buf);
                }
            }
            else
            {
                ERR_print_errors_fp(stderr);
                printf("ShutDown Control\n");
                exit(0);
            }
        }
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}