//SSL-Server.c
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
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

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
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
        printf("No certificates.\n");
}

void Servlet(SSL* ssl, SSL_CTX* ctx) /* Serve the connection -- threadable */
{   char buf[1024];
    int sd, bytes;
    char *FileNotFound = "File Not Found !";
    char *ErrorCommand = "Error Command or element !";

    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
    {
        ERR_print_errors_fp(stderr);
        printf("handshake failed\n");
        exit(0);
    }
    else
    {
        if(SSL_accept(ssl) == 1) printf("\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        else printf("Shutdown Controll\n");
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            char buf_temp[1024];
            strcpy(buf_temp, buf);
            char *fileName = NULL;
            char reply[5120] = "";
            char temp[2048] = "";
            int flag, copy;
            flag = copy = 0;
            char *ptr = strtok(buf_temp, " ");
            while(ptr != NULL)
            {
                flag += 1;
                if(flag == 1 && strcmp(ptr, "cp") == 0) copy = 1;
                if(flag == 2 && copy == 1){ // Save file name
                    fileName = malloc(sizeof(char) * strlen(ptr));
                    strcpy(fileName, ptr);
                }                
                ptr = strtok(NULL, " ");
            }
            free(ptr);
            FILE *fp;
            if(flag == 2 && copy)
            {
                // Deal with fileName with newline at end
                fileName = strtok(fileName, "\n");
                /* File Copy */
                printf("FileName = \"%s\"\n", fileName); // debug
                fp = fopen(fileName, "rb"); // read binary
                if(fp == NULL)
                {
                    SSL_write(ssl, FileNotFound, strlen(FileNotFound)); // file not found
                    printf("%s\n", FileNotFound);
                }
                else
                {
                    long filelen;
                    char *buffer = NULL;
                    printf("Reading File\n"); // debug
                    fseek(fp, 0, SEEK_END); // Jump to the end of file
                    filelen = ftell(fp); // Get current byte offset in the file
                    rewind(fp); // Jump back to the beginning of the file
                    buffer = (char *)malloc(filelen * sizeof(char));
                    fread(buffer, filelen, 1, fp); // read entire file
                    SSL_write(ssl, buffer, strlen(buffer)); // send file to client
                    printf("File Context = \"%s\"\n", buffer); // debug
                    free(buffer);
                }
                fclose(fp);
            }
            else
            {
                printf("system command : \"%s\"\n", strtok(buf, "\n")); // debug
                /* Simple Shell */
                fp = popen(buf, "r"); /* open the command for reading */
                while(fgets(temp, sizeof(temp) -1, fp) != NULL)
                {
                    strcat(reply, temp);
                }
                pclose(fp);
                SSL_write(ssl, reply, strlen(reply)); // reply to client
                if(system(buf) < 0) SSL_write(ssl, ErrorCommand, strlen(ErrorCommand));
            }
            free(fileName);
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}

int main(int argc, char *argv[])
{   SSL_CTX *ctx;
    int server;
    char *portnum;

    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( argc != 2 )
    {
        printf("Usage: %s <portnum>\n", argv[0]);
        exit(0);
    }
    SSL_library_init();
    portnum = argv[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "server.crt", "server.key"); /* load certs */
    SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL );
    SSL_CTX_set_verify_depth(ctx, 1);
    server = OpenListener(atoi(portnum));    /* create server socket */
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl, ctx);         /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}