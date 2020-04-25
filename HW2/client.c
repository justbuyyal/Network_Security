// //SSL-Client.c
// #include <stdio.h>
// #include <stdlib.h>
// #include <errno.h>
// #include <unistd.h>
// #include <malloc.h>
// #include <string.h>
// #include <sys/socket.h>
// #include <resolv.h>
// #include <netdb.h>
// #include <openssl/ssl.h>
// #include <openssl/err.h>

// #define FAIL    -1

// int OpenConnection(const char *hostname, int port)
// {   int sd;
//     struct hostent *host;
//     struct sockaddr_in addr;

//     if ( (host = gethostbyname(hostname)) == NULL )
//     {
//         perror(hostname);
//         abort();
//     }
//     sd = socket(PF_INET, SOCK_STREAM, 0);
//     bzero(&addr, sizeof(addr));
//     addr.sin_family = AF_INET;
//     addr.sin_port = htons(port);
//     addr.sin_addr.s_addr = *(long*)(host->h_addr);
//     if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
//     {
//         close(sd);
//         perror(hostname);
//         abort();
//     }
//     return sd;
// }

// SSL_CTX* InitCTX(void)
// {   SSL_METHOD *method;
//     SSL_CTX *ctx;

//     OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
//     SSL_load_error_strings();   /* Bring in and register error messages */
//     method = TLSv1_2_client_method();  /* Create new client-method instance */
//     ctx = SSL_CTX_new(method);   /* Create new context */
//     if ( ctx == NULL )
//     {
//         ERR_print_errors_fp(stderr);
//         abort();
//     }
//     return ctx;
// }

// void ShowCerts(SSL* ssl)
// {   X509 *cert;
//     char *line;

//     cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
//     if ( cert != NULL )
//     {
//         printf("Server certificates:\n");
//         line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
//         printf("Subject: %s\n", line);
//         free(line);       /* free the malloc'ed string */
//         line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
//         printf("Issuer: %s\n\n", line);
//         free(line);       /* free the malloc'ed string */
//         X509_free(cert);     /* free the malloc'ed certificate copy */
//     }
//     else
//         printf("Info: No client certificates configured.\n");
// }

// void SendMsg(SSL* ssl)
// {
//     setvbuf(stdout, NULL, _IONBF, 0);
    
//     char buf[1024];
//     int bytes;
//     char *message;
//     printf("Input Your message that you want to send below\n");
//     scanf("%s", message);
//     printf("%s\n", message);
//     SSL_write(ssl, message, strlen(message));   /* encrypt & send message */
//     bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
//     buf[bytes] = 0;
//     printf("Received: \"%s\"\n", buf);
//     return;
// }

// // void SendFile(SSL* ssl)
// // {
// //     FILE *fp;
// //     char* buf[512];
// //     fp = fopen("text.txt", "rb");
// //     if(!fp)
// //     {
// //         printf("File Not Found !\n");
// //         return 1;
// //     }
// //     while(fgets(buf, 512, fp) != EOF)
// //     {
        
// //     }
// //     fclose(fp);
// //     return;
// // }

// int main(int count, char *strings[])
// {   SSL_CTX *ctx;
//     int server;
//     char buf[1024];
//     int bytes;
//     SSL *ssl;
//     char *hostname, *portnum;

//     setvbuf(stdout, NULL, _IONBF, 0);

//     if ( count != 3 )
//     {
//         printf("usage: %s <hostname> <portnum>\n", strings[0]);
//         exit(0);
//     }
//     hostname=strings[1];
//     portnum=strings[2];
//         SSL_library_init();
//         server = OpenConnection(hostname, atoi(portnum));
//         ctx = InitCTX();
//         ssl = SSL_new(ctx);      /* create new SSL connection state */
//         SSL_set_fd(ssl, server);    /* attach the socket descriptor */
//         if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
//             ERR_print_errors_fp(stderr);
//         else
//         {   
//             printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
//             ShowCerts(ssl);        /* get any certs */
//             /* File copy */
//             FILE *fp;
//             char *temp[512];
//             fp = fopen("text.txt", "rb");
//             if(!fp) return FAIL;
//             while(fgets(temp, 512, fp) != EOF)
//             {
//                 SSL_write(ssl, temp, strlen(temp));
//             }
//             fclose(fp);
//             printf("Communication !\n");
//             while(1)
//             {
//                 /* Communication */
//                 char *message;
//                 printf("Input Your message that you want to send below\n");
//                 scanf("%s", message);
//                 SSL_write(ssl, message, strlen(message));   /* encrypt & send message */
//                 bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
//                 buf[bytes] = 0;
//                 printf("Received: \"%s\"\n", buf);
//             }
//             SSL_CTX_free(ctx);     /* release context */
//             SSL_free(ssl);        /* release connection state */
//         }
//     close(server);         /* close socket */
//     return 0;
// }

//SSL-Client.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1

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

void ShowCerts(SSL* ssl)
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

int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname, *portnum;

    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];

    while(1)
    {
        ctx = InitCTX();
        server = OpenConnection(hostname, atoi(portnum));
        ssl = SSL_new(ctx);      /* create new SSL connection state */
        SSL_set_fd(ssl, server);    /* attach the socket descriptor */
        if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
            ERR_print_errors_fp(stderr);
        else
        {   
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            ShowCerts(ssl);        /* get any certs */
            /* Communication */
            char *msg;
            printf("Input Your message that you want to send below\n");
            scanf("%s", msg);
            SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
            bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
            buf[bytes] = 0;
            printf("Received: \"%s\"\n", buf);
            /* Communication done */
            /* File copy */

            /* copy done */
            SSL_free(ssl);        /* release connection state */
        }
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}