//SSL-Server.c
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

#define FAIL    -1

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

void VerifyingCert(SSL* ssl, X509* cert)
{
    // init CertStore
    X509_STORE* m_store = X509_STORE_new();
    X509_LOOKUP* m_lookup = X509_STORE_add_lookup(m_store,X509_LOOKUP_file());
    X509_STORE_load_locations(m_store, "client.crt", NULL);
    X509_STORE_set_default_paths(m_store);
    X509_LOOKUP_load_file(m_lookup,"client.crt",X509_FILETYPE_PEM);
    // VerifyCert
    X509_STORE_CTX *storeCtx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(storeCtx,m_store,cert,NULL);
    X509_STORE_CTX_set_flags(storeCtx, X509_V_FLAG_CB_ISSUER_CHECK);
    if (X509_verify_cert(storeCtx) == 1)
    {
      printf("Verification Successful\n");
    }
    else
    {
      printf("Verification Error: %s\n",X509_verify_cert_error_string(storeCtx->error));
    }
    X509_STORE_CTX_free(storeCtx);
    // Clean m_store
    if(m_store != NULL)
    {
       X509_STORE_free(m_store);
       m_store = NULL;
    }
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Verifying\n");
        VerifyingCert(ssl, cert);
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
    char reply[1024];
    int sd, bytes;
    const char* echo="Client Msg Recieved";

    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            // sprintf(reply, echo, buf);   /* construct reply */
            SSL_write(ssl, echo, strlen(echo)); /* send reply */
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
    server = OpenListener(atoi(portnum));    /* create server socket */
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
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