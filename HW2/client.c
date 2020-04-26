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

void VerifyingCert(SSL* ssl, X509* cert)
{
    // init CertStore
    X509_STORE* m_store = X509_STORE_new();
    X509_LOOKUP* m_lookup = X509_STORE_add_lookup(m_store,X509_LOOKUP_file());
    X509_STORE_load_locations(m_store, "server.crt", NULL);
    X509_STORE_set_default_paths(m_store);
    X509_LOOKUP_load_file(m_lookup,"server.crt",X509_FILETYPE_PEM);
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
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        VerifyingCert(ssl, cert);
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
{   SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname, *portnum;

    setvbuf(stdout, NULL, _IONBF, 0);

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
    char *msg;
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {   
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        /* Communication */
        printf("Input Your message that you want to send below\n");
        scanf("%s", msg);
        SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}