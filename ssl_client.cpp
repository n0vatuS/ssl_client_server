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
#include <thread>
#define FAIL    -1

using namespace std;

const static int BUFSIZE = 1024;

int OpenConnection(const char *hostname, int port)
{
	int sd;
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
{
	const SSL_METHOD *method;
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
{
	X509 *cert;
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

void recv_msg(SSL* ssl) {
	while(true) {
		char buf[BUFSIZE];
		ssize_t received = SSL_read(ssl, buf, sizeof(buf));
		if (received == 0 || received == -1) {
			perror("recv failed");
			exit(1);
		}
		buf[received] = '\0';
		printf("%s\n", buf);
	}
}

void usage() {
	printf("syntax : ssl_client <host> <port>");
	printf("sample : ssl_client 127.0.0.1 1234");
}

int main(int argc, char *argv[])
{
	if(argc != 3) {
		usage();
		exit(1);
	}

	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buf[BUFSIZE];
	char acClientRequest[BUFSIZE] = {0};
	int bytes;
	char *hostname, *portnum;

	SSL_library_init();
	hostname=argv[1];
	portnum=argv[2];
	ctx = InitCTX();
	server = OpenConnection(hostname, atoi(portnum));
	ssl = SSL_new(ctx);      /* create new SSL connection state */
	SSL_set_fd(ssl, server);    /* attach the socket descriptor */
	if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
	    ERR_print_errors_fp(stderr);
	else
	{
	    char acUsername[16] = {0};
	    char acPassword[16] = {0};
	    const char *cpRequestMessage = "<Body><UserName>%s<UserName><Password>%s<Password><Body>";
	    printf("Enter the User Name : ");
	    scanf("%s",acUsername);
	    printf("Enter the Password : ");
	    scanf("%s",acPassword);
	    sprintf(acClientRequest, cpRequestMessage, acUsername,acPassword);   /* construct reply */
	    printf("\nConnected with %s encryption\n", SSL_get_cipher(ssl));
	    ShowCerts(ssl);        /* get any certs */
	    SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
	    bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
	    buf[bytes] = 0;
	    printf("Received: \"%s\"\n", buf);

		thread T(recv_msg, ssl);

		while (true) {
			char buf[BUFSIZE];
			scanf("%s", buf);
			if (strcmp(buf, "quit") == 0) break;
			
			ssize_t sent = SSL_write(ssl, buf, sizeof(buf));
			if (sent <= 0) {
				perror("send failed");
				break;
			}
		}

	    SSL_free(ssl);        /* release connection state */
	}
	close(server);         /* close socket */
	SSL_CTX_free(ctx);        /* release context */
	return 0;
}
