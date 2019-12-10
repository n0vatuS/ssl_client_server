#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <set>
#include <thread>
#include <vector>
#include <string>
#include <mutex>

#include "openssl/ssl.h"
#include "openssl/err.h"
#define FAIL    -1

using namespace std;

const static int BUFSIZE = 1024;

set<SSL *> Clients;
bool bflag;
mutex m;

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
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
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    const SSL_METHOD *method = TLSv1_2_server_method();  /* create new server-method instance */
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
{
    X509 *cert;
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

void echo(SSL* ssl) {
    X509 *cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    int sd = SSL_get_fd(ssl);

    if ( cert != NULL )
    {
		perror("ERROR on accept");
		return;
	}
	printf("connected  [Client %d]\n", sd);

	while (true) {
		char buf[BUFSIZE];
		int received = SSL_read(ssl, buf, sizeof(buf));
		if (received == 0 || received == -1) {
			printf("recv failed to %d\n", sd);
            m.lock();
			Clients.erase(ssl);
            m.unlock();
            close(sd);          /* close connection */
			break;
		}
		snprintf(buf+strlen(buf), 14, "  [Client %d]\0", sd);
		printf("%s\n", buf);
		
		if(bflag) {
			for(auto it = Clients.begin(); it != Clients.end(); it++) {
				ssize_t sent = SSL_write(*it, buf, strlen(buf));
				if (sent == 0) {
					printf("send failed to %d\n", sd);
                    m.lock();
					Clients.erase(*it);
                    m.unlock();
                    close(sd);          /* close connection */
                    break;
				}
			}
		}
		else {
			ssize_t sent = SSL_write(ssl, buf, strlen(buf));
			if (sent == 0) {
				printf("send failed to %d\n", sd);
                m.lock();
				Clients.erase(ssl);
                m.unlock();
                close(sd);          /* close connection */
				break;
			}
		}
	}
}

bool Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int bytes;
    bool ret = false;
    const char* ServerResponse="<Body><Name>aticleworld.com</Name><year>1.5</year><BlogType>Embedede and c/c++</BlogType><Author>amlendra<Author></Body>";
    const char *cpValidMessage = "<Body><UserName>a<UserName><Password>b<Password><Body>";

    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        buf[bytes] = '\0';
        printf("Client msg: \"%s\"\n", buf);
        if ( bytes > 0 )
        {
            if(strcmp(cpValidMessage,buf) == 0)
            {
                SSL_write(ssl, ServerResponse, strlen(ServerResponse)); /* send reply */
                ret = true;
            }
            else
            {
                SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); /* send reply */
            }
        }
        else
        {
            ERR_print_errors_fp(stderr);
        }
    }
    return ret;
}

void usage() {
	printf("syntax : ssl_server <port> [-b]\n");
	printf("sample : ssl_server 1234 -b\n");
}

int main(int argc, char *argv[])
{
    if(!(argc == 3 && argv[2][0] == '-' && argv[2][1] == 'b') && argc != 2) {
		usage();
		exit(1);
	}
	if(argc == 3) bflag = true;

    SSL_CTX *ctx;
    int server;
    char *portnum;
//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }

    // Initialize the SSL library
    SSL_library_init();
    portnum = argv[1];
    ctx = InitServerCTX();        /* initialize SSL */
    char cert[20] = "new.cert.cert", key[20] = "new.cert.key";
    LoadCertificates(ctx, cert, key); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */

    vector<thread> T;

    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        bool certificate = Servlet(ssl);         /* service connection */

        if(certificate) {
            m.lock();
            Clients.insert(ssl);
            m.unlock();
            T.push_back(thread(echo, ssl));
        }
    }

    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}
