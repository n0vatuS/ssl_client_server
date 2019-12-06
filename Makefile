all: ssl_client ssl_server

ssl_client: ssl_client.c
	gcc -Wall -o ssl_client ssl_client.c -L/usr/lib -lssl -lcrypto

ssl_server: ssl_server.c
	gcc -Wall -o ssl_server ssl_server.c -L/usr/lib -lssl -lcrypto

clean: 
	rm -f ssl_client ssl_server
