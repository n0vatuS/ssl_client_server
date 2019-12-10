# ssl_client_server

ssl(tls) 기반으로 echo client, echo server를 제작

[상세]
**ssl_client**
syntax : ssl_client <host> <port>
sample : ssl_client 127.0.0.1 1234
* ssl_client는 주어진 host:port로 TCP 접속하고 SSL handshake(SSL_connect)를 하여 SSL 접속을 완료한다.
* SSL 접속이 이루어 지고 나서는 콘솔로부터 메세지를 입력받아 서버로 전송(SSL_write)한다.
* 서버로부터 메세지가 오면 화면에 표시를 해 준다.
* TCP 접속이 끊기면 프로그램을 종료한다.

**ssl_server**
syntax : ssl_server <port> [-b]
sample : ssl_server 1234 -b
* ssl_server는 주어진 port로 TCP 접속 대기를 한다.
* TCP 접속이 이루어 지고 나서는 SSL handshake(SSL_accept)를 하여 SSL 접속을 완료한 이후 client로부터 메세지를 전송받아(SSL_read) 화면에 출력하고 받은 메세지를 그대로 echo(SSL_write)한다. 이 행위를 TCP 접속이 끊길때까지 계속 반복한다.
* "-b" 옵션이 주어진 경우에 수신받은 메세지를 접속이 이루어진 모든 client들에게 전송(SSL_write)한다. 이를 위해 서버에서는 클라이언트 접속 정보를 리스트로 관리를 하며 Lock을 이용하여 접속 정보를 관리(추가, 삭제)한다.
* ssl_client로부터 다중 접속을 처리할 수 있도록 한다(힌트 : thread).

Username과 password는 각각 a와 b를 넣으면 된다.
