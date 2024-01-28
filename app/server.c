#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define ERR_MSG(x) do { \
    fprintf(stderr, "[ERROR]: %s\n", x); } \
    while(0)

int init_stream_socket() {
	int server_fd;
	server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        ERR_MSG(strerror(errno));
    }

    int reuse = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

    return server_fd;
}

struct sockaddr_in bindto(int fd, int address, int port) {
    struct sockaddr_in server_address = {
        .sin_addr = { .s_addr = htonl(address) },
        .sin_port = htons(port),
        .sin_family = AF_INET,
    };

    // when a socket is created with `socket(2)` it exists in a name space
    // but has no name assigned.
    //
    // `bind` requests that the address is assigned to a socket.
    if (bind(fd, (struct sockaddr *) &server_address, sizeof(server_address)) != 0) {
        ERR_MSG(strerror(errno));
    }

    return server_address;
}

void process_requests(int server, struct sockaddr_in * server_addr) {
    unsigned int client_addr_len;
	struct sockaddr_in client_addr;

	printf("Connecting to client...\n");
	client_addr_len = sizeof(client_addr);
	
    do {
	    int client_fd = accept(server, (struct sockaddr *) &client_addr, &client_addr_len);
        //printf("Client connected\n");
        
        //void            *msg_name;      /* [XSI] optional address */
        //socklen_t       msg_namelen;    /* [XSI] size of address */
        //struct          iovec *msg_iov; /* [XSI] scatter/gather array */
        //int             msg_iovlen;     /* [XSI] # elements in msg_iov */
        //void            *msg_control;   /* [XSI] ancillary data, see below */
        //socklen_t       msg_controllen; /* [XSI] ancillary data buffer len */
        //int             msg_flags;      /* [XSI] flags on received message */
        struct msghdr imsg;

        struct iovec iov[1];

        char buffer[1024];
        iov[0].iov_base = buffer;
        iov[0].iov_len = 1024;

        imsg.msg_name = &client_addr;
        imsg.msg_namelen = client_addr_len;
        imsg.msg_iov = iov;
        imsg.msg_iovlen = 1;


        ssize_t len = recvmsg(client_fd, &imsg, 0);
        buffer[len] = '\0';

        printf("Received message %s (%lu)\n", buffer, len);


        struct msghdr rmsg;

        char response[] = "+PONG\r\n";
        ssize_t response_len = strlen(response);
        iov[0].iov_base = response;
        iov[0].iov_len = response_len;

        rmsg.msg_name = &client_addr;
        rmsg.msg_namelen = client_addr_len;
        rmsg.msg_iov = iov;
        rmsg.msg_iovlen = 1;

        ssize_t l = sendmsg(client_fd, &rmsg, 0);
        if (l != response_len) {
            printf("Sent incomplete message %lu!\n", l);
        } else {
            printf("Sent message\n");
        }

    } while(1);



}

int main() {
	// Disable output buffering
	setbuf(stdout, NULL);

    // create socket
    int server_fd = init_stream_socket();
    struct sockaddr_in server_addr = bindto(server_fd, INADDR_ANY, 6379);

	
	int connection_backlog = 1;
	if (listen(server_fd, connection_backlog) != 0) {
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}	

    process_requests(server_fd, &server_addr);
	
	close(server_fd);

	return 0;
}
