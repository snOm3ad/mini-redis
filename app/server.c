#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#if defined(__APPLE__) && defined(__MACH__)
#include <sys/event.h>
#include <sys/types.h>
#include <sys/time.h>
#elif defined(__linux__)
#include <sys/epoll.h>
#else 
#    error "YOU FOOL, GET OUT... NOW!"
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define ERR_MSG(x) do { \
    fprintf(stderr, "[ERROR]: %s\n", x); } \
    while(0)

#define PRINTFUNC(format, ...)      fprintf(stderr, format, __VA_ARGS__)


#ifdef DEBUG
    #define LOG(msg, args...) PRINTFUNC("[INFO@%-10s:%d]: " msg "\n", __FILE__, __LINE__, ## args)
#else
    #define LOG(msg, args...) do { (void)(msg); } while(0)
#endif

// do not set to greater than 255
#define MAX_CLIENTS 32

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

struct node {
    int fd;
    struct sockaddr_in addr;
} ctbl[MAX_CLIENTS];

ssize_t write_msg(struct node * self, int client) {
    // abort
    if (self == NULL) {
        return -1;
    }

    struct msghdr msg;
    struct iovec iov[1];
    ssize_t len = 0;

    char response[] = "+PONG\r\n";
    ssize_t response_len = strlen(response);
    iov[0].iov_base = response;
    iov[0].iov_len = response_len;

    msg.msg_name = &(self->addr);
    msg.msg_namelen = sizeof(self->addr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    //len = send(c->fd, response, response_len, 0);
    len = sendmsg(client, (struct msghdr *) &msg, 0);
    if (len != response_len) {
        LOG("Sent incomplete message %lu!", len);
    } else {
        LOG("Sent message");
    }
    return len;
}



ssize_t read_msg(struct node * c) {
    // abort
    if (c == NULL) {
        return -1;
    }
    ssize_t len = 0;
    //void            *msg_name;      /* [XSI] optional address */
    //socklen_t       msg_namelen;    /* [XSI] size of address */
    //struct          iovec *msg_iov; /* [XSI] scatter/gather array */
    //int             msg_iovlen;     /* [XSI] # elements in msg_iov */
    //void            *msg_control;   /* [XSI] ancillary data, see below */
    //socklen_t       msg_controllen; /* [XSI] ancillary data buffer len */
    //int             msg_flags;      /* [XSI] flags on received message */
    struct msghdr msg;
    struct iovec iov[1];

    char buffer[1024];
    iov[0].iov_base = buffer;
    iov[0].iov_len = 1024;

    msg.msg_name = &c->addr;
    msg.msg_namelen = sizeof(c->addr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    
    len = recvmsg(c->fd, &msg, 0);
    if (len == 0) {
        // client no longer active
        return len;
    }
    buffer[len] = '\0';
    LOG("Received message %s (%lu)", buffer, len);

    return len;
}

void process_requests(struct node * self) {
    unsigned int client_addr_len;
	struct sockaddr_in client_addr;

    int client_fd = 0;
    client_addr_len = sizeof(client_addr);
    memset(ctbl, 0, sizeof(struct node) * MAX_CLIENTS);


#if defined(__APPLE__) && defined(__MACH__)
    int qid;
    struct timespec timeout;

    if ((qid = kqueue()) < 0) {
        ERR_MSG("Could not create `kqueue` object");
        return;
    }
    timeout.tv_sec = 5;
    timeout.tv_nsec = 0;
    //EV_SET(
    //    &targets[0], // populate this event with the following data:
    //    client_fd,   // · the descriptor we care for
    //    EVFILT_READ, // · the event we care for
    //    EV_ADD,      // · the action we want whenever the event occurs
    //    0,           // · specific flags for `EV_ADD` action.
    //    0,           // · data for flags above
    //    NULL         // · user-defined data
    //);
    struct kevent ev_conn;
    int nev = 0;
    int serving = 0;

    // subscribe to see if the server has any incoming connections
    // if so then calling `accept` will not block
    EV_SET(&ev_conn, self->fd, EVFILT_READ, EV_ADD, 0, 0, NULL);

    while (1) {
        struct kevent incoming[MAX_CLIENTS];
        // block for at most 5s
        nev = kevent(qid, &ev_conn, 1, incoming, MAX_CLIENTS, &timeout);
        if (nev == -1) {
            ERR_MSG(strerror(errno));
        }

        LOG("up -> found %i events\tserving %i", nev, serving);

        // `qid` will _also_ contain events from clients, i.e. when the clients
        // are ready for read. that's why we _only_ process events where the
        // identifier is the server in this loop.
        for (int i = 0; i < nev; ++i) {
            if (incoming[i].ident == self->fd) {
                // `accept` seems to remove the server read event from the kqueue, so there
                // is no need to handle this ourselves.
                client_fd = accept(self->fd, (struct sockaddr *) &client_addr, &client_addr_len);

                LOG("Client (%i) connected", client_fd);

                // add client to client table
                for (int cid = 0; cid < MAX_CLIENTS; ++cid) {
                    LOG("before ctbl[%i]: %i", cid, ctbl[cid].fd);
                    // find first available slot in client table.
                    if (ctbl[cid].fd == 0) {
                        // place the current client in the slot.
                        ctbl[cid] = (struct node) {
                            .fd = client_fd,
                            .addr = client_addr,
                        };
                        LOG("after ctbl[%i]: %i", cid, ctbl[cid].fd);
                        // increment the number of registered clients
                        serving += 1;
                        break;
                    }
                }
            }
        }

        // this is where we store the event data we will pass to kqueue.
        struct kevent cedtbl[serving];
        unsigned char cedid = 0;
        int client_ids[MAX_CLIENTS];
        nev = 0;

        for (unsigned char cid = 0; cid < MAX_CLIENTS; ++cid) {
            // this setup is so that we can handle reads and disconnects.
            //
            // when a client disconnects we have to empty its slot from
            // the client table __and__ deregister the event from our kqueue.
            //
            // otherwise the `read` event for a disconnected client will
            // remain in the queue which will lead to an error during read.
            if (ctbl[cid].fd != 0 && cedid < serving) {

                // because `cedtbl` and `ctbl` are likely _not_ the same size
                // then we cannot simply store the slot index. we _also_ have to
                // store the `cedid` which we use to access it's kqueue event data.
                //
                // we jam both these ids inside the slot for this client and pass it
                // as user data when we register our client.
                client_ids[cid] = (cedid << 8) | cid;
                LOG("client_ids(%i): %p", cid, &client_ids[cid]);
                EV_SET(&cedtbl[cedid], ctbl[cid].fd, EVFILT_READ, EV_ADD, 0, 0, &client_ids[cid]);
                cedid += 1;
            }
        }
        // client event table.
        struct kevent cetbl[MAX_CLIENTS];

        // At this point we would block indefinetly, but because we registered
        // the server read event on `qid` above this will unblock as soon as
        // there is a client connection incoming
        nev = kevent(qid, cedtbl, serving, cetbl, MAX_CLIENTS, NULL);
        LOG("down -> found %i events\tserving %i", nev, serving);

        for (int i = 0; i < nev; ++i) {
            // this will not handle server read events as those will not have
            // any user data inside of them. so here we only handle client
            // events.
            if (cetbl[i].udata != NULL) {
                // parse the user data
                int indexes = *((int *) cetbl[i].udata);
                LOG("udata: %p", cetbl[i].udata);
                LOG("indexes: 0x%x", indexes);

                // the lower bits are the client slot id from ctbl
                unsigned char csid = indexes & 0x00FF;
                // the upper bits are the event data slot id from cedtbl
                unsigned char cedsid = (indexes & 0xFF00) >> 8;
                ssize_t len;

                if (cetbl[i].filter == EVFILT_READ) {
                    // normally people use `kevent.ident` to access the fd
                    // of the client they want to communicate with.
                    //
                    // but you already _are_ keeping track of active clients
                    // so you might as well use that data.
                    LOG("read ready: (rac_id: %i, csid: %i)", cedsid, csid);

                    // TODO: implement batch. so if a client sends multiple
                    //       messages group the responses together and answer
                    //       all queries at once.
                    len = read_msg(&ctbl[csid]);
                    write_msg(self, ctbl[csid].fd);

                    if (len <= 0) {
                        LOG("csid: %i has disconnected!", csid);

                        EV_SET(&cedtbl[cedsid], ctbl[csid].fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);

                        if (kevent(qid, &cedtbl[cedsid], 1, NULL, 0, NULL) < 0) {
                            ERR_MSG("Could not delete event from kqueue");
                        }
                        serving -= 1;
                        memset(&ctbl[csid], 0, sizeof(struct node));
                        break;
                    }
                }
            }
        }
    }
#elif defined(__linux__)
    int epfd;
    int timeout;

    if ((epfd = epoll_create1(0)) < 0) {
        ERR_MSG("Could not create epoll instance");
    }

    timeout = (int) (1000 * 5); // 5s
    struct epoll_event ev_conn;

    ev_conn.events = EPOLLIN;
    ev_conn.data.fd = self->fd;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, self->fd, &ev_conn) < 0) {
        ERR_MSG("Could not register server read event in epoll instance");
        ERR_MSG(strerror(errno));
    }

    int nev = 0;
    int serving = 0;

    while (1) {
        struct epoll_event incoming[MAX_CLIENTS];
        nev = epoll_wait(epfd, incoming, MAX_CLIENTS, timeout);

        LOG("up -> found %i events\tserving %i", nev, serving);

        for (int i = 0; i < nev; ++i) {
            if (incoming[i].data.fd == self->fd) {
                //TODO: do I have to call `epoll_ctl` to remove the read event? maybe.
                client_fd = accept(self->fd, (struct sockaddr *) &client_addr, &client_addr_len);

                LOG("Client (%i) connected", client_fd);

                // add client to client table
                for (int cid = 0; cid < MAX_CLIENTS; ++cid) {
                    LOG("before ctbl[%i]: %i", cid, ctbl[cid].fd);
                    // find first available slot in client table.
                    if (ctbl[cid].fd == 0) {
                        // place the current client in the slot.
                        ctbl[cid] = (struct node) {
                            .fd = client_fd,
                            .addr = client_addr,
                            .ptr = NULL,
                        };
                        LOG("after ctbl[%i]: %i", cid, ctbl[cid].fd);
                        // increment the number of registered clients
                        serving += 1;
                        break;
                    }
                }
            }
        }

        int client_ids[MAX_CLIENTS];
        nev = 0;

        for (unsigned char cid = 0; cid < MAX_CLIENTS; ++cid) {
            if (ctbl[cid].fd != 0 && ctbl[cid].ptr == NULL) {
                // register new client
                struct epoll_event ced;
                client_ids[cid] = cid;
                LOG("client_ids[%i]: %p", cid, &client_ids[cid]);

                ced.events = EPOLLIN;
                ced.data.ptr = &client_ids[cid];

                if (epoll_ctl(epfd, EPOLL_CTL_ADD, ctbl[cid].fd, &ced) < 0) {
                    ERR_MSG("Could not register client read event");
                    ERR_MSG(strerror(errno));
                }
                ctbl[cid].ptr = &client_ids[cid];
            }
        }
        // client event table
        struct epoll_event cetbl[MAX_CLIENTS];
        nev = epoll_wait(epfd, cetbl, MAX_CLIENTS, -1);
        LOG("down -> found %i events\tserving %i", nev, serving);


        for (int i = 0; i < nev; ++i) {
            if (cetbl[i].data.ptr != NULL && cetbl[i].data.fd != self->fd) {
                int indexes = *((int *)cetbl[i].data.ptr);
                LOG("udata: %p", cetbl[i].data.ptr);
                LOG("indexes: 0x%x", indexes);

                unsigned char csid = indexes & 0x00FF;
                ssize_t len;

                if (cetbl[i].events == EPOLLIN) {
                    LOG("read ready (csid: %i)", csid);
                    len = read_msg(&ctbl[csid]);
                    if (len <= 0) {
                        LOG("csid: %i has disconnected!", csid);
                        if (epoll_ctl(epfd, EPOLL_CTL_DEL, ctbl[csid].fd, NULL) < 0) {
                            ERR_MSG("Could not delete event");
                            ERR_MSG(strerror(errno));
                        }
                        serving -= 1;
                        memset(&ctbl[csid], 0, sizeof(struct node));
                        break;
                    } 
                    else {
                        write_msg(self, ctbl[csid].fd);
                    }
                }
            }
        }
    }
#endif
}

int main() {
	// Disable output buffering
	setbuf(stdout, NULL);

    // Create socket
    int server_fd = init_stream_socket();
    struct sockaddr_in server_addr = bindto(server_fd, INADDR_ANY, 6379);
	
	int connection_backlog = 10;
	if (listen(server_fd, connection_backlog) != 0) {
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
    }

    struct node server = {
        .fd = server_fd,
        .addr = server_addr,
    };

    process_requests(&server);
	
	close(server_fd);

	return 0;
}
