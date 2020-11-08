#include "ctap_udp.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static const uint16_t PORT = 8111;
static const uint16_t PORT_REMOTE = 7112;

static int g_sockfd;

void ctap_udp_create(void)
{
    DEBUG("ctap_udp_create \n");
	struct sockaddr_in serveraddr;

    g_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sockfd < 0) {
        DEBUG("ERROR opening socket \n");
    }

    struct timeval read_timeout;
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 10;
	if (setsockopt(g_sockfd, SOL_SOCKET, SO_RCVTIMEO,
		&read_timeout, sizeof(struct timeval)) < 0) {
        DEBUG("setsockopt error \n");
    }

    bzero((char *)&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons(PORT);

    if (bind(g_sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        DEBUG("ERROR on binding \n");
    }
}

int ctap_udp_read_timeout(void *buffer, size_t len, uint32_t timeout)
{
    fd_set input;
    FD_ZERO(&input);
    FD_SET(g_sockfd, &input);
    struct timeval to;
    to.tv_sec = 0;
    to.tv_usec = timeout;
    int n = select(g_sockfd + 1, &input, NULL, NULL, &to);
    if (n < 0) {
        DEBUG("Select failed \n");
    }
    if (n == 0) {
        return n;
    }

    n = recvfrom(g_sockfd, buffer, len, 0, NULL, 0);
    if (n < 0) {
        DEBUG("Recvfrom failed \n");
    }
    return n;
}

void ctap_udp_write(const void* buffer, size_t len)
{
    struct sockaddr_in serveraddr;
    memset( &serveraddr, 0, sizeof(serveraddr) );
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons( PORT_REMOTE );
    serveraddr.sin_addr.s_addr = htonl( 0x7f000001 ); // (127.0.0.1)

    if (sendto(g_sockfd , buffer, len, 0, (struct sockaddr *)&serveraddr,
        sizeof(serveraddr)) < 0 ) {
        perror( "sendto failed" );
        exit(1);
    }
}