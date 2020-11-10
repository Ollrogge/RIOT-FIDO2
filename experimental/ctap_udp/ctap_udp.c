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

static void read_loop(ctap_trans_cb_t cb);
static int g_sockfd;

void ctap_udp_create(ctap_trans_cb_t cb)
{
    DEBUG("ctap_udp_create \n");
	struct sockaddr_in serveraddr;
    int optval;

    g_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sockfd < 0) {
        DEBUG("ERROR opening socket \n");
    }


    optval = 1;
	if (setsockopt(g_sockfd, SOL_SOCKET, SO_REUSEADDR,
		(const void *)&optval, sizeof(int))) {
        DEBUG("setsockopt error \n");
    }

    bzero((char *)&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons(PORT);

    if (bind(g_sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        DEBUG("ERROR on binding \n");
    }

    read_loop(cb);
}

static void read_loop(ctap_trans_cb_t cb)
{
    int n;
    uint8_t buf[0x40];

    n = recvfrom(g_sockfd, buf, sizeof(buf), 0, NULL, 0);
    if (n < 0) {
        DEBUG("Recvfrom failed \n");
    }

    cb(buf, sizeof(buf));
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