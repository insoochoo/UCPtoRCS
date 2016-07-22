/**
 * @brief: ECE358 network utility functions
 * @author: Mahesh V. Tripunitara
 * @file: net_util.c 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>

#include "net_util.h"

/**
 * @brief: get a non-loopback IP address
 */

uint32_t getPublicIPAddr() 
{
	struct ifaddrs *ifa;

	if(getifaddrs(&ifa) < 0) {
		perror("getifaddrs"); exit(0);
	}

	struct ifaddrs *c;
	for(c = ifa; c != NULL; c = c->ifa_next) {
		if(c->ifa_addr == NULL) continue;
		if(c->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in a;

			memcpy(&a, (c->ifa_addr), sizeof(struct sockaddr_in));
			char *as = inet_ntoa(a.sin_addr);
#ifdef _DEBUG_
			printf("%s\n", as);
#endif // _DEBUG_

			int apart;
			sscanf(as, "%d", &apart);
			if(apart > 0 && apart != 127) {
				freeifaddrs(ifa);
				return (a.sin_addr.s_addr);
			}
		}
	}

	freeifaddrs(ifa);
	return 0;
}


/* 
 * mybind() -- a wrapper to bind that tries to bind() to a port in the
 * range PORT_RANGE_LO - PORT_RANGE_HI, inclusive, if the provided port is 0.
 * Or else, it will try to just call bind instead.
 *
 * Parameters:
 *
 * sockfd -- the socket descriptor to which to bind
 *
 * addr -- a pointer to struct sockaddr_in. mybind() works for AF_INET sockets only.
 * Note that addr is and in-out parameter. That is, addr->sin_family and
 * addr->sin_addr are assumed to have been initialized correctly before the call.
 * If addr->sin_port is not 0, it will try to bind to the provided port.
 * Up on return, addr->sin_port contains, in network byte order, the port to which 
 * the call bound sockfd.
 *
 * returns int -- negative return means an error occurred, else the call succeeded.
 */
int mybind(int sockfd, struct sockaddr_in *addr) {
	if(sockfd < 1) {
		fprintf(stderr, "mybind(): sockfd has invalid value %d\n", sockfd);
		return -1;
	}

	if(addr == NULL) {
		fprintf(stderr, "mybind(): addr is NULL\n");
		return -1;
	}

	// if(addr->sin_port != 0) {
	//     fprintf(stderr, "mybind(): addr->sin_port is non-zero. Perhaps you want bind() instead?\n");
	//     return -1;
	// }

	if(addr->sin_port != 0) {
		if(bind(sockfd, (const struct sockaddr *)addr, sizeof(struct sockaddr_in)) < 0) {
			fprintf(stderr, "mybind(): cannot bind to port %d\n", addr->sin_port);
			return -1;
		}
		return 0;
	}

	unsigned short p;
	for(p = PORT_RANGE_LO; p <= PORT_RANGE_HI; p++) {
		addr->sin_port = htons(p);
		int b = bind(sockfd, (const struct sockaddr *)addr, sizeof(struct sockaddr_in));
		if(b < 0) {
			continue;
		}
		else {
			break;
		}
	}

	if(p > PORT_RANGE_HI) {
		fprintf(stderr, "mybind(): all bind() attempts failed. No port available...?\n");
		return -1;
	}

	/* Note: upon successful return, addr->sin_port contains, in network byte order, the
	 * port to which we successfully bound. */
	return 0;
}
