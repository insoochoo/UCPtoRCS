/* Mahesh V. Tripunitara
 * University of Waterloo
 * rcsapp-server.c -- first prints out the IP & port on which in runs.
 * Then awaits connections from clients. Create a pthread for each
 * connection. The thread just reads what the other end sends and
 * write()'s it to a file whose name is the thread's ID.
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "net_util.h"
#include "rcs.h"

#if 0
#define _DEBUG_
#endif

void *serviceConnection(void *arg) {
	int s = *(int *)arg;
	free(arg);
	char fname[256];
	memset(fname, 0, 256);
	snprintf(fname, 255, "%lu", pthread_self());

	int wfd = open(fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);

	if(wfd < 0) {
		perror("open"); return NULL;
	}

	unsigned char buf[256];
	ssize_t recvlen = 0;
	while((recvlen = rcsRecv(s, buf, 256)) >= 0) {
#ifdef _DEBUG_
		if(recvlen > 0) {
			printf("%lu received %d bytes.\n",
				pthread_self(), recvlen);
		}
#endif

		if(recvlen <= 0) { 
			// quit 
#ifdef _DEBUG_
			printf("%lu exiting, spot 1...\n", pthread_self());
#endif
			close(wfd);
			rcsClose(s);
			return NULL;
		}

		if(write(wfd, buf, recvlen) < recvlen) {
			perror("write() in thread wrote too few");
			close(wfd);
			rcsClose(s);
			return NULL;
		}
	}

#ifdef _DEBUG_
	printf("%lu exiting, spot 2...\n", pthread_self());
#endif
	close(wfd);
	rcsClose(s);
	return NULL;
}

int main(int argc, char *argv[]) {
	int s = rcsSocket();
	struct sockaddr_in a;

	memset(&a, 0, sizeof(struct sockaddr_in));
	a.sin_family = AF_INET;
	a.sin_port = 0;
	if((a.sin_addr.s_addr = getPublicIPAddr()) == 0) {
		fprintf(stderr, "Could not get public ip address. Exiting...\n");
		exit(0);
	}

	if(rcsBind(s, &a) < 0) {
		fprintf(stderr, "rcsBind() failed. Exiting...\n");
		exit(0);
	}

	if(rcsGetSockName(s, &a) < 0) {
		fprintf(stderr, "rcsGetSockName() failed. Exiting...\n");
		exit(0);
	}

	printf("%s %u\n", inet_ntoa(a.sin_addr), ntohs(a.sin_port));

	if(rcsListen(s) < 0) {
		perror("listen"); exit(0);
	}

	memset(&a, 0, sizeof(struct sockaddr_in));
	int asock;
	while((asock = rcsAccept(s, (struct sockaddr_in *)&a)) > 0) {
		int *newasock = (int *)malloc(sizeof(int));
		*newasock = asock;
		int err;
		pthread_t t;

		if(err = pthread_create(&t, NULL, &serviceConnection, (void *)(newasock))) {
			fprintf(stderr, "pthread_create(): %s\n", strerror(err));
			exit(1);
		}
	}

	return 0;
}
