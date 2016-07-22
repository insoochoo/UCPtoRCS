/**
 * @brief: ECE358 RCS API interface dummy implementation 
 *
 */
#include "rcs.h"
#include "ucp.h"

int rcsSocket() 
{
	return -1;
}

int rcsBind(int sockfd, struct sockaddr_in *addr) 
{
	return -1;
}

int rcsGetSockName(int sockfd, struct sockaddr_in *addr) 
{
	return -1;
}

int rcsListen(int sockfd)
{
	return -1;
}

int rcsAccept(int sockfd, struct sockaddr_in *addr)
{
	return -1;
}

int rcsConnect(int sockfd, const struct sockaddr_in *addr)
{
	return -1;
}

int rcsRecv(int sockfd, void *buf, int len)
{
	return -1;
}

int rcsSend(int sockfd, void *buf, int len)
{
	return -1;
}

int rcsClose(int sockfd)
{
	return -1;
}
