/**
 * @brief: RCS API interface implementation using standard socket (not UCP protocol!!!)
 *
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "rcs.h"
#include "ucp.h"

int rcsSocket() 
{
	return socket(AF_INET, SOCK_STREAM, 0);
}

int rcsBind(int sockfd, struct sockaddr_in *addr) 
{
	return (mybind(sockfd, addr));
}

int rcsGetSockName(int sockfd, struct sockaddr_in *addr) 
{
	socklen_t len = (socklen_t)sizeof(struct sockaddr_in);
	return(getsockname(sockfd, (struct sockaddr *)addr, &len));
}

int rcsListen(int sockfd)
{
	return listen(sockfd, 0); 
}

int rcsAccept(int sockfd, struct sockaddr_in *addr)
{
	socklen_t len = (socklen_t)sizeof(struct sockaddr_in);
	return(accept(sockfd, (struct sockaddr *)addr, &len));
}

int rcsConnect(int sockfd, const struct sockaddr_in *addr)
{
	socklen_t len = (socklen_t)sizeof(struct sockaddr_in);
	return(connect(sockfd, (struct sockaddr *)addr, len));
}

int rcsRecv(int sockfd, void *buf, int len)
{
	return (int) recv(sockfd, buf, len, 0);
}

int rcsSend(int sockfd, void *buf, int len)
{
	return (int) send(sockfd, buf, len, 0);
}

int rcsClose(int sockfd)
{
	return close(sockfd); 
}
