/**
 * @brief: ECE358 RCS API interface header
 *
 */
#ifndef RCS_H_
#define RCS_H_

#include <netinet/in.h>

int rcsSocket();
int rcsBind(int sockfd, struct sockaddr_in *addr);
int rcsGetSockName(int sockfd, struct sockaddr_in *addr);
int rcsListen(int sockfd);
int rcsAccept(int sockfd, struct sockaddr_in *addr);
int rcsConnect(int sockfd, const struct sockaddr_in *addr);
int rcsRecv(int sockfd, void *buf, int len);
int rcsSend(int sockfd, void *buf, int len);
int rcsClose(int sockfd);

#endif // RCS_H_
