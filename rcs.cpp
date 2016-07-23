#include <stdio.h>
#include <string.h>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net_util.h"
#include "rcs.h"
#include "ucp.h"

#define SUCCESS 0;
#define CONNECT 1;
#define ACKNOWLEDGE 2;

class Socket {
 public:
  int ucpSockfd;
  sockaddr_in* addr;
  bool listening;

  Socket(int ucpSockfd) : ucpSockfd(ucpSockfd), addr(NULL), listening(false) {}
};

std::vector<Socket> sockets; // Move this to rcs.h file

//err handling
bool isValidSockfd(int sockfd){
  if (sockfd < 0 || sockfd >= sockets.size()) {
    printf("Not a valid sockfd");
    return false;
  }
  return true;
}

int rcsSocket()
{
  int ucpSockfd = ucpSocket();

  Socket socket = Socket(ucpSockfd);

  sockets.push_back(socket);

  return sockets.size() - 1;
}

int rcsBind(int sockfd, struct sockaddr_in *addr)
{
  // TODO: err handling

  sockets[sockfd].addr = addr;

  if(sockets[sockfd].addr->sin_port == 0){
    // TODO: fill with random port?
  }

  return ucpBind(sockets[sockfd].ucpSockfd, addr);
}

int rcsGetSockName(int sockfd, struct sockaddr_in *addr)
{
  // TODO: err handling

  return ucpGetSockName(sockets[sockfd].ucpSockfd, addr);
}

int rcsListen(int sockfd)
{
  // TODO: err handling

  sockets[sockfd].listening = true;
  return SUCCESS;
}

/*
accepts a connection request on a socket (the first argument).This is a blocking call while awaiting connection requests. The call is unblocked when a connectionrequest is received. The address of the client is filled into the second argument. The call returns a descriptor to a new RCS socket that can be used to rcsSend() and rcsRecv() with the client.
*/
int rcsAccept(int sockfd, struct sockaddr_in *addr)
{
  printf("rcsAccept: Accepted\n");
  // TODO: err handling

  // accept a connection request
  int buf[1];

  int recv = ucpRecvFrom(sockets[sockfd].ucpSockfd, buf, 1, addr);

  // TODO: handle buf

  // create new socket
  int newSockfd = rcsSocket();
  sockets[newSockfd].addr = addr;

  // Send to client an acknowledgement message
  buf[0] = ACKNOWLEDGE;
  int send = ucpSendTo(sockets[newSockfd].ucpSockfd, buf, 1, addr);
  // TODO: error check on send

  return newSockfd;
}

/*
Connects a client to a server. The socket (first argument) must have been bound beforehand using rcsBind(). The second argument identifies the server to which connection should be attempted. Returns 0 on success
*/
int rcsConnect(int sockfd, const struct sockaddr_in *addr)
{
  printf("rcsConnect: Connected\n");
  if (sockfd < 0 || sockfd >= sockets.size()) {
    //  TODO: err handling
  }

  // connect client to server
  int buf[1];
  buf[0] = CONNECT;

  int send = ucpSendTo(sockets[sockfd].ucpSockfd, buf, 1, addr);
  // TODO: err handle on send

  int recv = ucpRecvFrom(sockets[sockfd].ucpSockfd, buf, 1, (struct sockaddr_in *)addr);
  // TODO: err handle on recv

  return SUCCESS;
}

/*
blocks awaiting data on a socket (first argument). Presumably, the socket is one that has been returned by a prior call to rcsAccept(), or on which rcsConnect() has been successfully called. The second argument is the buffer which is filled with received data. The maximum amount of data that may be written is identified by the third argument.  Returns the actual amount ofdata received. “Amount” is the number of bytes. Data is sent and received reliably, so any byte that is returned by this call should be what was sent, and in the correct order.
*/
int rcsRecv(int sockfd, void *buf, int len)
{
  // TODO: err handling

  int recv = ucpRecvFrom(sockets[sockfd].ucpSockfd, buf, len, sockets[sockfd].addr);
  printf("rcsRecv: Receiving:\nbuf: %s\n", (char *)buf);
  return recv;
}

/*
blocks sending data. The first argument is a socket descriptor that has been returned by a prior call to rcsAccept(), or on which rcsConnect() has been successfully called.  The second argument is the buffer that contains the data to be sent. The third argument is the number of bytes to be sent. Returns the actual number of bytes sent.  If rcsSend()returns with a non-negative return value, then we know that so many bytes were reliably received by the other end
*/
int rcsSend(int sockfd, void *buf, int len)
{
  printf("rcsSend: Sending:\nbuf: %s\n", (char *)buf);
  int bytes = ucpSendTo(sockets[sockfd].ucpSockfd, buf, len, sockets[sockfd].addr);

  return bytes;
}

int rcsClose(int sockfd)
{
  int close = ucpClose(sockets[sockfd].ucpSockfd);
  sockets.erase(sockets.begin() + sockfd);
  printf("Closed\n");

  return close;
}
