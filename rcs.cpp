#include <stdio.h>
#include <string.h>
#include <sstream>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <stdlib.h>

#include "net_util.h"
#include "rcs.h"
#include "ucp.h"

#define SUCCESS 0
#define CONNECT 1
#define ACKNOWLEDGE 2

class Socket {
 public:
  int ucpSockfd;
  sockaddr_in* addr;
  bool listening;
  int nextPacketId;

  Socket(int ucpSockfd) : ucpSockfd(ucpSockfd), addr(NULL), listening(false), nextPacketId(0) {}
};

std::vector<Socket> sockets; // Move this to rcs.h file

//err handling
bool isValidSockfd(int sockfd, const char* functionName){
  if (sockfd < 0 || sockfd >= sockets.size()) {
    printf("Not a valid sockfd for func: %s\n", functionName);
    return false;
  }
  return true;
}

// order is either 0 or 1 where 0 gives you string before first token
// 1 returns string before second token
std::string parsePacket(char* buf, char token, int order) {
  for(int i = 0; i < strlen(buf); i++) {
    if(buf[i] == token) {

      std::string str(buf);

      if(order == 0) {
        return str.substr(0,i);
      }

      return str.substr(i,strlen(buf)-1);
    }
  }

  return "";
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
  if(!isValidSockfd(sockfd, "rcsBind")){
    return -1;
  }

  sockets[sockfd].addr = addr;

  if(sockets[sockfd].addr->sin_port == 0){
    // TODO: fill with random port?
  }

  return ucpBind(sockets[sockfd].ucpSockfd, addr);
}

int rcsGetSockName(int sockfd, struct sockaddr_in *addr)
{
  if(!isValidSockfd(sockfd, "rcsGetSockName")){
    return -1;
  }

  return ucpGetSockName(sockets[sockfd].ucpSockfd, addr);
}

int rcsListen(int sockfd)
{
  if(!isValidSockfd(sockfd, "rcsListen")){
    return -1;
  }

  sockets[sockfd].listening = true;
  return SUCCESS;
}

/*
accepts a connection request on a socket (the first argument).This is a blocking call while awaiting connection requests. The call is unblocked when a connectionrequest is received. The address of the client is filled into the second argument. The call returns a descriptor to a new RCS socket that can be used to rcsSend() and rcsRecv() with the client.
*/
int rcsAccept(int sockfd, struct sockaddr_in *addr)
{

  if(!isValidSockfd(sockfd, "rcsAccept")){
    return -1;
  }
  printf("rcsAccept: Accepted\n");

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
  if(!isValidSockfd(sockfd, "rcsConnect")){
    return -1;
  }

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
  while(true) {
    char bufRecv[256];
    int recv = ucpRecvFrom(sockets[sockfd].ucpSockfd, bufRecv, 256, sockets[sockfd].addr);
    printf("rcsRecv: Receiving:\nbuf: %s\n", (char *)buf);

    int sentPacketId = atoi(parsePacket(bufRecv, '@', 1).c_str());

    if(sentPacketId != sockets[sockfd].nextPacketId) {
      continue;
    }

    int responseBuf[1];
    responseBuf[0] = ACKNOWLEDGE;

    int send = ucpSendTo(sockets[sockfd].ucpSockfd, responseBuf, 1, sockets[sockfd].addr);

    sockets[sockfd].nextPacketId++;

    std::string str = parsePacket(bufRecv, '@', 0);
    char * writable = new char[str.size() + 1];
    std::copy(str.begin(), str.end(), writable);
    writable[str.size()] = '\0';
    buf = writable;

    return strlen((char *)buf);
  }

  return -1;
}

/*
blocks sending data. The first argument is a socket descriptor that has been returned by a prior call to rcsAccept(), or on which rcsConnect() has been successfully called.  The second argument is the buffer that contains the data to be sent. The third argument is the number of bytes to be sent. Returns the actual number of bytes sent.  If rcsSend()returns with a non-negative return value, then we know that so many bytes were reliably received by the other end
*/
int rcsSend(int sockfd, void *buf, int len)
{
  std::ostringstream newBuf;
  newBuf << sockets[sockfd].nextPacketId;
  sockets[sockfd].nextPacketId++;
  newBuf << "@";

  int packetIdLength = newBuf.str().length();
  newBuf << (char *)buf;

  printf("rcsSend: Sending:\nbuf: %s\n", (char *)buf);
  int ucpSentBytes = ucpSendTo(sockets[sockfd].ucpSockfd, newBuf.str().c_str(),
                        len + packetIdLength, sockets[sockfd].addr);

  // check for acknowledgement
  while (true) {
    int bufRecv[1];
    int bytes = ucpRecvFrom(sockets[sockfd].ucpSockfd, bufRecv, 1, sockets[sockfd].addr);

    if (bufRecv[0] == ACKNOWLEDGE) {
      return ucpSentBytes;
    }
  }
  return -1; // should not reach here
}

int rcsClose(int sockfd)
{
  int close = ucpClose(sockets[sockfd].ucpSockfd);
  sockets.erase(sockets.begin() + sockfd);
  printf("Closed\n");

  return close;
}
