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

/* Order is either 0, 1 or 2, where:
    0 gives you the nextPacketId
    1 gives you total buf content converted into integer value
    2 gives you the real packet content
*/
std::string parsePacket(char* buf, char token, int order) {
  int i, j;

  std::string str(buf);

  // find the first occurrence of token
  for(i = 0; i < strlen(buf); i++) {
    if(buf[i] == token) {

      if(order == 0) {
        return str.substr(0,i);
      }
      break;
    }
  }

  // find the second occurrence of token
  for(j = i+1; j < strlen(buf); j++) {
    if(buf[j] == token) {
      if(order == 1) {
        return str.substr(i+1, j);
      }
      break;
    }
  }

  // if we couldn't find enough tokens, return string to handle error
  if(j >= strlen(buf) - 1) {
    return "";
  }

  return str.substr(j+1,strlen(buf)-1);
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
accepts a connection request on a socket (the first argument). his is a
blocking call while awaiting connection requests. The call is unblocked when a
connectionrequest is received. The address of the client is filled into the
second argument. The call returns a descriptor to a new RCS socket that can be
used to rcsSend() and rcsRecv() with the client.
*/
int rcsAccept(int sockfd, struct sockaddr_in *addr)
{

  if(!isValidSockfd(sockfd, "rcsAccept")){
    return -1;
  }

  // if socket is not listening, then it can't accept any connection request
  if(!sockets[sockfd].listening) {
    printf("rcsAccept: socket %d is not listening\n", sockfd);
    return -1;
  }

  printf("rcsAccept: Accepted\n");

  // accept a connection request
  char buf[1];
  int recv = ucpRecvFrom(sockets[sockfd].ucpSockfd, buf, 1, addr);

  if(buf[0] != 'C') {
    return -1;
  }

  // create new socket
  int newSockfd = rcsSocket();
  sockets[newSockfd].addr = addr;

  // Send to client an acknowledgement message
  buf[0] = 'Z';
  int send = ucpSendTo(sockets[newSockfd].ucpSockfd, buf, 1, addr);

  return newSockfd;
}

/*
Connects a client to a server. The socket (first argument) must have been bound
beforehand using rcsBind(). The second argument identifies the server to which
connection should be attempted. Returns 0 on success
*/
int rcsConnect(int sockfd, const struct sockaddr_in *addr)
{
  if(!isValidSockfd(sockfd, "rcsConnect")){
    return -1;
  }
  // connect client to server
  char buf[1];
  buf[0] = 'C';

  // send a connection request
  int send = ucpSendTo(sockets[sockfd].ucpSockfd, buf, 1, addr);

  // receive an acknowledgement from server
  int recv = ucpRecvFrom(sockets[sockfd].ucpSockfd, buf, 1, (struct sockaddr_in *)addr);

  ucpSetSockRecvTimeout(sockets[sockfd].ucpSockfd, 1000);

  return SUCCESS;
}

/*
blocks awaiting data on a socket (first argument). Presumably,
the socket is one that has been returned by a prior call to
rcsAccept(), or on which rcsConnect() has been successfully
called. The second argument is the buffer which is filled with
received data. The maximum amount of data that may be written
is identified by the third argument.  Returns the actual amount
ofdata received. “Amount” is the number of bytes. Data is sent
and received reliably, so any byte that is returned by this call
should be what was sent, and in the correct order.
*/
int rcsRecv(int sockfd, void *buf, int len)
{
  if(!isValidSockfd(sockfd, "rcsBind")){
    return -1;
  }

  while(true) {
    char bufRecv[256];
    int recv = ucpRecvFrom(sockets[sockfd].ucpSockfd, bufRecv, 256, sockets[sockfd].addr);

    printf("rcsRecv: received data %s\n", bufRecv);

    //incorrect recv, continue waiting on socket
    if(recv < 0) {
      printf("rcsSend: timeout %d, %s\n", recv, bufRecv);
      continue;
    }

    std::string checkSentPacketId = parsePacket(bufRecv, '@', 0);
    if(checkSentPacketId.length() <= 0) {
      printf("checkSentPacketId corrupted\n");
      continue;
    }

    int sentPacketId = atoi(checkSentPacketId.c_str());

    char responseBuf[1];
    responseBuf[0] = 'Z';
    //delay occured, send is re-sending previous packets, send ack and continue waiting on socket
    if(sentPacketId < sockets[sockfd].nextPacketId) {
      int send = ucpSendTo(sockets[sockfd].ucpSockfd, responseBuf, 1, sockets[sockfd].addr);
      printf("rcsRecv: DELAY sent acknowledgement %d\n", responseBuf[0]);
      continue;
    }
    //corrupted payload, continue waiting on socket
    std::string str = parsePacket(bufRecv, '@', 2);
    if(str.length() == 0){
      printf("Payload corrupted\n");
      continue;
    }
    char* writable = new char[str.size() + 1];
    std::copy(str.begin(), str.end(), writable);
    writable[str.size()] = '\0';
    buf = writable;

    std::string checkSumStr = parsePacket(bufRecv, '@', 1);
    //string parsed was corrupted, parsePacket returned "",cont. waiting on socket
    if(checkSumStr.length() <= 0) {
      printf("checkSumStr corrupted\n");
      continue;
    }

    int checkSum = atoi(checkSumStr.c_str());

    // handle checkSum
    int bufContent = 0;
    for (int i = 0; i < len; i++) {
      if (((char *)buf)[i] == '\n') {
        break;
      }
      bufContent += ((char *)buf)[i];
    }
    //if data was partially sent or corrupted, continue waiting on socket
    if(checkSum != bufContent) {
      printf("checkSum %d, %d\n", checkSum, bufContent);
      continue;
    }

    int send = ucpSendTo(sockets[sockfd].ucpSockfd, responseBuf, 1, sockets[sockfd].addr);
    printf("rcsRecv: sent acknowledgement %d\n", responseBuf[0]);

    sockets[sockfd].nextPacketId++;

    return strlen((char *)buf);
  }

  return -1;
}

/*
blocks sending data. The first argument is a socket descriptor that
has been returned by a prior call to rcsAccept(), or on which rcsConnect()
has been successfully called.  The second argument is the buffer that
contains the data to be sent. The third argument is the number of bytes
to be sent. Returns the actual number of bytes sent.  If rcsSend()
returns with a non-negative return value, then we know that so many
bytes were reliably received by the other end
*/
int rcsSend(int sockfd, void *buf, int len)
{
  // enter the packetID at the beginning of the buf that will be sent
  std::ostringstream newBuf;
  newBuf << sockets[sockfd].nextPacketId;
  sockets[sockfd].nextPacketId++;
  newBuf << "@";

  // append the total bufContent in integer to the buf that will be sent
  int bufContent = 0;
  for (int i = 0; i < len; i++) {
    if (((char *)buf)[i] == '\n') {
      break;
    }
    bufContent += ((char *)buf)[i];
  }
  newBuf << bufContent;
  newBuf << "@";

  // append the buf to the buffer that will be sent
  int packetIdLength = newBuf.str().length();
  newBuf << (char *)buf;

  printf("rcsSend: sending data:\nbuf: %s\n", (char *)buf);

  int sendResp = ucpSendTo(sockets[sockfd].ucpSockfd, newBuf.str().c_str(),
                           len + packetIdLength, sockets[sockfd].addr);
  printf("rcsSend: sent data %s\n", newBuf.str().c_str());

  // check for acknowledgement
  while (true) {
    char bufRecv[1];
    int recvResp = ucpRecvFrom(sockets[sockfd].ucpSockfd, bufRecv, 1, sockets[sockfd].addr);

    printf("rcsSend: received acknowledgement : %c, %d\n", bufRecv[0], recvResp);

    // if it did not receive anything, send the last message again
    if (recvResp < 0) {
      printf("rcsSend: timeout %s\n", newBuf.str().c_str());
      ucpSendTo(sockets[sockfd].ucpSockfd, newBuf.str().c_str(),
                len + packetIdLength, sockets[sockfd].addr);

      continue;
    }

    // if ACKNOWLEDGE mark is received, return # of bytes
    if (bufRecv[0] == 'Z') {
      printf("acknowledged\n");
      return sendResp;
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
