/**
 * @brief: ECE358 network utility functions 
 * @file: net_util.h 
 */

#ifndef NET_UTIL_H_
#define NET_UTIL_H_

//includes
#include <netinet/in.h>

// defines
#define PORT_RANGE_LO 10000
#define PORT_RANGE_HI 11000

// functions
uint32_t getPublicIPAddr();
int mybind(int sockfd, struct sockaddr_in *addr); 

#endif // ! NET_UTIL_H_
