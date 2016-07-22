# Makefile
# ECE358 Computer Networks
# Yiqing Huang, 2016/06/17

INCLUDE =
CC = gcc
CFLAGS = -I$(INCLUDE) -Wall -g  -D_BSD_SOURCE
LD = gcc
LDFLAGS = -lpthread
LDLIBS = 

NET_SRCS = net_util.c ucp.c rcs.c 
MAIN_SRCS = tcp-server.c tcp-client.c rcsapp-server.c rcsapp-client.c
SRCS = $(NET_SRCS) $(MAIN_SRCS) 

OBJS_LIB = net_util.o
OBJS_RCS = ucp.o rcs.o
OBJS_TCP_S = $(OBJS_LIB) tcp-server.o
OBJS_TCP_C = $(OBJS_LIB) tcp-client.o
OBJS_RCS_S = $(OBJS_LIB) $(OBJS_RCS) rcsapp-server.o
OBJS_RCS_C = $(OBJS_LIB) $(OBJS_RCS) rcsapp-client.o

TARGETS = rcsapp-server rcsapp-client tcp-server tcp-client 

all: rcsapp tcpapp 

rcsapp: rcsapp-server rcsapp-client

tcpapp: tcp-server tcp-client

tcp-server: $(OBJS_TCP_S) 
	$(LD) -o $@ $^ $(LDLIBS) $(LDFLAGS) 

tcp-client: $(OBJS_TCP_C) 
	$(LD) -o $@ $^ $(LDLIBS) $(LDFLAGS) 

rcsapp-server: $(OBJS_RCS_S) 
	$(LD) -o $@ $^ $(LDLIBS) $(LDFLAGS) 

rcsapp-client: $(OBJS_RCS_C) 
	$(LD) -o $@ $^ $(LDLIBS) $(LDFLAGS) 

%.o: %.c 
	$(CC) $(CFLAGS) -c $< 

%.d: %.c
	g++ $(CFLAGS) -MM -MF $@ $<

-include $(SRCS:.c=.d)

.PHONY: clean
clean:
	rm -f *.d *.o *.a $(TARGETS) 
