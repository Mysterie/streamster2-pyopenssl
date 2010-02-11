 #  
### Makefile for server
 #

STRIP = strip

SHELL= /bin/sh
LIBS = -lssl

# Use this when you want DEBUG info
#CFLAGS = -DLINUX -D_REENTRANT -pipe -g -O2 -Wall -Dlint -funroll-loops -fomit-frame-pointer -I../common -DDEBUG
CFLAGS = -DLINUX -D_REENTRANT -pipe -g -O2 -Wall -Werror -Dlint -funroll-loops -fomit-frame-pointer -I../common

all: dtls_server

dtls_server.o: dtls_server.c
	$(CC) $(CFLAGS) -c dtls_server.c
sslmgr.o: ../common/sslmgr.c ../common/sslmgr.h
	$(CC) $(CFLAGS) -c ../common/sslmgr.c

dtls_server: dtls_server.o sslmgr.o
	
	$(CC) -o dtls_server $(LIBS) dtls_server.o sslmgr.o
	
	$(STRIP) dtls_server	
	$(RM) -f *.o

install: all

clean:
	$(RM) -f *.o dtls_server

