 #  
### Makefile for server
 #

STRIP = strip

SHELL= /bin/sh
LIBS = -lssl -lcrypto

# Use this when you want DEBUG info
#CFLAGS = -DLINUX -D_REENTRANT -pipe -g -O2 -Wall -Dlint -funroll-loops -fomit-frame-pointer -I../common -I -DDEBUG
# CFLAGS = -DLINUX -D_REENTRANT -pipe -g -O2 -Wall -Werror -Dlint -funroll-loops -fomit-frame-pointer -I../common -I/usr/local/ssl/include/ 
CFLAGS = -DLINUX -D_REENTRANT -pipe -g -O2 -Wall -Dlint -funroll-loops -fomit-frame-pointer -I../common -I/usr/local/ssl/include/ 
# LDFLAGS = -L/usr/local/ssl/lib/ 

all: dtls_server

dtls_server.o: dtls_server.c
	$(CC) $(CFLAGS) -c dtls_server.c
sslmgr.o: ../common/sslmgr.c ../common/sslmgr.h
	$(CC) $(CFLAGS) -c ../common/sslmgr.c

dtls_server: dtls_server.o sslmgr.o
	
	$(CC) -L/usr/local/ssl/lib/ -o dtls_server $(LIBS) dtls_server.o sslmgr.o
	
	$(STRIP) dtls_server	
	$(RM) -f *.o

install: all

clean:
	$(RM) -f *.o dtls_server

