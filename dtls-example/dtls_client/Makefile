LIBS=
CPP=g++
CC=gcc

COFLAGS=-O2
CWFLAGS=-Wall -Werror
CIFLAGS=-I. -I../common
#Uncomment this if you want more debug messages
#CMFLAGS=-DDEBUG 
CMFLAGS=
CLIBS=-lssl

CFLAGS= $(CWFLAGS) $(COFLAGS) $(CIFLAGS) $(CMFLAGS)

all: dtls_client

dtls_client.o: dtls_client.c
	$(CC) $(CFLAGS) -c dtls_client.c
sslmgr.o: ../common/sslmgr.h ../common/sslmgr.c
	$(CC) $(CFLAGS) -c ../common/sslmgr.c
	
dtls_client: dtls_client.o sslmgr.o
	$(CC) -o dtls_client dtls_client.o sslmgr.o $(CLIBS)
	$(RM) *.o

install: compile

clean:
	$(RM) -f *.o dtls_client
		
distclean: clean
