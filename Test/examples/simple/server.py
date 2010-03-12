# -*- coding: latin-1 -*-
#
# Copyright (C) 2001 Martin Sjögren and AB Strakt, All rights reserved
# Copyright (C) Jean-Paul Calderone 2008, All rights reserved

"""
Simple echo server, using nonblocking I/O
"""

from OpenSSL import SSL
import sys, os, select, socket

def verify_cb(conn, cert, errnum, depth, ok):
    # This obviously has to be updated
    print 'Got certificate: %s' % cert.get_subject()
    return ok

if len(sys.argv) < 2:
    print 'Usage: python[2] server.py PORT'
    sys.exit(1)

dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir

# Initialize context
ctx = SSL.Context(SSL.DTLSv1_METHOD) # SSLv23_METHOD ! DTLSv1_METHOD
ctx.set_options(SSL.OP_NO_SSLv3)
ctx.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb) # Demand a certificate
ctx.use_privatekey_file (os.path.join(dir, 'server.pkey'))
ctx.use_certificate_file(os.path.join(dir, 'server.cert'))
ctx.load_verify_locations(os.path.join(dir, 'CA.cert'))

# Set up server
addr = ('', int(sys.argv[1])) 
server = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) # SOCK_STREAM ! SOCK_DGRAM
#server.bind(addr)

print "wait client ..." 
#server.recv(10)
print "connected :)"
# clients = {}
# writers = {}
	
#server.close()
