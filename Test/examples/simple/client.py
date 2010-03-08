# -*- coding: latin-1 -*-
#
# Copyright (C) 2001 Martin Sjögren and AB Strakt, All rights reserved
# Copyright (C) Jean-Paul Calderone 2008, All rights reserved

"""
Simple SSL client, using blocking I/O
"""

from OpenSSL import SSL
import sys, os, select, socket

if len(sys.argv) < 3:
  print 'Usage: python[2] client.py HOST PORT'
  sys.exit(1)

def verify_cb(conn, cert, errnum, depth, ok):
  # This obviously has to be updated
  print 'Got certificate: %s' % cert.get_subject()
  return ok
	
dir = os.path.dirname(sys.argv[0])
if dir == '':
  dir = os.curdir

ctx = SSL.Context(SSL.DTLSv1_METHOD) # SSLv23_METHOD ! DTLSv1_METHOD
ctx.set_verify(SSL.VERIFY_PEER, verify_cb)
ctx.use_privatekey_file (os.path.join(dir, 'client.pkey'))
ctx.use_certificate_file(os.path.join(dir, 'client.cert'))
ctx.load_verify_locations(os.path.join(dir, 'CA.cert'))

sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) # SOCK_STREAM ! SOCK_DGRAM
sock.connect((sys.argv[1], int(sys.argv[2])))

#sock.send("Test", addr)

#while 1:
#  line = sys.stdin.readline()
#  if line == '':
#		break
#		try:
#			sock.sendto(line, addr)
#			sys.stdout.write(sock.recvfrom(10))
#			sys.stdout.flush()
#		except SSL.Error:
#			print 'Connection died unexpectedly'
#			break

sock.shutdown()
sock.close()