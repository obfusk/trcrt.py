#!/usr/bin/python

# --                                                            ; {{{1
#
# File        : trcrt.py
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2015-05-14
#
# Copyright   : Copyright (C) 2015  Felix C. Stegerman
# Version     : v0.0.1
# License     : LGPLv3+
#
# --                                                            ; }}}1

                                                                # {{{1
"""
Python (2+3) traceroute implementation

Example
-------

...

"""
                                                                # }}}1

import binascii
import select
import socket as S
import struct
import sys

if sys.version_info.major == 2:
  def b2s(x):
    """convert bytes to str"""
    return x
else:
  def b2s(x):
    """convert bytes to str"""
    if isinstance(x, str): return x
    return x.decode("utf8")
  xrange = range

# TODO
def main(*args):
  """..."""
  import doctest
  doctest.testmod()
  return 0

# ...

def icmp_echo_request(ID, seq, data):
  """create ICMP echo request packet"""
  return icmp_packet(ICMP_ECHO_REQUEST, ID, seq, data)

def icmp_packet(msg_t, ID, seq, data):
  """create ICMP packet"""
  return icmp_header(
    msg_t, ID, seq,
    internet_checksum(icmp_header(msg_t, ID, seq, 0) + data)
  ) + data

# === ICMP ECHO REPLY & REQUEST ===================
# | type (8)  | code (8)  | checksum (16)         |
# | identifier (16)       | sequence number (16)  |
# | ... data ...                                  |
# =================================================

def icmp_header(msg_t, ID, seq, csum):
  """create ICMP header"""
  return struct.pack('!BBHHH', msg_t['TYPE'], msg_t['CODE'],
                               csum, ID, seq)

def internet_checksum(data):                                    # {{{1
  """
  calculate internet checksum as per RFC 1071

  >>> import binascii as B, trcrt as T
  >>> x = B.unhexlify("0001f203f4f5f6f7")
  >>> c = T.internet_checksum(x)
  >>> B.hexlify(T.i2b(c))
  'ddf2'
  """
  csum = 0; count = len(data); i = 0;
  while count > 1:
    csum += b2i(data[i:i+2]); count -= 2; i += 2
  if count > 0:
    csum += b2i(data[i])
  while csum >> 16:
    csum = (csum & 0xffff) + (csum >> 16)
  return csum
                                                                # }}}1

ICMP_ECHO_REPLY   = dict(TYPE = 0, CODE = 0)
ICMP_ECHO_REQUEST = dict(TYPE = 8, CODE = 0)

def b2i(x):
  """convert bytes to integer"""
  if isinstance(x, int): return x
  return int(binascii.hexlify(x), 16)

def i2b(x, n = 1):
  """convert integer to bytes of length (at least) n"""
  if isinstance(x, bytes): return x
  return binascii.unhexlify("%0*x" % (n*2,x))

if __name__ == "__main__":
  sys.exit(main(*sys.argv[1:]))

# vim: set tw=70 sw=2 sts=2 et fdm=marker :
