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

from __future__ import print_function

import binascii
import os
import select
import socket as S
import struct
import sys
import time

if sys.version_info.major == 2:
  def b2s(x):
    """convert bytes to str"""
    return x
  def s2b(x):
    """convert str to bytes"""
    return x
else:
  def b2s(x):
    """convert bytes to str"""
    if isinstance(x, str): return x
    return x.decode("utf8")
  def s2b(x):
    """convert str to bytes"""
    if isinstance(x, bytes): return x
    return x.encode("utf8")
  xrange = range

DEFAULT_ID      = os.getpid()
DEFAULT_MSG     = "Hi" * 24
DEFAULT_SLEEP   = 0.5
DEFAULT_TIMEOUT = 5

# TODO
def main(*args):
  """..."""
  import code; code.interact(local=globals())
  import doctest
  doctest.testmod()
  return 0

def verbose_ping(addr, count = None, timeout = DEFAULT_TIMEOUT):# {{{1
  """ping addr verbosely"""
  info = S.gethostbyname_ex(addr); l = len(DEFAULT_MSG)
  print("PING {} ({}) {}({}) bytes of data." \
    .format(info[0], info[2][0], l, l + 28))
  for (seq, p, td) in ping(addr, count, timeout):
    if p == TIMEOUT:
      print("timeout!") # TODO
    elif is_icmp_dest_unreach(p):
      fmt = "From {} icmp_seq={} {}"
      print(fmt.format(p["recv_addr"][0], p["echo"]["seq"],
                       ICMP_DEST_UNREACHABLE_CODES[p["CODE"]]))
    else:
      fmt = "{} bytes from {}: icmp_req={} ttl={} time={:.2f} ms"
      print(fmt.format(p["length"] - 28, p["recv_addr"][0],
                       seq, p["TTL"], td*1000))
  # TODO: statistics
                                                                # }}}1

def ping(addr, count, timeout):                                 # {{{1
  """yield pings to addr"""
  seq = 1; sock = S.socket(S.AF_INET, S.SOCK_RAW, S.IPPROTO_ICMP)
  while 1:
    if count is not None:
      if count <= 0: break
      count -= 1
    t1  = time.time()
    ID  = send_ping(sock, addr, seq)[0]
    ret = recv_ping(sock, addr, ID, seq, timeout)
    t2  = time.time()
    yield (seq, ret, t2 - t1)
    seq += 1
    time.sleep(DEFAULT_SLEEP)
  sock.close()
                                                                # }}}1

def send_ping(sock, addr, seq, ID = DEFAULT_ID, msg = DEFAULT_MSG):
  """send ping"""
  t   = time.time()                 # time in secs + usecs
  td  = struct.pack("!LL", int(t), int(t * 10**6) % 10**6)
  pkt = icmp_echo_request(ID, seq, td + msg)
  sock.sendto(pkt, (addr, 1))
  return (ID, seq, msg)

def recv_ping(sock, addr, ID, seq, timeout):                    # {{{1
  """receive ping reply"""
  def f(pkt, recv_addr):
    data = unpack_icmp(pkt)
    if data is None: return None
    data.update(recv_addr = recv_addr, length = len(pkt))
    if is_icmp_echoreply(data) and data["ID"]  == ID and \
                                   data["seq"] == seq:
      return data
    if is_icmp_dest_unreach(data):
      data2 = unpack_icmp(data["data"])
      if  data2 is not None and is_icmp_echo(data2) and \
          data2["ID"] == ID and data2["seq"] == seq:
        data.update(echo = data2)
        return data
    return None   # ignore
  return recv_reply(sock, timeout, f)
                                                                # }}}1

def recv_reply(sock, timeout, f):                               # {{{1
  """receive reply"""
  time_left = timeout
  while 1:
    t1 = time.time()
    r, w, x = select.select([sock], [], [], timeout)
    if r == []: return TIMEOUT
    t2 = time.time()
    pkt, recv_addr = sock.recvfrom(1024)
    ret = f(pkt, recv_addr)
    if ret is not None: return ret
    time_left -= (t2 - t1)
    if time_left <= 0: return TIMEOUT
                                                                # }}}1

# === ICMP ======================================================== #
# type (8)       | code (8)       | checksum (16)                   #
# ================================================================= #

# === ICMP DEST UNREACH =========================================== #
# unused (16)                     | next-hop MTU (16)               #
#       IP header + first 8 bytes of original datagram's data       #
# ================================================================= #

# === ICMP ECHO REPLY & REQUEST =================================== #
# identifier (16)                 | sequence number (16)            #
#                           ... data ...                            #
# ================================================================= #

def is_icmp_dest_unreach(icmp_data):
  """is ICMP destination unreachable?"""
  return icmp_data["TYPE"] == ICMP_DEST_UNREACH

def is_icmp_echoreply(icmp_data):
  """is ICMP echo reply?"""
  return  dict(TYPE = icmp_data["TYPE"], CODE = icmp_data["CODE"]) \
            == ICMP_ECHOREPLY

def is_icmp_echo(icmp_data):
  """is ICMP echo?"""
  return  dict(TYPE = icmp_data["TYPE"], CODE = icmp_data["CODE"]) \
            == ICMP_ECHO

def unpack_icmp(pkt):
  """unpack ICMP packet from IP packet"""
  d = unpack_ip(pkt)
  if d["PROTO"] != S.IPPROTO_ICMP: return None
  icmp_hdr, data = pkt[20:28], pkt[28:]
  TYPE, code, _, ID, seq = struct.unpack("!BBHHH", icmp_hdr)
  d.update(TYPE = TYPE, CODE = code, ID = ID, seq = seq, data = data)
  return d

def icmp_echo_request(ID, seq, data):                           # {{{1
  """
  create ICMP echo request packet

  >>> import binascii as B, trcrt as T
  >>> p = T.icmp_echo_request(3553, 1, "HIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefg")
  >>> B.hexlify(p)
  '080074980de1000148494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6061626364656667'
  """
  return icmp_packet(ICMP_ECHO, ID, seq, data)
                                                                # }}}1

def icmp_packet(msg_t, ID, seq, data):
  """create ICMP packet"""
  return icmp_header(
    msg_t, ID, seq,
    internet_checksum(icmp_header(msg_t, ID, seq, 0) + data)
  ) + data

def icmp_header(msg_t, ID, seq, csum):
  """create ICMP header"""
  return struct.pack("!BBHHH", msg_t["TYPE"], msg_t["CODE"],
                               csum, ID, seq)

# === IP ========================================================== #
# version (8)    | service type   | length (16)                     #
# identification (16)             | flags and offset (16)           #
# TTL (8)        | protocol (8)   | checksum (16)                   #
#                        source IP address (32)                     #
#                     destination IP address (32)                   #
# ================================================================= #

def unpack_ip(pkt):
  """unpack IP packet"""
  ttl, proto = pkt[8], pkt[9]
  return dict(TTL = b2i(ttl), PROTO = b2i(proto))

def internet_checksum(data):                                    # {{{1
  """
  calculate internet checksum as per RFC 1071

  >>> import binascii as B, trcrt as T
  >>> x = B.unhexlify(b"0001f203f4f5f6f7")
  >>> c = T.internet_checksum(x)
  >>> T.b2s(B.hexlify(T.i2b(c)))
  '220d'
  """
  csum = 0; count = len(data); i = 0;
  while count > 1:
    csum += b2i(data[i:i+2])
    csum &= 0xffffffff
    count -= 2; i += 2
  if count > 0:
    csum += b2i(data[i])
    csum &= 0xffffffff
  while csum >> 16:
    csum = (csum & 0xffff) + (csum >> 16)
  return ~csum & 0xffff
                                                                # }}}1

ICMP_ECHOREPLY        = dict(TYPE = 0, CODE = 0)
ICMP_ECHO             = dict(TYPE = 8, CODE = 0)

ICMP_DEST_UNREACH     = 3

ICMP_NET_UNREACH      = 0                                       # {{{1
ICMP_HOST_UNREACH     = 1
ICMP_PROT_UNREACH     = 2
ICMP_PORT_UNREACH     = 3
ICMP_FRAG_NEEDED      = 4
ICMP_SR_FAILED        = 5
ICMP_NET_UNKNOWN      = 6
ICMP_HOST_UNKNOWN     = 7
ICMP_HOST_ISOLATED    = 8
ICMP_NET_ANO          = 9
ICMP_HOST_ANO         = 10
ICMP_NET_UNR_TOS      = 11
ICMP_HOST_UNR_TOS     = 12
ICMP_PKT_FILTERED     = 13
ICMP_PREC_VIOLATION   = 14
ICMP_PREC_CUTOFF      = 15                                      # }}}1

ICMP_DEST_UNREACHABLE_CODES = {                                 # {{{1
  ICMP_NET_UNREACH    : "Destination Net Unreachable",
  ICMP_HOST_UNREACH   : "Destination Host Unreachable",
  ICMP_PROT_UNREACH   : "Destination Protocol Unreachable",
  ICMP_PORT_UNREACH   : "Destination Port Unreachable",
  ICMP_FRAG_NEEDED    : "Frag needed and DF set",   # mtu?
  ICMP_SR_FAILED      : "Source Route Failed",
  ICMP_NET_UNKNOWN    : "Destination Net Unknown",
  ICMP_HOST_UNKNOWN   : "Destination Host Unknown",
  ICMP_HOST_ISOLATED  : "Source Host Isolated",
  ICMP_NET_ANO        : "Destination Net Prohibited",
  ICMP_HOST_ANO       : "Destination Host Prohibited",
  ICMP_NET_UNR_TOS    : "Destination Net Unreachable for Type of Service",
  ICMP_HOST_UNR_TOS   : "Destination Host Unreachable for Type of Service",
  ICMP_PKT_FILTERED   : "Packet filtered",
  ICMP_PREC_VIOLATION : "Precedence Violation",
  ICMP_PREC_CUTOFF    : "Precedence Cutoff",
}                                                               # }}}1

TIMEOUT           = "__timeout__"

def b2i(x):
  """convert bytes to integer"""
  if isinstance(x, int): return x
  return int(binascii.hexlify(x), 16)

def i2b(x, n = 1):
  """convert integer to bytes of length (at least) n"""
  if isinstance(x, bytes): return x
  return binascii.unhexlify(s2b("%0*x" % (n*2,x)))

if __name__ == "__main__":
  sys.exit(main(*sys.argv[1:]))

# vim: set tw=70 sw=2 sts=2 et fdm=marker :
