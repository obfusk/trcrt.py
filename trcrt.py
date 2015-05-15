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

Examples
--------

>>> import trcrt as T

>>> T.verbose_traceroute_icmp("localhost")        # doctest: +ELLIPSIS
traceroute to localhost (127.0.0.1), 30 hops max, 48 byte packets
 1  localhost (127.0.0.1)  ... ms  ... ms  ... ms

>>> T.verbose_traceroute_icmp("example.com")      # doctest: +ELLIPSIS
traceroute to example.com (93.184.216.34), 30 hops max, 48 byte packets
 1  ... (...)  ... ms  ... ms  ... ms
 2  ...
... ... (...)  ... ms  ... ms  ... ms
... 93.184.216.34 (93.184.216.34)  ... ms  ... ms  ... ms

...

>>> T.verbose_ping("example.com", 1)              # doctest: +ELLIPSIS
PING example.com (93.184.216.34) 48(76) bytes of data.
56 bytes from 93.184.216.34 (93.184.216.34): icmp_req=1 ttl=63 time=... ms
"""
                                                                # }}}1

from __future__ import print_function

import argparse
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

__version__       = "0.0.1"

DEFAULT_HOPS      = 30
DEFAULT_PING_WAIT = 1
DEFAULT_QUERIES   = 3
DEFAULT_TIMEOUT   = 5
DEFAULT_WAIT      = 0

DEFAULT_ID        = os.getpid()
DEFAULT_MSG       = b"Hi" * 24

def main(*args):                                                # {{{1
  p = argparse.ArgumentParser(description = "traceroute (& ping)",
                              epilog      = "the default is to run "
                                            "traceroute and use "
                                            "ICMP ECHO probe packets",
                              add_help    = False)
  p.add_argument("host", metavar = "HOST", nargs = "?",
                 help = "the name or IP address "
                        "of the destination host")
  p.add_argument("--help", action = "help",
                 help = "show this help message and exit")
  p.add_argument("--version", action = "version",
                 version = "%(prog)s {}".format(__version__))
  p.add_argument("--hops", "-h", type = int, action = "store",
                 help = "the maximum number of hops (max TTL) "
                        "(default: %(default)s)")
  p.add_argument("--queries", "-q", type = int, action = "store",
                 help = "the number of probe packets per hop "
                        "(default: %(default)s)")
  p.add_argument("--ping", "-P", dest = "f", action = "store_const",
                 const = verbose_ping,
                 help = "ping (instead of traceroute)")
  p.add_argument("--count", "-c", type = int, action = "store",
                 help = "stop after sending COUNT pings")
  p.add_argument("--tcp", "-T", dest = "f", action = "store_const",
                 const = verbose_traceroute_tcp,
                 help = "use TCP SYN probe packets")
  p.add_argument("--udp", "-U", dest = "f", action = "store_const",
                 const = verbose_traceroute_udp,
                 help = "use UDP probe packets")
  wait_default = "{} for traceroute and {} for ping" \
    .format(DEFAULT_WAIT, DEFAULT_PING_WAIT)
  p.add_argument("--sendwait", "-z", dest = "wait", type = float,
                 action = "store",
                 help = "the time interval between probes "
                        "(default: {})".format(wait_default))
  p.add_argument("--timeout", "-w", type = float, action = "store",
                 help = "the timeout "
                        "(default: %(default)s)")
  p.add_argument("--test", action = "store_true",
                 help = "run tests (and no traceroute or ping)")
  p.add_argument("--verbose", "-v", action = "store_true",
                 help = "run tests verbosely")
  p.set_defaults(
    f         = verbose_traceroute_icmp,
    count     = None,
    hops      = DEFAULT_HOPS,
    queries   = DEFAULT_QUERIES,
    wait      = None,
    timeout   = DEFAULT_TIMEOUT,
  )
  n = p.parse_args(args)
  if n.test:
    import doctest
    doctest.testmod(verbose = n.verbose)
    return 0
  if n.host is None:
    print("{}: error: too few arguments".format(p.prog),
          file = sys.stderr)
    return 2
  try:
    if n.f == verbose_ping:
      n.f(n.host, n.count, n.timeout,
          n.wait if n.wait is not None else DEFAULT_PING_WAIT)
    else:
      n.f(n.host, n.hops, n.queries, n.timeout,
          n.wait if n.wait is not None else DEFAULT_WAIT)
  except KeyboardInterrupt:
    if not (n.f == verbose_ping and n.count is None): return 1
  return 0
                                                                # }}}1

def verbose_traceroute_icmp(dest,                               # {{{1
                            hops    = DEFAULT_HOPS,
                            q       = DEFAULT_QUERIES,
                            timeout = DEFAULT_TIMEOUT,
                            wait    = DEFAULT_WAIT):
  """trace route to dest verbosely using ICMP"""

  l = len(DEFAULT_MSG); info = S.gethostbyname_ex(dest)
  host, addr = info[0], info[2][0]
  print("traceroute to {} ({}), {} hops max, {} byte packets" \
    .format(host, addr, hops, l))
  for (i, ttl, j, p, td) in traceroute_icmp(addr, hops, q, timeout,
                                            wait):
    if j == 0:
      if i != 0: print()
      hop_addr = None
      print_("{:2d} ".format(ttl))
    if p == TIMEOUT:
      print_(" *")
    else:
      p_addr = p["recv_addr"][0]
      if j == 0 or p_addr != hop_addr:
        hop_addr = p_addr; p_host = S.getfqdn(p_addr)
        print_(" {} ({})".format(p_host, p_addr))
      print_("  {:.3f} ms".format(td * 1000))
      if is_icmp_dest_unreach(p):
        c = ICMP_ERROR_SYMBOLS.get(p["CODE"], p["CODE"])
        print_(" !{}".format(c))
  print()
                                                                # }}}1

def traceroute_icmp(addr, hops, q, timeout, wait):              # {{{1
  """yield sets of q probes to addr"""

  seq   = 1; ttl = 1; i = 0; done = False
  sock  = S.socket(S.AF_INET, S.SOCK_RAW, S.IPPROTO_ICMP)
  while ttl <= hops:
    sock.setsockopt(S.IPPROTO_IP, S.IP_TTL, ttl)
    for j in xrange(q):
      t1  = time.time()
      ID  = send_probe_icmp(sock, addr, seq)[0]
      p   = recv_probe_icmp(sock, addr, ID, seq, timeout)
      t2  = time.time()
      if p != TIMEOUT and (is_icmp_echoreply(p) or \
                           is_icmp_dest_unreach(p)):
        done = True
      yield (i, ttl, j, p, t2 - t1); seq += 1
    i += 1; ttl += 1
    if done: break
    if ttl <= hops and wait > 0: time.sleep(wait)
  sock.close()
                                                                # }}}1

def send_probe_icmp(sock, addr, seq, ID = DEFAULT_ID,
                    msg = DEFAULT_MSG):
  """send ICMP probe"""
  pkt = icmp_echo_request(ID, seq, msg)
  sock.sendto(pkt, (addr, 1))
  return (ID, seq, msg)

def recv_probe_icmp(sock, addr, ID, seq, timeout):              # {{{1
  """receive ICMP probe reply"""

  chk = lambda x: x["ID"] == ID and x["seq"] == seq
  def f(pkt, recv_addr):
    data = unpack_icmp(pkt)
    if data is None: return None
    data.update(recv_addr = recv_addr, length = len(pkt))
    if is_icmp_echoreply(data) and chk(data):
      return data
    if is_icmp_ttl_exceeded(data) or is_icmp_dest_unreach(data):
      data2 = unpack_icmp(data["data"])
      if data2 is not None and is_icmp_echo(data2) and chk(data2):
        data.update(echo = data2)
        return data
    return None   # ignore
  return recv_reply(sock, timeout, f)
                                                                # }}}1

# TODO
def verbose_traceroute_tcp(*_):
  raise RuntimeError("TODO - not yet implemented")

# TODO
def verbose_traceroute_udp(*_):
  raise RuntimeError("TODO - not yet implemented")

def verbose_ping(dest, count = None, timeout = DEFAULT_TIMEOUT, # {{{1
                 wait = DEFAULT_PING_WAIT):
  """ping dest verbosely"""

  l = len(DEFAULT_MSG)
  if dest.split(".")[-1].isdigit():
    host, addr  = dest, dest
    show_addr   = lambda x: x
  else:
    info        = S.gethostbyname_ex(dest)
    host, addr  = info[0], info[2][0]
    show_addr   = lambda x: "{} ({})".format(S.getfqdn(x), x)
  print("PING {} ({}) {}({}) bytes of data." \
    .format(host, addr, l, l + 28))
  for (seq, p, td) in ping(addr, count, timeout, wait):
    if p == TIMEOUT:
      print("timeout!") # TODO
    elif is_icmp_dest_unreach(p):
      fmt = "From {} icmp_seq={} {}"
      print(fmt.format(p["recv_addr"][0], p["echo"]["seq"],
                       ICMP_DEST_UNREACHABLE_CODES[p["CODE"]]))
    else:
      fmt = "{} bytes from {}: icmp_req={} ttl={} time={:.2f} ms"
      print(fmt.format(p["length"] - 28, show_addr(p["recv_addr"][0]),
                       seq, p["TTL"], td * 1000))
  # TODO: statistics
                                                                # }}}1

def ping(addr, count, timeout, wait):                           # {{{1
  """yield pings to addr"""

  seq = 1; sock = S.socket(S.AF_INET, S.SOCK_RAW, S.IPPROTO_ICMP)
  while count is None or count > 0:
    t1  = time.time()
    ID  = send_ping(sock, addr, seq)[0]
    p   = recv_ping(sock, addr, ID, seq, timeout)
    t2  = time.time()
    yield (seq, p, t2 - t1); seq += 1
    if count is not None: count -= 1
    if count is None or count > 0: time.sleep(wait)
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

  chk = lambda x: x["ID"] == ID and x["seq"] == seq
  def f(pkt, recv_addr):
    data = unpack_icmp(pkt)
    if data is None: return None
    data.update(recv_addr = recv_addr, length = len(pkt))
    if is_icmp_echoreply(data) and chk(data):
      return data
    if is_icmp_dest_unreach(data):
      data2 = unpack_icmp(data["data"])
      if data2 is not None and is_icmp_echo(data2) and chk(data2):
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
    rs, _, _ = select.select([sock], [], [], timeout)
    if rs == []: return TIMEOUT
    t2 = time.time()
    pkt, recv_addr = sock.recvfrom(1024)
    r = f(pkt, recv_addr)
    if r is not None: return r
    time_left -= (t2 - t1)
    if time_left <= 0: return TIMEOUT
                                                                # }}}1

# === ICMP ======================================================== #
# type (8)       | code (8)       | checksum (16)                   #
# ================================================================= #

# === ICMP_ECHO & ICMP_ECHOREPLY ================================== #
# identifier (16)                 | sequence number (16)            #
#                           ... data ...                            #
# ================================================================= #

# === ICMP_DEST_UNREACHT ========================================== #
# unused (16)                     | next-hop MTU (16)               #
#       IP header + first 8 bytes of original datagram's data       #
# ================================================================= #

# === ICMP_TIME_EXCEEDED ========================================== #
#                             unused (32)                           #
#       IP header + first 8 bytes of original datagram's data       #
# ================================================================= #

def is_icmp_echo(icmp_data):
  """is ICMP_ECHO?"""
  return  dict(TYPE = icmp_data["TYPE"], CODE = icmp_data["CODE"]) \
            == ICMP_ECHO

def is_icmp_echoreply(icmp_data):
  """is ICMP_ECHOREPLY?"""
  return  dict(TYPE = icmp_data["TYPE"], CODE = icmp_data["CODE"]) \
            == ICMP_ECHOREPLY

def is_icmp_time_exceeded(icmp_data):
  """is ICMP_TIME_EXCEEDED?"""
  return icmp_data["TYPE"] == ICMP_TIME_EXCEEDED

def is_icmp_ttl_exceeded(icmp_data):
  """is ICMP_EXC_TTL?"""
  return  is_icmp_time_exceeded(icmp_data) and \
            icmp_data["CODE"] == ICMP_EXC_TTL

def is_icmp_dest_unreach(icmp_data):
  """is ICMP_DEST_UNREACH?"""
  return icmp_data["TYPE"] == ICMP_DEST_UNREACH

def unpack_icmp(pkt):                                           # {{{1
  """unpack ICMP packet from IP packet"""

  d = unpack_ip(pkt)
  if d["PROTO"] != S.IPPROTO_ICMP: return None
  icmp_hdr, data = pkt[20:28], pkt[28:]
  TYPE, code, _, ID, seq = struct.unpack("!BBHHH", icmp_hdr)
  d.update(TYPE = TYPE, CODE = code, ID = ID, seq = seq, data = data)
  return d
                                                                # }}}1

def icmp_echo_request(ID, seq, data):                           # {{{1
  """
  create ICMP echo request packet

  >>> import binascii as B, trcrt as T
  >>> p = T.icmp_echo_request(3553, 1, b"HIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefg")
  >>> T.b2s(B.hexlify(p))
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

ICMP_TIME_EXCEEDED    = 11

ICMP_EXC_TTL          = 0
ICMP_EXC_FRAGTIME     = 1

ICMP_TIME_EXCEEDED_CODES = {
  ICMP_EXC_TTL        : "Time to live exceeded",
  ICMP_EXC_FRAGTIME   : "Frag reassembly time exceeded",
}

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

# TODO
ICMP_ERROR_SYMBOLS = {
  ICMP_NET_UNREACH    : "N",
  ICMP_HOST_UNREACH   : "H",
  ICMP_PROT_UNREACH   : "P",
}

TIMEOUT               = "__timeout__"

def print_(x):
  """print w/o newline and flush"""
  print(x, end = ""); sys.stdout.flush()

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
