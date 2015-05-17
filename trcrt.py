#!/usr/bin/python

# --                                                            ; {{{1
#
# File        : trcrt.py
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2015-05-16
#
# Copyright   : Copyright (C) 2015  Felix C. Stegerman
# Version     : v0.1.0
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
traceroute to localhost (127.0.0.1), 30 hops max, 60 byte packets
 1  localhost (127.0.0.1)  ... ms  ... ms  ... ms

>>> T.verbose_traceroute_icmp("example.com")      # doctest: +ELLIPSIS
traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
 1  ... (...)  ... ms  ... ms  ... ms
 2  ...
... ... (...)  ... ms  ... ms  ... ms
... 93.184.216.34 (93.184.216.34)  ... ms  ... ms  ... ms


>>> T.verbose_traceroute_udp("localhost")         # doctest: +ELLIPSIS
traceroute to localhost (127.0.0.1), 30 hops max, 60 byte packets
 1  localhost (127.0.0.1)  ... ms  ... ms  ... ms

>>> T.verbose_traceroute_udp("example.com", q=1)  # doctest: +ELLIPSIS
traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
 1  ... (...)  ... ms
 2  ...
... ... (...)  ... ms
... 93.184.216.34 (93.184.216.34)  ... ms


>>> T.verbose_traceroute_tcp("localhost")         # doctest: +ELLIPSIS
traceroute to localhost (127.0.0.1), 30 hops max, 40 byte packets
 1  localhost (127.0.0.1)  ... ms  ... ms  ... ms

>>> T.verbose_traceroute_tcp("example.com", q=1)  # doctest: +ELLIPSIS
traceroute to example.com (93.184.216.34), 30 hops max, 40 byte packets
 1  ... (...)  ... ms
... 93.184.216.34 (93.184.216.34)  ... ms


>>> T.verbose_ping("example.com", 1)              # doctest: +ELLIPSIS
PING example.com (93.184.216.34) 32(60) bytes of data.
40 bytes from 93.184.216.34: icmp_req=1 ttl=63 time=... ms
"""
                                                                # }}}1

from __future__ import print_function

import argparse, binascii, os, random, select, struct, sys, time
import socket as S

if sys.version_info.major == 2:                                 # {{{1
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
                                                                # }}}1

__version__       = "0.1.0"

DEFAULT_HOPS      = 30
DEFAULT_MINTTL    = 1
DEFAULT_PING_WAIT = 1
DEFAULT_QUERIES   = 3
DEFAULT_TIMEOUT   = 5
DEFAULT_WAIT      = 0

DEFAULT_UDP_PORT  = 33434
DEFAULT_TCP_PORT  = 80

DEFAULT_ID        = os.getpid()
DEFAULT_MSG       = b"Hi" * 16
DEFAULT_SEQ       = (os.getpid() << 16) | random.randint(0, 0xffff)

def main(*args):                                                # {{{1
  n = argument_parser().parse_args(args)
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
      f_args = [n.count, n.timeout, n.ttl,
                n.wait if n.wait is not None else DEFAULT_PING_WAIT]
    else:
      f_args = [n.hops, n.queries, n.timeout,
                n.ttl  if n.ttl  is not None else DEFAULT_MINTTL,
                n.wait if n.wait is not None else DEFAULT_WAIT]
      if n.f == verbose_traceroute_udp:
        f_args += [n.port if n.port is not None else DEFAULT_UDP_PORT]
      elif n.f == verbose_traceroute_tcp:
        f_args += [n.port if n.port is not None else DEFAULT_TCP_PORT]
    n.f(n.host, *f_args)
  except KeyboardInterrupt:
    if not (n.f == verbose_ping and n.count is None): return 1
  return 0
                                                                # }}}1

def argument_parser():                                          # {{{1
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
  p.add_argument("--udp", "-U", dest = "f", action = "store_const",
                 const = verbose_traceroute_udp,
                 help = "use UDP probe packets")
  p.add_argument("--tcp", "-T", dest = "f", action = "store_const",
                 const = verbose_traceroute_tcp,
                 help = "use TCP SYN probe packets")
  wait_default = "{} for UDP and {} for TCP" \
    .format(DEFAULT_UDP_PORT, DEFAULT_TCP_PORT)
  p.add_argument("--port", "-p", type = int, action = "store",
                 help = "for UDP: the base port (incremented by each "
                        "probe); for TCP: the (constant) destination "
                        "port to connect to "
                        "(default: {})".format(wait_default))
  wait_default = "{} for traceroute and {} for ping" \
    .format(DEFAULT_WAIT, DEFAULT_PING_WAIT)
  p.add_argument("--sendwait", "-z", dest = "wait", type = float,
                 action = "store",
                 help = "the time interval between probes "
                        "(default: {})".format(wait_default))
  p.add_argument("--timeout", "-w", type = float, action = "store",
                 help = "the timeout "
                        "(default: %(default)s)")
  p.add_argument("--ttl", "-t", type = int, action = "store",
                 help = "for ping: the TTL; "
                        "for traceroute: the first TTL")
  p.add_argument("--test", action = "store_true",
                 help = "run tests (and no traceroute or ping)")
  p.add_argument("--verbose", "-v", action = "store_true",
                 help = "run tests verbosely")
  p.set_defaults(
    f         = verbose_traceroute_icmp,
    count     = None,
    hops      = DEFAULT_HOPS,
    port      = None,
    queries   = DEFAULT_QUERIES,
    wait      = None,
    timeout   = DEFAULT_TIMEOUT,
    ttl       = None,
  )
  return p
                                                                # }}}1

def verbose_traceroute_icmp(dest,
                            hops    = DEFAULT_HOPS,
                            q       = DEFAULT_QUERIES,
                            timeout = DEFAULT_TIMEOUT,
                            ttl     = DEFAULT_MINTTL,
                            wait    = DEFAULT_WAIT):
  """trace route to dest verbosely using ICMP"""
  verbose_traceroute(traceroute_icmp, dest, hops, q, timeout, ttl,
                     wait)

def traceroute_icmp(addr, hops, q, timeout, ttl, wait):
  """trace route to dest using ICMP"""
  return traceroute(send_probe_icmp, recv_probe_icmp, [], addr, hops,
                    q, timeout, ttl, wait)

def send_probe_icmp(sock, _socks, addr, seq, ttl, ID = DEFAULT_ID,
                    msg = DEFAULT_MSG):
  """send ICMP probe"""
  pkt = icmp_echo_request(ID, seq, msg);
  set_ttl(sock, ttl); sock.sendto(pkt, (addr, 0))
  return (ID, seq)

def recv_probe_icmp(sock, _socks, _addr, ID, seq, timeout):
  """receive ICMP probe reply"""
  chk = lambda x: x["ID"] == ID and x["seq"] == seq
  return recv_probe_reply([sock], timeout, chk)

def verbose_traceroute_udp(dest,
                           hops     = DEFAULT_HOPS,
                           q        = DEFAULT_QUERIES,
                           timeout  = DEFAULT_TIMEOUT,
                           ttl      = DEFAULT_MINTTL,
                           wait     = DEFAULT_WAIT,
                           port     = DEFAULT_UDP_PORT):
  """trace route to dest verbosely using UDP"""
  verbose_traceroute(traceroute_udp, dest, hops, q, timeout, ttl,
                     wait, port, port_unreach_ok = True)

def traceroute_udp(addr, hops, q, timeout, ttl, wait, port):    # {{{1
  """trace route to dest using UDP"""

  sock = S.socket(S.AF_INET, S.SOCK_RAW, S.IPPROTO_UDP)
  try:
    for x in traceroute(send_probe_udp, recv_probe_udp, [sock], addr,
                        hops, q, timeout, ttl, wait, port):
      yield x
  finally:
    sock.close()
                                                                # }}}1

def send_probe_udp(_sock, socks, addr, seq, ttl, port,          # {{{1
                   msg = DEFAULT_MSG):
  """send UDP probe"""

  sock = socks[0]; d_port = port + seq - 1; dest = (addr, d_port)
  def f(s):
    source = s.getsockname(); pkt = udp_packet(source, dest, msg)
    set_ttl(sock, ttl); sock.sendto(pkt, dest)
    return (source, d_port)
  return with_udp_socket(dest, f)
                                                                # }}}1

def recv_probe_udp(sock, _socks, addr, source, d_port, timeout): # {{{1
  """receive UDP probe reply"""

  chk = lambda x: (x["source_port"],x["dest_port"]) == \
                  (source[1],d_port)
  def f(_pkt, recv_addr, data):
    data2 = unpack_udp(data["icmp_data"])
    if data2 is not None and chk(data2): return data
  return recv_probe_reply([sock], timeout, None, handle_wrapped = f)
                                                                # }}}1

def verbose_traceroute_tcp(dest,
                           hops     = DEFAULT_HOPS,
                           q        = DEFAULT_QUERIES,
                           timeout  = DEFAULT_TIMEOUT,
                           ttl      = DEFAULT_MINTTL,
                           wait     = DEFAULT_WAIT,
                           port     = DEFAULT_TCP_PORT):
  """trace route to dest verbosely using TCP"""
  verbose_traceroute(traceroute_tcp, dest, hops, q, timeout, ttl,
                     wait, port, pkt_len = 20 + 20)

def traceroute_tcp(addr, hops, q, timeout, ttl, wait, port):    # {{{1
  """trace route to dest using TCP"""

  sock_udp = S.socket(S.AF_INET, S.SOCK_DGRAM)
  try:
    sock_udp.connect((addr, port))
    done = lambda p: is_tcp(p) and (is_tcp_synack(p) or is_tcp_rst(p))
    sock = S.socket(S.AF_INET, S.SOCK_RAW, S.IPPROTO_TCP)
    try:
      for x in traceroute(send_probe_tcp, recv_probe_tcp,
                          [sock, sock_udp], addr, hops, q, timeout,
                          ttl, wait, port, done):
        yield x
    finally:
      sock.close()
  finally:
    sock_udp.close()
                                                                # }}}1

def send_probe_tcp(_sock, socks, addr, seq, ttl, port):
  """send TCP probe"""
  sock, sock_udp  = socks; dest = (addr, port)
  source          = sock_udp.getsockname()
  pkt             = tcp_packet(source, dest, DEFAULT_SEQ, syn = 1)
  set_ttl(sock, ttl); sock.sendto(pkt, dest)
  return (source, dest)

# TODO
def recv_probe_tcp(sock, socks, _addr, source, dest, timeout):  # {{{1
  """receive TCP probe reply"""

  sd            = lambda x: (x["source_port"], x["dest_port"])
  chk_returned  = lambda x: sd(x) == (source[1],   dest[1])
  chk_reply     = lambda x: sd(x) == (  dest[1], source[1])
  def f(pkt, recv_addr):
    data = unpack_tcp(pkt)
    if data is not None and chk_reply(data):
      # NB: it seems that the RST is already being sent; presumably
      # because the port is not actually open -- TODO
      # if is_tcp_synack(data): send_tcp_rst(socks[0], source, dest)
      return data
  def g(_pkt, recv_addr, data):
    data2 = unpack_tcp_first8(data["icmp_data"])
    if data2 is not None and chk_returned(data2): return data
  return recv_probe_reply([sock, socks[0]], timeout, None,
                          handle_other = f, handle_wrapped = g)
                                                                # }}}1

# TODO
def send_tcp_rst(sock, source, dest):
  """send TCP RST"""
  pkt = tcp_packet(source, dest, DEFAULT_SEQ + 1, rst = 1)
  sock.sendto(pkt, dest)                # what seq_n? -- TODO

def verbose_traceroute(f, dest, hops, q, timeout, minttl, wait, # {{{1
                       port = None, port_unreach_ok = False,
                       pkt_len = len(DEFAULT_MSG) + 20 + 8):
  """trace route to dest verbosely using ICMP, UDP or TCP"""

  kw    = dict(port = port) if port is not None else {}
  info  = S.gethostbyname_ex(dest); host, addr = dest, info[2][0]
  print("traceroute to {} ({}), {} hops max, {} byte packets" \
    .format(host, addr, hops, pkt_len))
  for (i, ttl, j, p, td) in f(addr, hops, q, timeout, minttl, wait,
                              **kw):
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
      if  is_icmp(p) and is_icmp_dest_unreach(p) \
            and not (is_icmp_port_unreach(p) and port_unreach_ok):
        c = ICMP_ERROR_SYMBOLS.get(p["CODE"], p["CODE"])
        print_(" !{}".format(c))
  print()
                                                                # }}}1

def traceroute(send_probe, recv_probe, socks, addr, hops, q,    # {{{1
               timeout, ttl, wait, port = None, other_done = None):
  """yield sets of q probes to addr"""

  icmp_done = lambda x: is_icmp(x) and \
                (is_icmp_echoreply(x) or is_icmp_dest_unreach(x))
  kw        = dict(port = port) if port is not None else {}
  seq       = 1; i = 0; done = False
  sock      = S.socket(S.AF_INET, S.SOCK_RAW, S.IPPROTO_ICMP)
  try:
    while ttl <= hops:
      for j in xrange(q):
        t1        = time.time()
        x1, x2    = send_probe(sock, socks, addr, seq, ttl, **kw)
        p         = recv_probe(sock, socks, addr, x1, x2, timeout)
        t2        = time.time()
        if  p != TIMEOUT and icmp_done(p) or \
              (other_done is not None and other_done(p)):
          done = True
        yield (i, ttl, j, p, t2 - t1); seq += 1
      i += 1; ttl += 1
      if done: break
      if ttl <= hops and wait > 0: time.sleep(wait)
  finally:
    sock.close()
                                                                # }}}1

# TODO
def verbose_ping(dest, count = None, timeout = DEFAULT_TIMEOUT, # {{{1
                 ttl = None, wait = DEFAULT_PING_WAIT):
  """ping dest verbosely"""

  pkt_len = len(DEFAULT_MSG)
  if dest.split(".")[-1].isdigit():
    host = addr = dest; show_addr = lambda x: x
  else:
    info = S.gethostbyname_ex(dest); host, addr = info[0], info[2][0]
    def show_addr(x):
      f = S.getfqdn(x); return "{} ({})".format(f, x) if f != x else x
  print("PING {} ({}) {}({}) bytes of data." \
    .format(host, addr, pkt_len, pkt_len + 20 + 8))
  for (seq, p, td) in ping(addr, count, timeout, ttl, wait):
    if p == TIMEOUT:
      print("timeout!") # TODO
    elif is_icmp_exc_ttl(p) or is_icmp_dest_unreach(p):
      c   = ICMP_TIME_EXCEEDED_CODES if is_icmp_exc_ttl(p) else \
            ICMP_DEST_UNREACHABLE_CODES
      fmt = "From {} icmp_seq={} {}"
      print(fmt.format(show_addr(p["recv_addr"][0]), p["echo"]["seq"],
                       c[p["CODE"]]))
    else:
      fmt = "{} bytes from {}: icmp_req={} ttl={} time={} ms"
      print(fmt.format(p["length"] - 28, show_addr(p["recv_addr"][0]),
                       seq, p["TTL"], fmt_ms(td)))
  # TODO: statistics
                                                                # }}}1

def fmt_ms(t):                                                  # {{{1
  """
  format time (in s) as ms

  >>> import trcrt as T
  >>> T.fmt_ms(7.654321)
  '7654'
  >>> T.fmt_ms(0.654321)
  '654'
  >>> T.fmt_ms(0.054321)
  '54.3'
  >>> T.fmt_ms(0.004321)
  '4.32'
  >>> T.fmt_ms(0.000321)
  '0.321'
  >>> T.fmt_ms(0.000021)
  '0.021'
  >>> T.fmt_ms(0.000001)
  '0.001'
  """

  tu, tm = int(t * 10**6), int(t * 10**3)
  if tu >= 10**5:
    return "{:d}".format(tm)
  elif tu >= 10**4:
    return "{:d}.{:01d}".format(tm, (tu%1000)//100)
  elif tu >= 10**3:
    return "{:d}.{:02d}".format(tm, (tu%1000)//10)
  else:
    return "0.{:03d}".format(tu)
                                                                # }}}1

def ping(addr, count, timeout, ttl, wait):                      # {{{1
  """yield pings to addr"""

  seq = 1; sock = S.socket(S.AF_INET, S.SOCK_RAW, S.IPPROTO_ICMP)
  if ttl is not None: set_ttl(sock, ttl)
  try:
    while count is None or count > 0:
      t1  = time.time()
      ID  = send_ping(sock, addr, seq)[0]
      p   = recv_ping(sock, addr, ID, seq, timeout)
      t2  = time.time()
      yield (seq, p, t2 - t1); seq += 1
      if count is not None: count -= 1
      if count is None or count > 0: time.sleep(wait)
  finally:
    sock.close()
                                                                # }}}1

def send_ping(sock, addr, seq, ID = DEFAULT_ID, msg = DEFAULT_MSG):
  """send ping"""
  t   = time.time()                 # time in secs + usecs
  td  = struct.pack("!LL", int(t), int(t * 10**6) % 10**6)
  pkt = icmp_echo_request(ID, seq, td + msg)
  sock.sendto(pkt, (addr, 1))
  return (ID, seq, msg)

def recv_ping(sock, _addr, ID, seq, timeout):
  """receive ping reply"""
  chk = lambda x: x["ID"] == ID and x["seq"] == seq
  return recv_probe_reply([sock], timeout, chk)

def recv_probe_reply(socks, timeout, chk = None,                # {{{1
                     handle_other = None, handle_wrapped = None):
  """
  receive probe replies

  * handles ICMP (and filters w/ chk)
  * delegates non-ICMP packets to handle_other
  * delegates ICMP_EXC_TTL or ICMP_DEST_UNREACH replies to non-ICMP
    packets to handle_wrapped
  """

  def f(pkt, recv_addr):
    data = unpack_icmp(pkt)
    if data is None:
      return  handle_other(pkt, recv_addr) \
                if handle_other is not None else None
    if is_icmp_echoreply(data) and chk is not None and chk(data):
      return data
    if is_icmp_exc_ttl(data) or is_icmp_dest_unreach(data):
      data2 = unpack_icmp(data["icmp_data"])
      if data2 is None:
        return  handle_wrapped(pkt, recv_addr, data) \
                  if handle_wrapped is not None else None
      elif is_icmp_echo(data2) and chk is not None and chk(data2):
        data.update(echo = data2)
        return data
    return None   # ignore
  return recv_reply(socks, timeout, f)
                                                                # }}}1

def recv_reply(socks, timeout, f):                              # {{{1
  """receive reply"""

  while timeout > 0:
    t1 = time.time()
    rs, _, _ = select.select(socks, [], [], timeout)
    if rs == []: return TIMEOUT
    for sock in rs:
      pkt, recv_addr = sock.recvfrom(1024)
      r = f(pkt, recv_addr)
      if r is not None:
        r.update(recv_addr = recv_addr, length = len(pkt))
        return r
    timeout -= (time.time() - t1)
  return TIMEOUT
                                                                # }}}1

# === ICMP ======================================================== #
# type (8)       | code (8)       | checksum (16)                   #
# ================================================================= #

# === ICMP_ECHO & ICMP_ECHOREPLY ================================== #
# identifier (16)                 | sequence number (16)            #
#                           ... data ...                            #
# ================================================================= #

# === ICMP_DEST_UNREACH =========================================== #
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

def is_icmp_exc_ttl(icmp_data):
  """is ICMP_EXC_TTL?"""
  return  is_icmp_time_exceeded(icmp_data) and \
            icmp_data["CODE"] == ICMP_EXC_TTL

def is_icmp_time_exceeded(icmp_data):
  """is ICMP_TIME_EXCEEDED?"""
  return icmp_data["TYPE"] == ICMP_TIME_EXCEEDED

def is_icmp_port_unreach(icmp_data):
  """is ICMP_PORT_UNREACH?"""
  return  is_icmp_dest_unreach(icmp_data) and \
            icmp_data["CODE"] == ICMP_PORT_UNREACH

def is_icmp_dest_unreach(icmp_data):
  """is ICMP_DEST_UNREACH?"""
  return icmp_data["TYPE"] == ICMP_DEST_UNREACH

def unpack_icmp(pkt):                                           # {{{1
  """unpack ICMP packet from IP packet"""

  d = unpack_ip(pkt)
  if not is_icmp(d): return None
  o = d["ip_data_offset"]; icmp_hdr, icmp_data = pkt[o:o+8], pkt[o+8:]
  TYPE, code, _, ID, seq = struct.unpack("!BBHHH", icmp_hdr)
  d.update(TYPE = TYPE, CODE = code, ID = ID, seq = seq,
           icmp_data = icmp_data)
  return d
                                                                # }}}1

def is_icmp(ip_data):
  """is ICMP packet?"""
  return ip_data is not None and ip_data["PROTO"] == S.IPPROTO_ICMP

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

# === UDP ========================================================= #
# source port (16)                | destination port (16)           #
# length (16)                     | checksum (16)                   #
#                           ... data ...                            #
# ================================================================= #

def unpack_udp(pkt):                                            # {{{1
  """unpack UDP packet from IP packet"""

  d = unpack_ip(pkt)
  if not is_udp(d): return None
  o = d["ip_data_offset"]; udp_hdr, udp_data = pkt[o:o+8], pkt[o+8:]
  s_port, d_port, _, _ = struct.unpack("!HHHH", udp_hdr)
  d.update(source_port = s_port, dest_port = d_port,
           udp_data = udp_data)
  return d
                                                                # }}}1

def is_udp(ip_data):
  """is UDP packet?"""
  return ip_data is not None and ip_data["PROTO"] == S.IPPROTO_UDP

def udp_packet(source, dest, data):                             # {{{1
  """
  create UDP packet

  >>> import binascii as B, trcrt as T
  >>> p = T.udp_packet(("10.0.2.15", 55530), ("10.0.2.2", 33434), b"@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_")
  >>> T.b2s(B.hexlify(p))
  'd8ea829a00289703404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
  """

  s, s_p = source; d, d_p = dest; l = len(data)
  return udp_header(
    s_p, d_p, l,
    udp_checksum(source, dest, udp_header(s_p, d_p, l, 0), data)
  ) + data
                                                                # }}}1

def udp_header(s_port, d_port, length, csum):
  """create UDP header"""
  return struct.pack("!HHHH", s_port, d_port, length + 8, csum)

def udp_checksum(source, dest, header, data):                   # {{{1
  """
  UDP checksum as per RFC 768

  >>> import binascii as B, trcrt as T

  >>> d1 = b"@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_"
  >>> h1 = T.udp_header(55530, 33434, len(d1), 0)
  >>> hex(T.udp_checksum(("10.0.2.15", 55530), ("10.0.2.2", 33434), h1, d1))
  '0x9703'

  >>> u  = S.IPPROTO_UDP
  >>> d2 = B.unhexlify(b"ffda")
  >>> h2 = T.udp_header(0, 0, len(d2), 0)
  >>> ph = T.pseudo_ipv4_header("0.0.0.0", "0.0.0.0", len(d2) + 8, u)
  >>> hex(T.internet_checksum(ph + h2 + d2))
  '0x0'
  >>> hex(T.udp_checksum(("0.0.0.0", 0), ("0.0.0.0", 0), h2, d2))
  '0xffff'
  """

  s, s_p = source; d, d_p = dest; p = S.IPPROTO_UDP
  csum = internet_checksum(pseudo_ipv4_header(s, d, len(data) + 8, p)
                           + header + data)
  return csum if csum != 0 else 0xffff
                                                                # }}}1

def with_udp_socket(dest, f):                                   # {{{1
  """
  use UDP socket for something

  >>> import trcrt as T
  >>> f = lambda s: s.getsockname()[0]
  >>> T.with_udp_socket(("127.0.0.1", T.DEFAULT_UDP_PORT), f)
  '127.0.0.1'
  """

  s = S.socket(S.AF_INET, S.SOCK_DGRAM)
  try: s.connect(dest); return f(s)
  finally: s.close()
                                                                # }}}1

# === TCP ========================================================= #
# source port (16)                | destination port (16)           #
#                        sequence number (16)                       #
#                  acknowledgment number (16) (if ACK)              #
# data offset + flags (16)        | window Size (16)                #
# checksum (16)                   | urgent pointer (16) (if URG)    #
#                          ... options ...                          #
#                           ... data ...                            #
# ================================================================= #

# === TCP data offset + flags ===================================== #
# |      0|      1|      2|      3|      4|      5|      6|      7| #
# |        data offset (4)        | reserved (3) = 000    | NS    | #
# |      8|      9|     10|     11|     12|     13|     14|     15| #
# | CWR   | ECE   | URG   | ACK   | PSH   | RST   | SYN   | FIN   | #
# ================================================================= #

def unpack_tcp(pkt):                                            # {{{1
                                                                # {{{2
  r"""
  unpack TCP packet from IP packet

  >>> import binascii as B, trcrt as T
  >>> d = b"GET / HTTP/1.0\r\n"
  >>> p = T.tcp_packet(("10.0.2.15", 54474), ("93.184.216.34", 80), 0x01772089, 0x1f9fb402, d, 29200, psh = 1, ack = 1)
  >>> i = B.unhexlify(b"45" + 8 * b"00" + b"06" + 10 * b"00") # fake IP header
  >>> x = T.unpack_tcp(i + p)
  >>> " ".join(str(x[k]) for k in "source_port dest_port seq_n ack_n offset win_sz".split())
  '54474 80 24584329 530560002 5 29200'
  >>> T.b2s(x["tcp_opts"])
  ''
  >>> T.b2s(x["tcp_data"])
  'GET / HTTP/1.0\r\n'
  >>> " ".join("{}={}".format(k,v) for k, v in sorted(x["flags"].items()))
  'ack=1 cwr=0 ece=0 fin=0 ns=0 psh=1 rst=0 syn=0 urg=0'
  """                                                           # }}}2

  d = unpack_ip(pkt)
  if not is_tcp(d): return None
  o = d["ip_data_offset"]; tcp_hdr = pkt[o:o+20]
  s_port, d_port, seq_n, ack_n, offset_and_flags, win_sz, _, _ = \
    struct.unpack("!HHIIHHHH", tcp_hdr)
  offset = offset_and_flags >> 12; flags = {}
  if not 5 <= offset <= 15: return None
  for i, flag in enumerate(reversed(TCP_FLAGS)):
    flags[flag.lower()] = (offset_and_flags >> i) & 0b1
  tcp_opts, tcp_data = pkt[o+20:o+offset*4], pkt[o+offset*4:]
  d.update(source_port  = s_port  , dest_port = d_port,
           seq_n        = seq_n   , ack_n     = ack_n,
           offset       = offset  , flags     = flags,
           win_sz       = win_sz  , tcp_opts  = tcp_opts,
           tcp_data     = tcp_data)
  return d
                                                                # }}}1

def unpack_tcp_first8(pkt):                                     # {{{1

  """
  unpack first 8 bytes of TCP packet from IP packet (from ICMP packet)

  >>> import binascii as B, trcrt as T
  >>> p = T.tcp_packet(("10.0.2.15", 54474), ("93.184.216.34", 80), 0x01772089)
  >>> i = B.unhexlify(b"45" + 8 * b"00" + b"06" + 10 * b"00") # fake IP header
  >>> x = T.unpack_tcp_first8(i + p)
  >>> " ".join(str(x[k]) for k in "source_port dest_port seq_n".split())
  '54474 80 24584329'
  """

  d = unpack_ip(pkt)
  if not is_tcp(d): return None
  o = d["ip_data_offset"]; tcp_hdr = pkt[o:o+8]
  s_port, d_port, seq_n = struct.unpack("!HHI", tcp_hdr)
  d.update(source_port = s_port, dest_port = d_port, seq_n = seq_n)
  return d
                                                                # }}}1

def is_tcp_synack(tcp_data):
  """is TCP SYN+ACK?"""
  return tcp_data["flags"]["syn"] == 1 and \
         tcp_data["flags"]["ack"] == 1

def is_tcp_rst(tcp_data):
  """is TCP RST?"""
  return tcp_data["flags"]["rst"] == 1

def is_tcp(ip_data):
  """is TCP packet?"""
  return ip_data is not None and ip_data["PROTO"] == S.IPPROTO_TCP

def tcp_packet(source, dest, seq_n, ack_n = 0, data = b"",      # {{{1
               win_sz = 0, **flags):
  r"""
  create TCP packet

  >>> import binascii as B, trcrt as T
  >>> d = b"GET / HTTP/1.0\r\n"
  >>> p = T.tcp_packet(("10.0.2.15", 54474), ("93.184.216.34", 80), 0x01772089, 0x1f9fb402, d, 29200, psh = 1, ack = 1)
  >>> T.b2s(B.hexlify(p))
  'd4ca0050017720891f9fb402501872105f700000474554202f20485454502f312e300d0a'
  """

  s, s_p = source; d, d_p = dest
  args = lambda c = 0: [s_p, d_p, seq_n, ack_n, c, win_sz]
  csum = tcp_checksum(source, dest, tcp_header(*args(), **flags), data)
  return tcp_header(*args(csum), **flags) + data
                                                                # }}}1

# TODO
def tcp_header(s_port, d_port, seq_n, ack_n, csum,              # {{{1
               win_sz = 0, **flags):
  """create TCP header"""

  offset = 5; urg_ptr = 0;    # ignore TCP options and URG -- TODO
  offset_and_flags = offset << 12
  for i, flag in enumerate(reversed(TCP_FLAGS)):
    b = 1 if flags.get(flag.lower(), 0) else 0
    offset_and_flags |= b << i
  return struct.pack("!HHIIHHHH", s_port, d_port, seq_n, ack_n,
                     offset_and_flags, win_sz, csum, urg_ptr)
                                                                # }}}1

def tcp_checksum(source, dest, header, data):                   # {{{1
  r"""
  TCP checksum as per RFC 793

  >>> import trcrt as T
  >>> d = b"GET / HTTP/1.0\r\n"
  >>> h = T.tcp_header(54474, 80, 0x01772089, 0x1f9fb402, 0, 29200, psh = 1, ack = 1)
  >>> hex(T.tcp_checksum(("10.0.2.15", 54474), ("93.184.216.34", 80), h, d))
  '0x5f70'
  """

  s, s_p = source; d, d_p = dest; l = len(header); p = S.IPPROTO_TCP
  return internet_checksum(pseudo_ipv4_header(s, d, l + len(data), p)
                           + header + data)
                                                                # }}}1

TCP_FLAGS = "NS CWR ECE URG ACK PSH RST SYN FIN".split()

# === UDP/TCP Pseudo IPv4 Header ================================== #
#                        source IP address (32)                     #
#                     destination IP address (32)                   #
# zeroes (8)     | protocol (8)   | UDP length (16)                 #
# ================================================================= #

def pseudo_ipv4_header(s_ip, d_ip, length, proto):              # {{{1
  """
  UDP/TCP pseudo IPv4 header

  >>> import binascii as B, socket as S, trcrt as T
  >>> u = S.IPPROTO_UDP
  >>> h = T.pseudo_ipv4_header("10.0.2.15", "10.0.2.2", 32 + 8, u)
  >>> T.b2s(B.hexlify(h))
  '0a00020f0a00020200110028'
  """

  return  S.inet_aton(s_ip) + S.inet_aton(d_ip) + \
            struct.pack("!BBH", 0, proto, length)
                                                                # }}}1

# === IPv4 ======================================================== #
# version | IHL  | DSCP + ECN (8) | length (16)                     #
# identification (16)             | flags + offset (16)             #
# TTL (8)        | protocol (8)   | checksum (16)                   #
#                        source IP address (32)                     #
#                     destination IP address (32)                   #
# ================================================================= #

# TODO
def unpack_ip(pkt):
  """unpack IP packet"""
  ihl, ttl, proto = b2i(pkt[0]) & 0xf, b2i(pkt[8]), b2i(pkt[9])
  if ihl != 5: return None    # ignore IPv4 w/ options -- TODO
  return dict(TTL = ttl, PROTO = proto, ip_data_offset = 4*ihl)

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

def set_ttl(sock, ttl):
  """set TTL"""
  sock.setsockopt(S.IPPROTO_IP, S.IP_TTL, ttl)

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

# TODO: more!
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
