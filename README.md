[]: {{{1

    File        : README.md
    Maintainer  : Felix C. Stegerman <flx@obfusk.net>
    Date        : 2015-09-12

    Copyright   : Copyright (C) 2015  Felix C. Stegerman
    Version     : v0.1.1

[]: }}}1

<!-- badge? -->

## Description

trcrt.py - python (2+3) traceroute implementation

See `trcrt.py` for the code (with examples).

## Examples

```
$ sudo ./trcrt.py --ttl 10 --queries 2 example.com
traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
10  adm-bb4-link.telia.net (213.155.134.42)  34.241 ms  33.123 ms
11  ldn-bb2-link.telia.net (213.155.136.84)  38.618 ms  37.949 ms
12  ash-bb4-link.telia.net (62.115.141.90)  112.369 ms ash-bb4-link.telia.net (62.115.141.92)  113.439 ms
13  ash-b2-link.telia.net (62.115.134.54)  114.954 ms ash-b2-link.telia.net (213.155.133.233)  114.814 ms
14  edgecast-ic-305901-ash-b2.c.telia.net (213.248.88.42)  112.652 ms edgecast-ic-306715-ash-b2.c.telia.net (213.155.129.62)  112.671 ms
15  93.184.216.34 (93.184.216.34)  114.613 ms  113.204 ms
```

```
$ sudo ./trcrt.py --ping --count 2 example.com
PING example.com (93.184.216.34) 32(60) bytes of data.
40 bytes from 93.184.216.34: icmp_req=1 ttl=63 time=122 ms
40 bytes from 93.184.216.34: icmp_req=2 ttl=63 time=113 ms
```

## TODO

* handle IP headers larger than 20 bytes?
* optimize?

## License

GPLv3+ [1].

## References

[1] GNU General Public License, version 3
--- https://www.gnu.org/licenses/gpl-3.0.html

[]: ! ( vim: set tw=70 sw=2 sts=2 et fdm=marker : )
