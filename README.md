hype
====

![Travis CI](https://secure.travis-ci.org/ghedo/hype.png)

**hype** is a command-line packet generator and analyzer. It lets you generate
custom IP/ICMP/TCP/UDP packets, send them over the network and analyze replies
using Lua scripts.

Among other things, hype can be used to test firewall/IDS rules, perform
host discovery, port scanning and OS fingerprinting, test network performance
and so on.

hype is fully asynchronous, meaning that it has separate transmit and receive
threads and Lua contexts. The "sending" part of a script can't communicate with
the "receiving" part.

This makes it possible for hype to send packets as fast as possible without the
need to synchronously wait for replies, and send as many packets as needed
without worrying about memory exhaustion since it doesn't need to keep track of
sent packets. However this makes writing scripts a little bit trickier.

To make this easier hype provides the `cookie16()` and `cookie32()` functions
that can be used to generate 16/32bit hash values from source/destination ports
and addresses. These values can be embedded in the outgoing packets (e.g. in the
TCP sequence number field, or in the ICMP id or sequence number fields). When a
packet is received a new cookie value can be calculated and compared to the old
one.

For example, if a TCP SYN packet is sent with the sequence field generated using
cookie32(), the SYN+ACK or RST+ACK packet received as reply will have the same
value incremented by one in the acknowledgment sequence field. This can be
compared to a newly generated cookie value calculated on the received packet: if
they match the received packet is a reply to a packet sent by us. In the
[scripts/](scripts/) directory you can find various scripts that use this
technique for different protocols (ICMP, TCP, DNS, ...).

## GETTING STARTED

Under the [scripts/](scripts/) directory you can find some example scripts. To
run a script you need to specify a list of target hosts (e.g. `192.168.1.0/24`),
a port range (e.g. `0-65535`) and obviously the script you want to run:

```bash
# hype 192.168.1.0/24 -p 0 -S scripts/ping.lua
```

This will run the `ping.lua` script against all the hosts on the 192.168.0/24
network. The script simply sends out ICMP echo requests like the `ping(8)`
utility does, and can be used to discover active hosts from a set of IP ranges.

The port range (specified with the `-p` option) is `0`, since we only want to
send a single packet per host.

```bash
# hype 192.168.1.0/24 -p 0-65535 -S scripts/syn.lua
```

The `syn.lua` script sends out TCP SYN packets and can be used to discover open
ports on target hosts. In this case the port range is `0-65353` which means all
ports on the targets will be scanned.

Note that by default hype sends packet at a rate of 100 packets per second, in
order to avoid flooding the local network or the target hosts. You can specify a
different value using the `-r` command-line option:

```bash
# hype 192.168.1.0/24 -p 0-65535 -S scripts/syn.lua -r 1000
```

This will send 1000 packets per second instead. To disable rate limiting, the
value `0` (which means "send packets as fast as possible") can be used:

```bash
# hype 192.168.1.0/24 -p 0-65535 -S scripts/syn.lua -r 0
```

**Use this option with caution**.

See the [man page](http://ghedo.github.io/hype/) for more information.

## DEPENDENCIES

 * `libpcap`
 * `liblua5.1/5.2/jit`

## BUILDING

hype is distributed as source code. Install with:

```bash
$ mkdir build && cd build
$ cmake ..
$ make
$ [sudo] make install
```

## COPYRIGHT

Copyright (C) 2015 Alessandro Ghedini <alessandro@ghedini.me>

See COPYING for the license.
