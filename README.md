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

## GETTING STARTED

Under the [scripts/](scripts/) directory you can find some example scripts. To
run a script you need to specify a list of target hosts (e.g. `192.168.1.0/24`),
a port range (e.g. `0-65535`) and obviously the script you want to run:

```bash
$ sudo hype 192.168.1.0/24 -p 0 -S scripts/ping.lua
```

This will run the `ping.lua` script against all the hosts on the 192.168.0/24
network. The script simply sends out ICMP echo requests like the `ping(8)`
utility does, and can be used to discover active hosts from a set of IP ranges.

The port range (specified with the `-p` option) is `0`, since we only want to
send a single packet per host.

```bash
$ sudo hype 192.168.1.0/24 -p 0-65535 -S scripts/syn.lua
```

The `syn.lua` script sends out TCP SYN packets and can be used to discover open
ports on target hosts. In this case the port range is `0-65353` which means all
ports on the targets will be scanned.

Note that by default hype sends packet at a rate of 100 packets per second, in
order to avoid flooding the local network or the target hosts. You can specify a
different value using the `-r` command-line option:

```bash
$ sudo hype 192.168.1.0/24 -p 0-65535 -S scripts/syn.lua -r 1000
```

This will send 1000 packets per second instead. To disable rate limiting, the
value `0` (which means "send packets as fast as possible") can be used (**use
this option with caution**):

```bash
$ sudo hype 192.168.1.0/24 -p 0-65535 -S scripts/syn.lua -r 0
```

See the [man page](http://ghedo.github.io/hype/) for more information.

## DEPENDENCIES

 * `liblua5.1/5.2/jit`
 * `libpcap`
 * `liburcu`

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
