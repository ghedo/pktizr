hype(1) -- scriptable, asynchronous network packet generator/analyzer
=====================================================================

## SYNOPSIS

`hype <targets> [options]`

## DESCRIPTION

**hype** is a command-line packet generator and analyzer. It lets you generate
custom IP/ICMP/TCP/UDP packets, send them over the network and analyze replies
using Lua scripts.

## OPTIONS

`-S, --script=<file>`

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Load and run the given script.

`-p, --ports=<ranges>`

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Use the specified port ranges.

`-r, --rate=<packets_per_second>`

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Send packets no faster than the specified rate (default is 100).

`-s, --seed=<seed>`

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Use the given number as seed value.

`-w, --wait=<seconds>`

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Wait the given amount of seconds after the scan is complete (default is 5).

`-c, --count=<count>`

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Send the given amount of duplicate packets (default is 1).

`-q, --quiet`

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Don't show the status line.

## AUTHOR ##

Alessandro Ghedini <alessandro@ghedini.me>

## COPYRIGHT ##

Copyright (C) 2015 Alessandro Ghedini <alessandro@ghedini.me>

This program is released under the 2 clause BSD license.
