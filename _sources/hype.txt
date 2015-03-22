.. _hype(1):

hype
====

SYNOPSIS
--------

.. program:: hype

**hype <targets> [options]**

DESCRIPTION
-----------

**hype** is a command-line packet generator and analyzer. It lets you generate
custom IP/ICMP/TCP/UDP packets, send them over the network and analyze replies
using Lua scripts.

OPTIONS
-------

.. option:: -S, --script=<file>

Load and run the given script.

.. option:: -p, --ports=<ranges>

Use the specified port ranges.

.. option:: -r, --rate=<packets_per_second>

Send packets no faster than the specified rate [default: 100].

.. option:: -s, --seed=<seed>

Use the given number as seed value.

.. option:: -w, --wait=<seconds>

Wait the given amount of seconds after the scan is complete [default: 5].

.. option:: -c, --count=<count>

Send the given amount of duplicate packets [default: 1].

.. option:: -q, --quiet

Don't show the status line.

AUTHOR
------

Alessandro Ghedini <alessandro@ghedini.me>

COPYRIGHT
---------

Copyright (C) 2015 Alessandro Ghedini <alessandro@ghedini.me>

This program is released under the 2 clause BSD license.
