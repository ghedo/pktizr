.. _lua_pkt:

pkt library
-----------

The *pkt* library provides function for accessing and manipulating network
packets. It can be imported into a script as follows:

.. code-block:: lua

   local pkt = require("hype.pkt")
..

The provided functions can then be used by prepending `pkt.` to the name (e.g.
`pkt.send(...)`).

Functions
~~~~~~~~~

.. function:: cookie16(saddr, daddr, sport, dport)

   Returns a 16bit "cookie" value calculated from the source address,
   destination address, source port and destination port of a network packet,
   and a random number calculated at program startup.

.. function:: cookie32(saddr, daddr, sport, dport)

   Returns a 32bit "cookie" value calculated from the source address,
   destination address, source port and destination port of a network packet,
   and a random number calculated at program startup.

.. function:: send(p1, p2, ...)

   Packs and sneds the given packets on the network. The packets are stacked
   from left to right: p1 is stacked on the lower level, p2 on top of p1, etc.
