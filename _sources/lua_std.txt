.. _lua_std:

std library
-----------

The `std` library provides utility function for scripts. It can be imported
into a script as follows:

.. code-block:: lua

   local std = require("pktizr.std")
..

The provided functions can then be used by prepending `std.` to the name (e.g.
`std.print(...)`).

Functions
~~~~~~~~~

.. function:: get_addr()

   Returns the local IP address of the network interface used to send and
   received packets.

.. function:: get_time()

   Returns the current date and time in seconds.

.. function:: print(fmt, v1, v2, ...)

   Prints a string containing the values `v1`, `v2`, etc. stringified according
   to the format string fmt. The string is generated using the `string.format()`
   standard function. See the Lua reference_ for more information.

.. _reference: http://www.lua.org/manual/5.3/manual.html#pdf-string.format
