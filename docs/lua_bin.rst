.. _lua_bin:

bin library
-----------

The `bin` library provides function for packing and unpacking binary data. It
can be imported into a script as follows:

.. code-block:: lua

   local bin = require("pktizr.bin")
..

The provided functions can then be used by prepending `bin.` to the name (e.g.
`bin.pack(...)`).

Functions
~~~~~~~~~

.. function:: pack(fmt, v1, v2, ...)

   Returns a binary string containing the values `v1`, `v2`, etc. packed (that
   is, serialized in binary form) according to the format string `fmt`.

.. function:: unpack(fmt, s [, pos])

   Returns the values packed in the string `s` according to the format string
   `fmt`. An optional `pos` marks where to start reading in `s` (default is 1).
   After the read values, this function also returns the index of the first
   unread byte in `s`.

Format
~~~~~~

The format used by these functions is compatible with the one for the
`string.pack()` and `string.unpack()` functions in Lua 5.3. See the Lua
reference_ for more information.

.. _reference: http://www.lua.org/manual/5.3/manual.html#6.4.2
