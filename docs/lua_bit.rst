.. _lua_bit:

bit library
-----------

The `bit` library provides function for bitwise operations on numbers, and is
based on the bitop_ Lua library. It can be imported into a script as follows:

.. code-block:: lua

   local bit = require("pktizr.bit")
..

The provided functions can then be used by prepending `bit.` to the name (e.g.
`bit.bnot(...)`).

Functions
~~~~~~~~~

.. function:: tobit(x)

   Normalizes a number to the numeric range for bit operations and returns it.

.. function:: tohex(x [,n])

   Converts its first argument to a hex string. The number of hex digits is
   given by the absolute value of the optional second argument. Positive numbers
   between 1 and 8 generate lowercase hex digits. Negative numbers generate
   uppercase hex digits. Only the least-significant `4 * \|n\|` bits are used.
   The default is to generate 8 lowercase hex digits.

.. function:: bnot(x)

   Returns the bitwise not of its argument.

.. function:: bor(x1 [,x2...])

   Returns the bitwise or of all of its arguments.

.. function:: band(x1 [,x2...])

   Returns the bitwise and of all of its arguments.

.. function:: bxor(x1 [,x2...])

   Returns the bitwise xor of all of its arguments.

.. function:: lshift(x, )
.. function:: rshift(x, n)
.. function:: arshift(x, n)

   Returns either the bitwise logical left-shift, bitwise logical right-shift,
   or bitwise arithmetic right-shift of its first argument by the number of
   bits given by the second argument.

   Logical shifts treat the first argument as an unsigned number and shift in
   0-bits. Arithmetic right-shift treats the most-significant bit as a sign bit
   and replicates it.

   Only the lower 5 bits of the shift count are used (reduces to the range [0..31]).

.. function:: rol(x, n)

   Returns the bitwise left rotation of its first argument by the number of bits
   given by the second argument. Bits shifted out on one side are shifted back
   in on the other side. Only the lower 5 bits of the rotate count are used
   (reduces to the range [0..31]).

.. function:: ror(x, n)

   Returns the bitwise right rotation of its first argument by the number of
   bits given by the second argument. Bits shifted out on one side are shifted
   back in on the other side. Only the lower 5 bits of the rotate count are used
   (reduces to the range [0..31]).

.. function:: bswap(x)

   Swaps the bytes of its argument and returns it. This can be used to convert
   little-endian 32 bit numbers to big-endian 32 bit numbers or vice versa.

.. _bitop: http://bitop.luajit.org/
