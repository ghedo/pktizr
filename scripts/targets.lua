-- This script prints the targets (for debug purposes)

local std = require("pktizr.std")

function loop(addr, port)
    std.print("%s:%d", addr, port)
    return nil
end
