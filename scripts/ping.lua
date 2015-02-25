-- This script sends out ICMP echo requests and listens for matching replies
-- like the ping(8) utility.

local socket = require("socket")

-- template packets
local ip4  = hype.IP({id=1, src=hype.local_addr})
local icmp = hype.ICMP({type=8, id=1})
local raw  = hype.Raw({})

function loop(addr, port)
	ip4.dst = addr

	icmp.seq = hype.cookie16(hype.local_addr, addr, 65535, 0)

	raw.payload = hype.string.pack('=n', socket.gettime())

	return ip4, icmp, raw
end

function recv(pkts)
	local ip4  = pkts[1]
	local icmp = pkts[2]
	local raw  = pkts[3]

	if #pkts < 2 or icmp._type ~= 'icmp' then
		return
	end

	-- ignore if not icmp echo reply
	if icmp.type ~= 0 then
		return
	end

	local seq = hype.cookie16(ip4.dst, ip4.src, 65535, 0)

	if icmp.seq ~= seq then
		return
	end

	local now   = socket.gettime()
	local clock = hype.string.unpack('=n', raw.payload)

	hype.print("Host %s is up, time %f ms", ip4.src, (now - clock) * 1000)
	return true
end
