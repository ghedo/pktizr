-- This script sends out ICMP echo requests and listens for matching replies
-- like the ping(8) utility.

local socket = require("socket")

-- template packets
local pkt_ip4  = hype.IP({id=1, src=hype.local_addr})
local pkt_icmp = hype.ICMP({type=8, id=1})
local pkt_raw  = hype.Raw({})

function loop(addr, port)
	pkt_ip4.dst = addr

	pkt_icmp.seq = hype.cookie16(hype.local_addr, addr, 65535, 0)

	pkt_raw.payload = hype.string.pack('=n', socket.gettime())

	return pkt_ip4, pkt_icmp, pkt_raw
end

function recv(pkts)
	local pkt_ip4  = pkts[1]
	local pkt_icmp = pkts[2]
	local pkt_raw  = pkts[3]

	if #pkts < 3 or pkt_icmp._type ~= 'icmp' or pkt_raw._type ~= 'raw' then
		return
	end

	-- ignore if not icmp echo reply
	if pkt_icmp.type ~= 0 then
		return
	end

	local seq = hype.cookie16(pkt_ip4.dst, pkt_ip4.src, 65535, 0)

	if pkt_icmp.seq ~= seq then
		return
	end

	local now   = socket.gettime()
	local clock = hype.string.unpack('=n', pkt_raw.payload)

	hype.print("Host %s is up, time %f ms", pkt_ip4.src, (now - clock) * 1000)
	return true
end
