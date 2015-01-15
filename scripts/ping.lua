-- This script sends out ICMP echo requests and listens for matching replies
-- like the ping(8) utility.

-- template packets
local ip4  = hype.IP({id=1, src=hype.local_addr})
local icmp = hype.ICMP({type=8, id=1})

function assemble(addr, port)
	ip4.dst = addr

	icmp.seq = hype.cookie16(hype.local_addr, addr, 65535, 0)

	-- TODO: send timestamp

	return ip4, icmp
end

function analyze(pkts)
	local ip4  = pkts[1]
	local icmp = pkts[2]

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

	hype.print("Host %s is up", ip4.src)
	return true
end
