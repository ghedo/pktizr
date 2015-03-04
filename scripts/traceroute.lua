-- This script executes a traceroute to the target address using ICMP echo
-- requests. It is recommended to use this with a single target address, or the
-- output will be pretty confusing.

-- template packets
local pkt_ip4  = hype.IP({id=1, src=hype.local_addr})
local pkt_icmp = hype.ICMP({type=8, id=1})

function loop(addr, port)
	pkt_ip4.dst = addr
	pkt_ip4.ttl = pkt_icmp.id

	pkt_icmp.seq = hype.cookie16(hype.local_addr, addr, 65535, 0)

	return pkt_ip4, pkt_icmp
end

function recv(pkts)
	local pkt_ip4  = pkts[1]
	local pkt_icmp = pkts[2]

	if #pkts < 2 or pkt_icmp._type ~= 'icmp' then
		return
	end

	if pkt_icmp.type == 0 then
		local seq = hype.cookie16(pkt_ip4.dst, pkt_ip4.src, 65535, 0)

		if pkt_icmp.seq ~= seq then
			return
		end

		hype.print("%2d %s", pkt_icmp.id, pkt_ip4.src)

		return true
	end

	if pkt_icmp.type == 11 then
		local pkt_ip4_orig  = pkts[3]
		local pkt_icmp_orig = pkts[4]

		if #pkts < 4 or pkt_icmp_orig._type ~= 'icmp' then
			return
		end

		local seq = hype.cookie16(pkt_ip4_orig.src, pkt_ip4_orig.dst,
		                          65535, 0)

		if pkt_icmp_orig.seq ~= seq then
			return
		end

		hype.print("%2d %s", pkt_icmp_orig.id, pkt_ip4.src)

		pkt_icmp_orig.id = pkt_icmp_orig.id + 1

		pkt_ip4_orig.ttl = pkt_icmp_orig.id

		hype.send(pkt_ip4_orig, pkt_icmp_orig)
	end

	return
end
