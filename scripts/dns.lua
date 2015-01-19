-- This script sends out DNS requests for the "example.com" domain, and listens
-- for matching replies.

-- template packets
local ip4 = hype.IP({id=1, src=hype.local_addr})
local udp = hype.UDP({sport=64434})
local raw = hype.Raw({})

-- A? example.com. (without initial transaction ID)
local dns_query = '\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'
local dns_length = string.len(dns_query)

function assemble(addr, port)
	ip4.dst = addr

	udp.dport = port

	local seq = hype.cookie16(hype.local_addr, addr, 64434, port)
	raw.payload = hype.pack('>Hc' .. dns_length, seq, dns_query)

	return ip4, udp, raw
end

function analyze(pkts)
	local ip4 = pkts[1]
	local udp = pkts[2]
	local dns = pkts[3]

	if #pkts < 3 or udp._type ~= 'udp' or dns._type ~= 'raw' then
		return
	end

	local seq = hype.cookie16(ip4.dst, ip4.src, udp.dport, udp.sport)

	local id = hype.unpack('>H', dns.payload)

	if seq ~= id then
		return
	end

	-- TODO: check if recursive queries are allowed

	hype.print("Received DNS reply from %s.%u", ip4.src, udp.sport)
	return true
end
