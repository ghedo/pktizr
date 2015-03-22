-- This script sends out DNS requests for the "example.com" domain, and listens
-- for matching replies.

local bin = require("hype.bin")
local pkt = require("hype.pkt")
local std = require("hype.std")

-- template packets
local pkt_ip4 = pkt.IP({id=1, src=std.get_addr()})
local pkt_udp = pkt.UDP({sport=64434})
local pkt_dns = pkt.Raw({})

-- A? example.com. (without initial transaction ID)
local dns_query = '\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'
local dns_length = string.len(dns_query)

function loop(addr, port)
	pkt_ip4.dst = addr

	pkt_udp.dport = port

	local seq = pkt.cookie16(std.get_addr(), addr, 64434, port)
	pkt_dns.payload = bin.pack('>Hc' .. dns_length, seq, dns_query)

	return pkt_ip4, pkt_udp, pkt_dns
end

function recv(pkts)
	local pkt_ip4 = pkts[1]
	local pkt_udp = pkts[2]
	local pkt_dns = pkts[3]

	if #pkts < 3 or pkt_udp._type ~= 'udp' or pkt_dns._type ~= 'raw' then
		return
	end

	local src = pkt_ip4.src
	local dst = pkt_ip4.dst

	local sport = pkt_udp.sport
	local dport = pkt_udp.dport

	local pkt_id = pkt.cookie16(dst, src, dport, sport)

	local dns_id = bin.unpack('>H', pkt_dns.payload)

	if pkt_id ~= dns_id then
		return
	end

	-- TODO: check if recursive queries are allowed

	std.print("Received DNS reply from %s.%u", src, sport)
	return true
end
