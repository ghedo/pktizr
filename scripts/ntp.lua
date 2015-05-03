-- This script sends out NTP requests and listens for matching replies.

local bin = require("pktizr.bin")
local bit = require("pktizr.bit")
local pkt = require("pktizr.pkt")
local std = require("pktizr.std")

-- NTP MONLIST
local ntp_query = '\x17\x00\x03\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

-- template packets
local local_addr = std.get_addr()
local local_port = 64434

local pkt_ip4 = pkt.IP({id=1, src=local_addr})
local pkt_udp = pkt.UDP({sport=local_port})
local pkt_ntp = pkt.Raw({payload=ntp_query})

function loop(addr, port)
	pkt_ip4.dst = addr

	pkt_udp.dport = port

	return pkt_ip4, pkt_udp, pkt_ntp
end

function recv(pkts)
	local pkt_ip4 = pkts[1]
	local pkt_udp = pkts[2]
	local pkt_ntp = pkts[3]

	if #pkts < 3 or pkt_udp._type ~= 'udp' or pkt_ntp._type ~= 'raw' then
		return
	end

	local vers, impl, code = bin.unpack('>BBB', pkt_ntp.payload)

	-- response bit set
	if bit.rshift(vers, 7) ~= 1 then
		return
	end

	-- version is as expected
	if bit.band(bit.rshift(vers, 3), 0x07) ~= 2 then
		return
	end
  
	-- mode is as expected
	if bit.band(vers, 0x07) ~= 7 then
		return
	end

	local fmt = "Received NTP reply from %s.%u: impl=%u, code=%u"
	std.print(fmt, pkt_ip4.src, pkt_udp.sport, impl, code)
	return true
end
