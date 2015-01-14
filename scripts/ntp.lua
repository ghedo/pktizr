-- This script sends out NTP requests and listens for matching replies.

local bit = require("bit")

-- NTP MONLIST
local ntp_query = '\x17\x00\x03\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

-- template packets
local ip4 = hype.IP({id=1, src=hype.local_addr})
local udp = hype.UDP({sport=64434})
local raw = hype.Raw({payload=ntp_query})

function assemble(addr, port)
	ip4.dst = addr

	udp.dport = port

	return ip4, udp, raw
end

function analyze(pkts)
	local ip4 = pkts[1]
	local udp = pkts[2]
	local ntp = pkts[3]

	if #pkts < 3 or udp._type ~= 'udp' or ntp._type ~= 'raw' then
		return
	end

	local n, vers, impl, code, rsp = hype.unpack(ntp.payload, '>bbbA')

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
	hype.print(string.format(fmt, ip4.src, udp.sport, impl, code))
	return true
end
