-- This script sends out TCP SYN packets and listens for matching replies. It
-- can be used to perform a port scan on the target hosts.

local pkt = require("hype.pkt")
local std = require("hype.std")

-- template packets
local local_addr = std.get_addr()
local local_port = 64434

local pkt_ip4 = pkt.IP({id=1, src=local_addr})
local pkt_tcp = pkt.TCP({sport=local_port, syn=true})

function loop(addr, port)
	pkt_ip4.dst = addr

	pkt_tcp.dport = port
	pkt_tcp.seq   = pkt.cookie32(local_addr, addr, local_port, port)

	return pkt_ip4, pkt_tcp
end

function recv(pkts)
	local pkt_ip4 = pkts[1]
	local pkt_tcp = pkts[2]

	if #pkts < 2 or pkt_tcp._type ~= 'tcp' then
		return
	end

	if not pkt_tcp.ack then
		return
	end

	local src = pkt_ip4.src
	local dst = pkt_ip4.dst

	local sport = pkt_tcp.sport
	local dport = pkt_tcp.dport

	local seq = pkt.cookie32(dst, src, dport, sport)

	if pkt_tcp.ack_seq - 1 ~= seq then
		return
	end

	local status = "unknown"

	if pkt_tcp.syn then
		status = "open"
	elseif pkt_tcp.rst then
		status = "closed"
		return -- don't print closed ports
	end

	pkt_ip4.src = dst
	pkt_ip4.dst = src

	pkt_tcp.sport   = dport
	pkt_tcp.dport   = sport
	pkt_tcp.doff    = 5
	pkt_tcp.syn     = false
	pkt_tcp.psh     = false
	pkt_tcp.ack     = false
	pkt_tcp.rst     = true
	pkt_tcp.seq     = pkt_tcp.ack_seq
	pkt_tcp.ack_seq = 0

	pkt.send(pkt_ip4, pkt_tcp)

	std.print("Port %u at %s is %s", sport, src, status)
	return true
end
