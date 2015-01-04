-- This script sends out TCP SYN packets and listens for matching replies. It
-- can be used to perform a port scan on the target hosts.

-- template packets
local ip4 = hype.IP({id=1, src=hype.local_addr})
local tcp = hype.TCP({sport=64434, syn=true})

function assemble(addr, port)
	ip4.dst = addr

	tcp.dport = port
	tcp.seq   = hype.cookie32(hype.local_addr, addr, 64434, port)

	return ip4, tcp
end

function analyze(pkts)
	local ip4 = pkts[1]
	local tcp = pkts[2]

	if #pkts < 2 or tcp._type ~= 'tcp' then
		return
	end

	if not tcp.ack then
		return
	end

	local seq = hype.cookie32(ip4.dst, ip4.src, tcp.dport, tcp.sport)

	if tcp.ack_seq - 1 ~= seq then
		return
	end

	local status = "unknown"

	if tcp.syn then
		status = "open"
	elseif tcp.rst then
		status = "closed"
		return -- don't print closed ports
	end

	local fmt = "Port %u at %s is %s"
	hype.print(string.format(fmt, tcp.sport, ip4.src, status))
	return true
end
