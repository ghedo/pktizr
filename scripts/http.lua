-- This script creates a TCP connection to the target and sends an HTTP GET
-- request to it. It then listens for a matching HTTP reply and prints the
-- status line.
--
-- Note that on Linux, the kernel will automatically send out a TCP RST packet
-- when the target SYN+ACK is received, ruining everything. You'll need to
-- filter outgoing RST packets with iptables like so:
--
--   iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
--
-- Also note that if the remote target doesn't actually answers to HTTP, the
-- connection is left open. The target will, at some point, realize that it's a
-- dead connection anyway, but that may take some time.

-- template packets
local pkt_ip4 = hype.IP({id=1, src=hype.local_addr})
local pkt_tcp = hype.TCP({sport=64431, syn=true})
local pkt_raw = hype.Raw({})

function loop(addr, port)
	pkt_ip4.dst = addr

	pkt_tcp.dport = port
	pkt_tcp.seq   = hype.cookie32(hype.local_addr, addr, 64434, port)

	return pkt_ip4, pkt_tcp
end

function recv(pkts)
	local pkt_ip4 = pkts[1]
	local pkt_tcp = pkts[2]

	if #pkts < 2 or pkt_tcp._type ~= 'tcp' then
		return
	end

	local src = pkt_ip4.src
	local dst = pkt_ip4.dst

	local sport = pkt_tcp.sport
	local dport = pkt_tcp.dport

	local seq = hype.cookie32(dst, src, dport, sport)

	pkt_ip4.src = dst
	pkt_ip4.dst = src

	pkt_tcp.sport = dport
	pkt_tcp.dport = sport
	pkt_tcp.doff  = 5

	if pkt_tcp.syn and pkt_tcp.ack then
		if pkt_tcp.ack_seq - 1 ~= seq then
			return
		end

		pkt_tcp.syn     = false
		pkt_tcp.psh     = false
		pkt_tcp.ack     = true
		pkt_tcp.ack_seq = pkt_tcp.seq + 1
		pkt_tcp.seq     = seq + 1

		hype.send(pkt_ip4, pkt_tcp)

		pkt_raw.payload = "GET / HTTP/1.1\r\n\r\n"

		hype.send(pkt_ip4, pkt_tcp, pkt_raw)
		return
	end

	if pkt_tcp.psh then
		local pkt_raw = pkts[3]

		if pkt_tcp.ack_seq ~= seq + 19 then -- 19 is size of GET req + 1
			return
		end

		for line in pkt_raw.payload:gmatch("[^\n]+") do
			status = line:match("HTTP/1.1 %d+.*")
			if status ~= nil  then
				local fmt = "HTTP status from %s.%u: %s"
				hype.print(fmt, src, sport, status)
			end
		end

		pkt_tcp.syn   = false
		pkt_tcp.psh   = false
		pkt_tcp.ack   = false
		pkt_tcp.rst   = true
		pkt_tcp.seq   = pkt_tcp.ack_seq
		pkt_tcp.ack_seq = 0

		hype.send(pkt_ip4, pkt_tcp)
		return true
	end

	return false
end
