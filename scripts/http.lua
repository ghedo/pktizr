-- This script creates a TCP connection to the target and sends an HTTP GET
-- request to it. It then listens for a matching HTTP reply and prints the
-- status line.
--
-- Note that on Linux, the kernel will automatically send out a TCP RST packet
-- when the target SYN+ACK is received, ruining everything. You'll need to
-- filter outgoing RST packets with iptables like so:
--
--   iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
--
-- Also note that if the remote target doesn't actually answers to HTTP, the
-- connection is left open. The target will, at some point, realize that it's a
-- dead connection anyway, but that may take some time.

-- template packets
local ip4 = hype.IP({id=1, src=hype.local_addr})
local tcp = hype.TCP({sport=64431, syn=true})
local raw = hype.Raw({})

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

	local src = ip4.src
	local dst = ip4.dst

	local sport = tcp.sport
	local dport = tcp.dport

	local seq = hype.cookie32(dst, src, dport, sport)

	ip4.src = dst
	ip4.dst = src

	tcp.sport = dport
	tcp.dport = sport
	tcp.doff  = 5

	if tcp.syn and tcp.ack then
		if tcp.ack_seq - 1 ~= seq then
			return
		end

		tcp.syn   = false
		tcp.psh   = false
		tcp.ack   = true
		tcp.ack_seq = tcp.seq + 1
		tcp.seq   = seq + 1

		hype.send(ip4, tcp)

		raw.payload = "GET / HTTP/1.1\r\n\r\n"

		hype.send(ip4, tcp, raw)
		return
	end

	if tcp.psh then
		local raw = pkts[3]

		if tcp.ack_seq ~= seq + 19 then -- 19 is size of GET req + 1
			return
		end

		for line in raw.payload:gmatch("[^\n]+") do
			status = line:match("HTTP/1.1 %d+.*")
			if status ~= nil  then
				local fmt = "HTTP status from %s.%u: %s"
				hype.print(string.format(fmt, src, sport, status))
			end
		end

		tcp.syn   = false
		tcp.psh   = false
		tcp.ack   = false
		tcp.rst   = true
		tcp.seq   = tcp.ack_seq
		tcp.ack_seq = 0

		hype.send(ip4, tcp)
		return true
	end

	return false
end
