-- This script creates a TCP connection to the target and grabs the TCP banner
-- (basically whatever the target pushes to us after the handshake). This can be
-- used to determine what protocol is run on a particular port and works for
-- protocols like FTP, SMTP, POP3, IMAP, SSH, ...
--
-- Note that on Linux, the kernel will automatically send out a TCP RST packet
-- when the target SYN+ACK is received, ruining everything. You'll need to
-- filter outgoing RST packets with iptables like so:
--
--   iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
--
-- Also note that if the remote target doesn't actually send a banner, the
-- connection is left open. The target will, at some point, realize that it's a
-- dead connection anyway, but that may take some time.

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

	local src = ip4.src
	local dst = ip4.dst

	local sport = tcp.sport
	local dport = tcp.dport

	local seq = hype.cookie32(dst, src, dport, sport)

	if tcp.ack_seq - 1 ~= seq then
		return
	end

	ip4.src = dst
	ip4.dst = src

	tcp.sport = dport
	tcp.dport = sport
	tcp.doff  = 5

	if tcp.syn and tcp.ack then
		tcp.syn   = false
		tcp.psh   = false
		tcp.ack   = true
		tcp.ack_seq = tcp.seq + 1
		tcp.seq   = seq + 1

		hype.send(ip4, tcp)
		return
	end

	if tcp.psh then
		local fmt = "Banner from %s.%u: %s"
		hype.print(string.format(fmt, src, sport,
		                         string.sub(pkts[3].payload, 1, -2)))

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
