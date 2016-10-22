-- This script creates a TCP connection to the target and grabs the TCP banner
-- (basically whatever the target pushes to us after the handshake). This can be
-- used to determine what protocol is run on a particular port and works for
-- protocols like FTP, SMTP, POP3, IMAP, SSH, ...
--
-- Note that on Linux, the kernel will automatically send out a TCP RST packet
-- when the target SYN+ACK is received, ruining everything. It's recommended
-- to use pktzir's --local-addr option to change the source IP address, or in
-- alternative outgoing RST packets can be filtered with iptables like so:
--
--   iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
--
-- Also note that if the remote target doesn't actually send a banner, the
-- connection is left open. The target will, at some point, realize that it's a
-- dead connection anyway, but that may take some time.

local pkt = require("pktizr.pkt")
local std = require("pktizr.std")

-- template packets
local local_addr = std.get_addr()
local local_port = 64434

local pkt_ip4 = pkt.IP()
pkt_ip4.src = local_addr

local pkt_tcp = pkt.TCP()
pkt_tcp.sport = local_port
pkt_tcp.syn   = true

function loop(addr, port)
    pkt_ip4.dst = addr

    pkt_tcp.dport = port
    pkt_tcp.seq   = pkt.cookie32(local_addr, addr, local_port, port)

    return pkt_ip4, pkt_tcp
end

function recv(pkts)
    local pkt_ip4 = pkts[1]
    local pkt_tcp = pkts[2]
    local pkt_raw = pkts[3]

    if #pkts < 3 or pkt_tcp._type ~= 'tcp' or pkt_raw._type ~= 'raw' then
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

    pkt_ip4.src = dst
    pkt_ip4.dst = src

    pkt_tcp.sport = dport
    pkt_tcp.dport = sport
    pkt_tcp.doff  = 5

    if pkt_tcp.syn and pkt_tcp.ack then
        pkt_tcp.syn     = false
        pkt_tcp.psh     = false
        pkt_tcp.ack     = true
        pkt_tcp.ack_seq = pkt_tcp.seq + 1
        pkt_tcp.seq     = seq + 1

        pkt.send(pkt_ip4, pkt_tcp)
        return
    end

    if pkt_tcp.psh then
        local fmt = "Banner from %s.%u: %s"
        std.print(fmt, src, sport, string.sub(pkt_raw.payload, 1, -2))

        pkt_tcp.syn     = false
        pkt_tcp.psh     = false
        pkt_tcp.ack     = false
        pkt_tcp.rst     = true
        pkt_tcp.seq     = pkt_tcp.ack_seq
        pkt_tcp.ack_seq = 0

        pkt.send(pkt_ip4, pkt_tcp)
        return true
    end

    return false
end
