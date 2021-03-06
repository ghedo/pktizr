-- This script creates a TCP connection to the target and sends an HTTP GET
-- request to it. It then listens for a matching HTTP reply and prints the
-- status line.
--
-- Note that on Linux, the kernel will automatically send out a TCP RST packet
-- when the target SYN+ACK is received, ruining everything. It's recommended
-- to use pktzir's --local-addr option to change the source IP address, or in
-- alternative outgoing RST packets can be filtered with iptables like so:
--
--   iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
--
-- Also note that if the remote target doesn't actually answers to HTTP, the
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

    if #pkts < 2 or pkt_tcp._type ~= 'tcp' then
        return
    end

    local src = pkt_ip4.src
    local dst = pkt_ip4.dst

    local sport = pkt_tcp.sport
    local dport = pkt_tcp.dport

    local seq = pkt.cookie32(dst, src, dport, sport)

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

        pkt.send(pkt_ip4, pkt_tcp)

        -- We can't reuse pkt_ip4 and pkt_tcp again (they might still
        -- be in the send queue) so we creare new ones.
        local pkt_ip4_new   = pkt.IP()
        pkt_ip4_new.src     = dst
        pkt_ip4_new.dst     = src

        local pkt_tcp_new   = pkt.TCP()
        pkt_tcp_new.sport   = dport
        pkt_tcp_new.dport   = sport
        pkt_tcp_new.doff    = 5
        pkt_tcp_new.syn     = false
        pkt_tcp_new.psh     = false
        pkt_tcp_new.ack     = true
        pkt_tcp_new.ack_seq = pkt_tcp.ack_seq
        pkt_tcp_new.seq     = pkt_tcp.seq

        local pkt_raw   = pkt.Raw()
        pkt_raw.payload = "GET / HTTP/1.1\r\n\r\n"

        pkt.send(pkt_ip4_new, pkt_tcp_new, pkt_raw)
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
                std.print(fmt, src, sport, status)
            end
        end

        pkt_tcp.syn   = false
        pkt_tcp.psh   = false
        pkt_tcp.ack   = false
        pkt_tcp.rst   = true
        pkt_tcp.seq   = pkt_tcp.ack_seq
        pkt_tcp.ack_seq = 0

        pkt.send(pkt_ip4, pkt_tcp)
        return true
    end

    return false
end
