"""
Adaptive Load Balancer - Ryu (OpenFlow 1.3) controller

Features
  * Virtual IP (VIP) in front of multiple TCP application servers
  * Distributes each client TCP flow using SDN (rewrite flows on the switch)
  * Monitors server load (active flows) and network load (port stats, Mbps)
  * Detects overloaded servers (skipped while others are available)
  * Detects server failures (active TCP SYN probes + link-down events)
  * Logs blocked and permitted requests to requests.log

Run: ryu-manager lb_controller.py
"""

import time

from ryu.base import app_manager # type: ignore
from ryu.controller import ofp_event # type: ignore
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls # type: ignore
from ryu.lib import hub # type: ignore
from ryu.lib.packet import arp, ethernet, ether_types, ipv4, packet, tcp # type: ignore
from ryu.ofproto import ofproto_v1_3 # type: ignore

# ---------------- configuration ----------------
VIP, VMAC = "10.0.0.100", "00:00:00:00:01:00"
PROBE_IP, PROBE_MAC = "10.0.0.200", "00:00:00:00:02:00"
SERVICE_PORT = 80

# Server IP -> MAC address and switch port
SERVERS = {
    "10.0.0.4": {"mac": "00:00:00:00:00:04", "port": 4},
    "10.0.0.5": {"mac": "00:00:00:00:00:05", "port": 5},
    "10.0.0.6": {"mac": "00:00:00:00:00:06", "port": 6},
}

BLOCKED_CLIENTS = set()
LINK_MBPS = 10.0
MAX_CONN = 10
RATE_HI = 8.0
POLL_INTERVAL = 2
PROBE_INTERVAL = 2
MISS_LIMIT = 3
FLOW_IDLE = 5
# ------------------------------------------------

TCP_SYN, TCP_RST, TCP_SYNACK = 0x02, 0x04, 0x12


class AdaptiveLB(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dp = None
        self.mac_to_port = {}
        self.flows = {}
        self.srv = {}

        for ip, cfg in SERVERS.items():
            self.srv[ip] = dict(
                mac=cfg["mac"],
                port=cfg["port"],
                healthy=True,
                misses=0,
                pending=False,
                rate=0.0,
                overloaded=False,
                last_bytes=None,
                last_t=None
            )

        self.port_to_srv = {
            cfg["port"]: ip for ip, cfg in SERVERS.items()
        }

        self.logf = open("requests.log", "a", buffering=1)
        hub.spawn(self._monitor_loop)
        hub.spawn(self._health_loop)

    # ---------------- helpers ----------------
    def _log(self, client, sport, action, server):
        line = "%s,%s,%s,%s,%s" % (
            time.strftime("%H:%M:%S"),
            client,
            sport,
            action,
            server
        )
        self.logf.write(line + "\n")
        self.logger.info(
            "REQUEST %s:%s -> %s [%s]",
            client, sport, server, action
        )

    def _add_flow(self, dp, prio, match, actions, idle=0, flags=0):
        p, o = dp.ofproto_parser, dp.ofproto
        inst = [
            p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, actions)
        ]
        dp.send_msg(
            p.OFPFlowMod(
                datapath=dp,
                priority=prio,
                match=match,
                instructions=inst,
                idle_timeout=idle,
                flags=flags
            )
        )

    def _out(self, dp, actions, data, in_port=None):
        o = dp.ofproto
        dp.send_msg(
            dp.ofproto_parser.OFPPacketOut(
                datapath=dp,
                buffer_id=o.OFP_NO_BUFFER,
                in_port=(
                    in_port if in_port is not None
                    else o.OFPP_CONTROLLER
                ),
                actions=actions,
                data=data
            )
        )

    def _conns(self, ip):
        return sum(1 for v in self.flows.values() if v == ip)

    def _score(self, ip):
        s = self.srv[ip]
        return (
            0.5 * self._conns(ip) / MAX_CONN
            + 0.5 * min(s["rate"] / LINK_MBPS, 1.0)
        )

    def _pick(self):
        healthy = [
            ip for ip, s in self.srv.items() if s["healthy"]
        ]
        if not healthy:
            return None

        ok = [
            ip for ip in healthy
            if not self.srv[ip]["overloaded"]
        ]
        return min(ok or healthy, key=self._score)

    # ---------------- switch setup ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        p, o = dp.ofproto_parser, dp.ofproto
        self.dp = dp

        self._add_flow(
            dp,
            0,
            p.OFPMatch(),
            [
                p.OFPActionOutput(
                    o.OFPP_CONTROLLER,
                    o.OFPCML_NO_BUFFER
                )
            ]
        )

        self.logger.info("Switch %s connected", dp.id)

    # ---------------- packet-in ----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port.setdefault(dp.id, {})[eth.src] = in_port

        a = pkt.get_protocol(arp.arp)
        if a:
            if (
                a.opcode == arp.ARP_REQUEST
                and a.dst_ip in (VIP, PROBE_IP)
            ):
                self._arp_reply(dp, in_port, eth, a)
                return

            self._l2(msg, eth)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        t = pkt.get_protocol(tcp.tcp)

        if ip and t:
            if ip.dst == PROBE_IP:
                self._probe_reply(ip, t)
                return

            if ip.dst == VIP and t.dst_port == SERVICE_PORT:
                self._balance(msg, eth, ip, t, in_port)
                return

        self._l2(msg, eth)

    def _arp_reply(self, dp, in_port, eth, a):
        mac = VMAC if a.dst_ip == VIP else PROBE_MAC
        pkt = packet.Packet()

        pkt.add_protocol(
            ethernet.ethernet(
                dst=eth.src,
                src=mac,
                ethertype=ether_types.ETH_TYPE_ARP
            )
        )

        pkt.add_protocol(
            arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=mac,
                src_ip=a.dst_ip,
                dst_mac=a.src_mac,
                dst_ip=a.src_ip
            )
        )

        pkt.serialize()
        self._out(
            dp,
            [dp.ofproto_parser.OFPActionOutput(in_port)],
            pkt.data
        )

    def _l2(self, msg, eth):
        dp = msg.datapath
        p, o = dp.ofproto_parser, dp.ofproto
        in_port = msg.match["in_port"]
        out = self.mac_to_port[dp.id].get(
            eth.dst, o.OFPP_FLOOD
        )
        actions = [p.OFPActionOutput(out)]

        if out != o.OFPP_FLOOD:
            self._add_flow(
                dp,
                1,
                p.OFPMatch(
                    in_port=in_port,
                    eth_dst=eth.dst
                ),
                actions,
                idle=30
            )

        self._out(dp, actions, msg.data, in_port)

    # ---------------- load balancing ----------------
    def _balance(self, msg, eth, ip, t, in_port):
        dp = msg.datapath
        p, o = dp.ofproto_parser, dp.ofproto
        key = (ip.src, t.src_port)

        if ip.src in BLOCKED_CLIENTS:
            self._log(
                ip.src, t.src_port, "BLOCKED", "-"
            )
            return

        sip = self.flows.get(key)
        is_new = (
            sip is None
            or not self.srv[sip]["healthy"]
        )

        if is_new:
            sip = self._pick()
            if sip is None:
                self._log(
                    ip.src,
                    t.src_port,
                    "DROPPED_NO_HEALTHY_SERVER",
                    "-"
                )
                return

        s = self.srv[sip]
        self.flows[key] = sip

        # Client -> server: rewrite VIP to the chosen server.
        fm = p.OFPMatch(
            in_port=in_port,
            eth_type=0x0800,
            ip_proto=6,
            ipv4_src=ip.src,
            ipv4_dst=VIP,
            tcp_src=t.src_port,
            tcp_dst=SERVICE_PORT
        )

        fa = [
            p.OFPActionSetField(eth_dst=s["mac"]),
            p.OFPActionSetField(ipv4_dst=sip),
            p.OFPActionOutput(s["port"])
        ]

        self._add_flow(
            dp,
            10,
            fm,
            fa,
            idle=FLOW_IDLE,
            flags=o.OFPFF_SEND_FLOW_REM
        )

        # Server -> client: make reply look like it came from VIP.
        rm = p.OFPMatch(
            in_port=s["port"],
            eth_type=0x0800,
            ip_proto=6,
            ipv4_src=sip,
            ipv4_dst=ip.src,
            tcp_src=SERVICE_PORT,
            tcp_dst=t.src_port
        )

        ra = [
            p.OFPActionSetField(eth_src=VMAC),
            p.OFPActionSetField(eth_dst=eth.src),
            p.OFPActionSetField(ipv4_src=VIP),
            p.OFPActionOutput(in_port)
        ]

        self._add_flow(
            dp, 10, rm, ra, idle=FLOW_IDLE
        )

        self._out(dp, fa, msg.data, in_port)

        if is_new:
            self._log(
                ip.src, t.src_port, "PERMITTED", sip
            )

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed(self, ev):
        m = ev.msg.match
        if m.get("ipv4_dst") == VIP:
            self.flows.pop(
                (m.get("ipv4_src"), m.get("tcp_src")),
                None
            )

    # ---------------- network / server load monitoring ----------------
    def _monitor_loop(self):
        while True:
            hub.sleep(POLL_INTERVAL)
            if self.dp:
                p, o = self.dp.ofproto_parser, self.dp.ofproto
                self.dp.send_msg(
                    p.OFPPortStatsRequest(
                        self.dp, 0, o.OFPP_ANY
                    )
                )

    @set_ev_cls(
        ofp_event.EventOFPPortStatsReply,
        MAIN_DISPATCHER
    )
    def _port_stats(self, ev):
        now = time.time()

        for st in ev.msg.body:
            ip = self.port_to_srv.get(st.port_no)
            if not ip:
                continue

            s = self.srv[ip]
            total = st.rx_bytes + st.tx_bytes

            if s["last_t"] is not None:
                s["rate"] = (
                    (total - s["last_bytes"])
                    * 8
                    / (now - s["last_t"])
                    / 1e6
                )

            s["last_bytes"], s["last_t"] = total, now
            self._update_overload(ip)

        self.logger.info(
            "LOAD " + " | ".join(
                "%s conns=%d net=%.2fMbps %s" % (
                    ip,
                    self._conns(ip),
                    s["rate"],
                    "UP" if s["healthy"] else "DOWN"
                ) + (
                    " OVERLOADED" if s["overloaded"] else ""
                )
                for ip, s in self.srv.items()
            )
        )

    def _update_overload(self, ip):
        s = self.srv[ip]
        c = self._conns(ip)
        hi = c >= MAX_CONN or s["rate"] >= RATE_HI
        lo = (
            c < MAX_CONN * 0.6
            and s["rate"] < RATE_HI * 0.7
        )

        if hi and not s["overloaded"]:
            s["overloaded"] = True
            self.logger.warning(
                "OVERLOADED: %s (conns=%d, %.2f Mbps)",
                ip, c, s["rate"]
            )

        elif lo and s["overloaded"]:
            s["overloaded"] = False
            self.logger.info(
                "RECOVERED from overload: %s", ip
            )

    # ---------------- failure detection ----------------
    def _health_loop(self):
        while True:
            hub.sleep(PROBE_INTERVAL)

            if not self.dp:
                continue

            for ip, s in self.srv.items():
                if s["pending"]:
                    s["misses"] += 1

                    if (
                        s["misses"] >= MISS_LIMIT
                        and s["healthy"]
                    ):
                        self._fail(ip, "no probe response")

                s["pending"] = True
                self._send_probe(ip, TCP_SYN)

    def _send_probe(
        self, ip, bits, seq=1000, sport=None,
        dport=SERVICE_PORT
    ):
        s = self.srv[ip]
        sport = sport or 40000 + s["port"]
        pkt = packet.Packet()

        pkt.add_protocol(
            ethernet.ethernet(
                dst=s["mac"],
                src=PROBE_MAC,
                ethertype=ether_types.ETH_TYPE_IP
            )
        )

        pkt.add_protocol(
            ipv4.ipv4(
                src=PROBE_IP,
                dst=ip,
                proto=6
            )
        )

        pkt.add_protocol(
            tcp.tcp(
                src_port=sport,
                dst_port=dport,
                seq=seq,
                bits=bits,
                window_size=65535
            )
        )

        pkt.serialize()

        self._out(
            self.dp,
            [
                self.dp.ofproto_parser.OFPActionOutput(
                    s["port"]
                )
            ],
            pkt.data
        )

    def _probe_reply(self, ip, t):
        sip = ip.src

        if sip not in self.srv:
            return

        s = self.srv[sip]

        if (t.bits & TCP_SYNACK) == TCP_SYNACK:
            s["pending"], s["misses"] = False, 0

            self._send_probe(
                sip,
                TCP_RST,
                seq=t.ack,
                sport=t.dst_port,
                dport=t.src_port
            )

            if not s["healthy"]:
                s["healthy"] = True
                self.logger.info(
                    "SERVER RECOVERED: %s", sip
                )

        elif t.bits & TCP_RST:
            s["pending"] = False

            if s["healthy"]:
                self._fail(
                    sip, "service refused connection"
                )

    @set_ev_cls(
        ofp_event.EventOFPPortStatus,
        MAIN_DISPATCHER
    )
    def _port_status(self, ev):
        d = ev.msg.desc
        ip = self.port_to_srv.get(d.port_no)

        if (
            ip
            and (d.state & ofproto_v1_3.OFPPS_LINK_DOWN)
            and self.srv[ip]["healthy"]
        ):
            self._fail(ip, "link down")

    def _fail(self, ip, reason):
        s = self.srv[ip]
        s["healthy"] = False

        self.logger.error(
            "SERVER FAILED: %s (%s) - removing its flows",
            ip, reason
        )

        dp = self.dp
        p, o = dp.ofproto_parser, dp.ofproto

        for match, kw in (
            (p.OFPMatch(), dict(out_port=s["port"])),
            (
                p.OFPMatch(in_port=s["port"]),
                dict(out_port=o.OFPP_ANY)
            )
        ):
            dp.send_msg(
                p.OFPFlowMod(
                    datapath=dp,
                    command=o.OFPFC_DELETE,
                    table_id=o.OFPTT_ALL,
                    out_group=o.OFPG_ANY,
                    match=match,
                    **kw
                )
            )

        for key in [
            key for key, value in self.flows.items()
            if value == ip
        ]:
            del self.flows[key]