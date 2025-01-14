# Importing necessary libraries
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types

class SimpleSDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]  # Specifies OpenFlow version

    def __init__(self, *args, **kwargs):
        super(SimpleSDNController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # MAC-to-port mapping for forwarding
        self.traffic_stats = {}  # Dictionary to track traffic statistics

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handles the initial connection with a switch and installs a table-miss flow."""
        datapath = ev.msg.datapath
        self._install_table_miss_flow(datapath)

    def _install_table_miss_flow(self, datapath):
        """Installs a table-miss flow entry to handle unmatched packets."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()  # Matches all packets
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(flow_mod)  # Sends the flow mod message to the switch

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handles packets sent to the controller."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Parse the received packet
        pkt = packet.Packet(msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        # If the packet is not an IPv4 packet, ignore it
        if not pkt_ipv4:
            return

        source_ip = pkt_ipv4.src
        dest_ip = pkt_ipv4.dst

        self.logger.info("Packet received: src=%s, dst=%s, in_port=%s", source_ip, dest_ip, in_port)

        # Custom Packet Handling
        if self._is_same_subnet(source_ip, dest_ip):
            # Forward packets within the same subnet
            out_port = self.mac_to_port.get(dest_ip, ofproto.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=source_ip, ipv4_dst=dest_ip)
            self._install_flow(datapath, match, actions)
        else:
            # Drop packets from different subnets
            self.logger.info("Packet dropped: src=%s, dst=%s (different subnets)", source_ip, dest_ip)
            return

        # Traffic Monitoring
        if (source_ip, in_port) in self.traffic_stats:
            self.traffic_stats[(source_ip, in_port)] += 1
        else:
            self.traffic_stats[(source_ip, in_port)] = 1

        self.logger.info("Traffic Statistics: %s", str(self.traffic_stats))

        # Forward the packet to the destination (or flood if destination is unknown)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)  # Sends the packet-out message to the switch

    def _is_same_subnet(self, ip1, ip2):
        """Checks if two IP addresses belong to the same subnet."""
        from ipaddress import IPv4Address, IPv4Network
        subnet = IPv4Network('10.0.0.0/24')
        return IPv4Address(ip1) in subnet and IPv4Address(ip2) in subnet

    def _install_flow(self, datapath, match, actions, priority=1):
        """Installs a flow entry in the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(flow_mod)  # Sends the flow mod message to the switch
