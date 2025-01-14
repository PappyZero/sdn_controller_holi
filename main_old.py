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
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSDNController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.traffic_stats = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self._install_table_miss_flow(datapath)

    def _install_table_miss_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = msg.data

        # Parse the packet to extract IP addresses
        pkt_ethernet = ethernet.ethernet(pkt)
        pkt_ipv4 = ipv4.ipv4(pkt_ethernet.payload)
        if pkt_ipv4:
            source_ip = pkt_ipv4.src
            dest_ip = pkt_ipv4.dst
        else:
            # Handle non-IP packets (e.g., ARP)
            return

        self.logger.info("Packet received on port %s", in_port)

        # Custom Packet Handling
        if self._is_same_subnet(source_ip, dest_ip):
            # Forward within subnet
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, 
                ipv4_src=source_ip, 
                ipv4_dst=dest_ip
            )
            # Determine output port (replace with actual logic)
            out_port = 2  # Example: Assuming the output port is 2
            actions = [parser.OFPActionOutput(out_port)]
            self._install_flow(datapath, match, actions)
        else:
            # Drop the packet
            self.logger.info("Packet dropped: different subnet")
            return

        # Traffic Monitoring
        if (source_ip, in_port) in self.traffic_stats:
            self.traffic_stats[(source_ip, in_port)] += 1
        else:
            self.traffic_stats[(source_ip, in_port)] = 1
        self.logger.info("Traffic Statistics: %s", str(self.traffic_stats))

        # Flood the packet (for now, replace with actual forwarding logic)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=pkt
        )
        datapath.send_msg(out)

    def _is_same_subnet(self, ip1, ip2):
        from ipaddress import IPv4Network
        subnet = IPv4Network('10.0.0.0/24')
        return ip1 in subnet and ip2 in subnet

    def _install_flow(self, datapath, match, actions, priority=1):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)