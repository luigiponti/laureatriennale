from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from threading import Timer
import os
import json
import time
import datetime

class ControllerNetsoft(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControllerNetsoft, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.debug("[TIMER (%s)]", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))

        self.logger.debug("**installo regole ARP")              #INSTALLO REGOLE ARP
        match = parser.OFPMatch(eth_type = 2054)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 1, match, actions)

        self.logger.debug("**installo regole ICMP")             #INSTALLO REGOLE ICMP
        match = parser.OFPMatch(eth_type = 2048, ip_proto=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 1, match, actions)

	#VARIABILE GLOBALE DELLA PRIORITA' DELLA REGOLA	
	global h        
        h = 1

        #VARIABILI GLOBALI UTILI PER IL RICONOSCIMENTO DELLA CONGESTIONE
        global bu
        bu=0
        global ru
        ru=0


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=timeout,
                                    buffer_id=buffer_id, priority=priority,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=timeout,
                                    priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        #ANALISI PACKET_IN
        msg = ev.msg

        global datapath

        datapath = msg.datapath
        ofproto = datapath.ofproto

        global parser

        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)      #utile per estrarre gli indirizzi IP

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        #VARIABILE GLOBALE PRIORITA' DELLA REGOLA
        global h
        h = h+1

        #REGOLE REDIREZIONAMENTO PACCHETTI AL DPI E ALLA DESTINAZIONE
        actions = []

        if pkt_ipv4 and (in_port==1 or in_port==2 or in_port==8) :
            timeout = 50
            prio = h

            if in_port==1 or ( in_port==8 and pkt_ipv4.dst == '10.10.10.1' ) :
                if pkt_ipv4.proto==6 :
                    self.logger.debug("**** TCP pkt from VMU1 steered to DPI and port 8 ****")
                    match = parser.OFPMatch(in_port = 1, eth_type = eth.ethertype, ip_proto=6)
                    actions = [parser.OFPActionOutput(3),parser.OFPActionOutput(8)]
                    self.add_flow(datapath, prio, match, actions, timeout=timeout)

                    self.logger.debug("**** TCP pkt to VMU1 steered to DPI and VMU1 ****")
                    match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.1', eth_type = eth.ethertype, ip_proto=6)
                    actions = [parser.OFPActionOutput(3),parser.OFPActionOutput(1)]
                    self.add_flow(datapath, prio, match, actions, timeout=timeout)

                elif pkt_ipv4.proto==17 :
                    self.logger.debug("**** UDP pkt from VMU1 steered to DPI and port 8 ****")
                    match = parser.OFPMatch(in_port = 1, eth_type = eth.ethertype, ip_proto=17)
                    actions = [parser.OFPActionOutput(3),parser.OFPActionOutput(8)]
                    self.add_flow(datapath, prio, match, actions, timeout=timeout)

                    self.logger.debug("**** UDP pkt to VMU1 steered to DPI and VMU1 ****")
                    match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.1', eth_type = eth.ethertype, ip_proto=17)
                    actions = [parser.OFPActionOutput(3),parser.OFPActionOutput(1)]
                    self.add_flow(datapath, prio, match, actions, timeout=timeout)

            elif in_port==2 or ( in_port==8 and pkt_ipv4.dst == '10.10.10.2' ) :
                if pkt_ipv4.proto==6 :
                    self.logger.debug("**** TCP pkt from VMU2 steered to DPI and port 8 ****")
                    match = parser.OFPMatch(in_port = 2, eth_type = eth.ethertype, ip_proto=6)
                    actions = [parser.OFPActionOutput(3),parser.OFPActionOutput(8)]
                    self.add_flow(datapath, prio, match, actions, timeout=timeout)

                    self.logger.debug("**** TCP pkt to VMU2 steered to DPI and VMU2 ****")
                    match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.2', eth_type = eth.ethertype, ip_proto=6)
                    actions = [parser.OFPActionOutput(3),parser.OFPActionOutput(2)]
                    self.add_flow(datapath, prio, match, actions, timeout=timeout)

                elif pkt_ipv4.proto==17 :
                    self.logger.debug("**** UDP pkt from VMU2 steered to DPI and port 8 ****")
                    match = parser.OFPMatch(in_port = 2, eth_type = eth.ethertype, ip_proto=17)
                    actions = [parser.OFPActionOutput(3),parser.OFPActionOutput(8)]
                    self.add_flow(datapath, prio, match, actions, timeout=timeout)

                    self.logger.debug("**** UDP pkt to VMU2 steered to DPI and VMU2 ****")
                    match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.2', eth_type = eth.ethertype, ip_proto=17)
                    actions = [parser.OFPActionOutput(3),parser.OFPActionOutput(2)]
                    self.add_flow(datapath, prio, match, actions, timeout=timeout)

            #AVVIO nDPI
            self.logger.debug("[TIMER (%s)]", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
            self.logger.debug("**start ndpiReader")
            os.chdir("/home/green/nDPI_Tool/nDPI/example")
            os.system("sudo ./ndpiReader -i s1-eth3 -v 2 -j /home/green/dpi-output/l2-test/netsoft-s1-eth3.json &")
            self.logger.debug("*nDPI ATTIVO*")

            #ATTESA DI 60 SECONDI E FINE ANALISI
            t=Timer(60.0, self.end_analysis)
            t.start()

        else :
            self.logger.debug("******FLUSSO NON AMMESSO******")
            match = parser.OFPMatch(in_port = in_port, eth_type = eth.ethertype, eth_dst=dst)
            actions = []
            timeout=0
            prio=1
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, prio, match, actions, msg.buffer_id, timeout)
                return
            else:
                self.add_flow(datapath, prio, match, actions, timeout=timeout)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    def end_analysis(self):
        #STOP nDPI
        self.logger.debug("** STOP ndpiReader")
        os.system('sudo kill -2 $(pgrep ndpiReader)')
        time.sleep(0.10)

        #INIZIALIZZAZIONE VARIABILI HOST_A E HOST_B
        host_a="0.0.0.0"
        host_b="0.0.0.0"
        
        #LETTURA OUTPUT JSON (CLASSIFICAZIONE nDPI)
        json_data = open('/home/green/dpi-output/l2-test/netsoft-s1-eth3.json')
        data = json.load(json_data)
        list_of_flows = data["known.flows"]
        for i in list_of_flows :
            if ( i['protocol'] == "TCP" or i['protocol'] == "UDP" ) and ( i["host_a.name"] == "10.10.10.1" or i["host_b.name"] == "10.10.10.1" or i["host_a.name"] == "10.10.10.2" or i["host_b.name"] == "10.10.10.2" ) :
                host_a = i["host_a.name"]
                host_b = i["host_b.name"]
                port_a = i["host_a.port"]
                port_b = i["host_n.port"]
                self.logger.debug("[CONTROLLER - TIMER (%s)] Host %s:%s is exchanging packets with Host %s:%s, via %s ",
                            datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'),
                            i["host_a.name"], i["host_a.port"], i["host_b.name"], i["host_n.port"], i["protocol"])

        #AVVIO CASO DI CONGESTIONAMENTO
        global bu
        global ru

        if host_a == "10.10.10.1" or host_b == "10.10.10.1"  :        #CODICE RELATIVO AL BUSUSER
            if bu == 0 :
                bu=1
                self.congested_case()      #AVVIO CASO DI CONGESTIONAMENTO
            else :
                self.logger.debug("**** WARNING: BUSINESS USER'S FLOW ALREADY ACTIVE ****")
        
        if host_a == "10.10.10.2" or host_b == "10.10.10.2" :        #CODICE RELATIVO AL RESUSER
            if ru == 0 :
                ru=1
                self.congested_case()      #AVVIO CASO DI CONGESTIONAMENTO
            else :
                self.logger.debug("**** WARNING: RESIDENCE USER'S FLOW ALREADY ACTIVE ****")
        
        #ATTESA DI 1 SECONDO E POSSIBILE FASE DI NON CONGESTIONAMENTO
        
        nc=Timer(1.0, self.non_congested_case )
        if (ru == 0 or bu == 0) :
            nc.start()
        
        json_data.close()


    def congested_case(self):
        self.logger.debug("**** CONGESTED CASE at [TIMER (%s)]", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        
        global ru
        global bu
        global datapath
        global parser

        #AUMENTO PRIORITA'
        global h
        h = h+1
        
        timeout = 50
        prio = h

        if bu == 1 :
            self.logger.debug("**** STEERING BUSUSER FLOWS ****")

            #REGOLE STEERING PACCHETTI BU AL WANA
            self.logger.debug("**bu_c: 1/8 _ TCP pkt from VMU1 steered to WANA (LAN port) ****")
            match = parser.OFPMatch(in_port=1, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(4)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)

            self.logger.debug("**bu_c: 2/8 _ UDP pkt from VMU1 steered to WANA (LAN port) ****")
            match = parser.OFPMatch(in_port=1, eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(4)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
                    
            self.logger.debug("**bu_c: 3/8 _ TCP pkt to VMU1 steered to WANA (WAN port) ****")
            match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.1', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(5)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
    
            self.logger.debug("**bu_c: 4/8 _ UDP pkt to VMU1 steered to WANA (WAN port) ****")
            match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.1', eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(5)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
    
            #STEERING DAL WANA ALLA DESTINAZIONE
            self.logger.debug("**bu_c: 5/8 _ TCP pkt from WANA (WAN port) to destination ****")
            match = parser.OFPMatch(in_port = 5, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(8)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
    
            self.logger.debug("**bu_c: 6/8 _ UDP pkt from WANA (WAN port) to destination ****")
            match = parser.OFPMatch(in_port = 5, eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(8)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
    
            self.logger.debug("**bu_c: 7/8 _ TCP pkt from WANA (LAN port) to VMU1 ****")
            match = parser.OFPMatch(in_port=4, ipv4_dst = '10.10.10.1', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
                        
            self.logger.debug("**bu_c: 8/8 _ UDP pkt from WANA (LAN port) to VMU1 ****")
            match = parser.OFPMatch(in_port=4, ipv4_dst = '10.10.10.1', eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)

        if ru == 1 :
            self.logger.debug("**** STEERING RESUSER FLOWS ****")
            
            #REGOLE STEERING PACCHETTI RU AL TC
            self.logger.debug("**ru_c: 1/8 _ TCP pkt from VMU2 steered to TC ****")
            match = parser.OFPMatch(in_port=2, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(6)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
                                              
            self.logger.debug("**ru_c: 2/8 _ UDP pkt from VMU2 steered to TC ****")
            match = parser.OFPMatch(in_port=2, eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(6)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
                                                                                        
            self.logger.debug("**ru_c: 3/8 _ TCP pkt to VMU2 steered to TC (2nd port) ****")
            match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.2', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(7)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
    
            self.logger.debug("**ru_c: 4/8 _ UDP pkt to VMU2 steered to TC (2nd port) ****")
            match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.2', eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(7)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
    
            #STEERING DAL TC ALLA DESTINAZIONE 
            self.logger.debug("**ru_c: 5/8 _ TCP pkt from TC (2nd port) to destination ****")
            match = parser.OFPMatch(in_port = 7, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(8)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
                                              
            self.logger.debug("**ru_c: 6/8 _ UDP pkt from TC (2nd port) to destination ****")
            match = parser.OFPMatch(in_port = 7, eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(8)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
                                                                                        
            self.logger.debug("**ru_c: 7/8 _ TCP pkt from TC to VMU2 ****")
            match = parser.OFPMatch(in_port = 6, ipv4_dst = '10.10.10.2', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
    
            self.logger.debug("**ru_c: 8/8 _ UDP pkt from TC to VMU2 ****")
            match = parser.OFPMatch(in_port = 6, ipv4_dst = '10.10.10.2', eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
    
    def non_congested_case(self):
        self.logger.debug("**** NON CONGESTED CASE at [TIMER (%s)]", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        
        global ru
        global bu
        global datapath
        global parser
        
        #AUMENTO PRIORITA'
        global h
        h = h+1

        timeout = 50
        prio = h

        if bu == 1 :
            self.logger.debug("**** RESTORING BUSUSER FLOWS ****")

            #REGOLE PACCHETTI BU
            self.logger.debug("**bu_nc: 1/4 _ TCP pkt from VMU1 to destination ****")
            match = parser.OFPMatch(in_port=1, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(8)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
                            
            self.logger.debug("**bu_nc: 2/4 _ UDP pkt from VMU1 to destination ****")
            match = parser.OFPMatch(in_port=1, eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(8)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
                        
            self.logger.debug("**bu_nc: 3/4 _ TCP pkt to VMU1 ****")
            match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.1', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
        
            self.logger.debug("**bu_nc: 4/4 _ UDP pkt to VMU1 ****")
            match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.1', eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
    
        if ru == 1 :
            self.logger.debug("**** RESTORING RESUSER FLOWS ****")

            #REGOLE PACHETTI RU
            self.logger.debug("**ru_nc: 1/4 _ TCP pkt from VMU2 to destination ****")
            match = parser.OFPMatch(in_port=2, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(8)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
                                                  
            self.logger.debug("**ru_nc: 2/4 _ UDP pkt from VMU2 to destination ****")
            match = parser.OFPMatch(in_port=2, eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(8)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
                                                                                            
            self.logger.debug("**ru_nc: 3/4 _ TCP pkt to VMU2 ****")
            match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.2', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
        
            self.logger.debug("**ru_nc: 4/4 _ UDP pkt to VMU2 ****")
            match = parser.OFPMatch(in_port = 8, ipv4_dst = '10.10.10.2', eth_type = 2048 , ip_proto=17)
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, prio, match, actions, timeout=timeout)
