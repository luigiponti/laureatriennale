from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.ofproto import inet
from ryu.lib.packet import ether_types as ether
from threading import Timer
import os
import json
import time
import datetime

class BasicOpenStackL3Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet}

    #VARIABILI GLOBALI UTILI PER IL RICONOSCIMENTO DELLA CONGESTIONE
    global bu
    bu=0
    global ru
    ru=0
    global prio
    prio=1

    def __init__(self, *args, **kwargs):
        super(BasicOpenStackL3Controller, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset'] #NOTE. dpset (argument of kwargs) is the name specified in the contexts variable
        #VARIABLES
        self.switch_dpid_name = {} #Keep track of each switch by mapping dpid to name
        self.connections_name_dpid = {} #Keep track name and connection

    # FUNCTIONS
    def _get_ports_info(self, dpid): #Return information about all port on a switch
        return self.dpset.get_ports(dpid)

    def _get_port_name(self, dpid, port): #Return the name associated to the specified port number on the specified switch
        return self.dpset.get_port(dpid, port).name

    #Handle reception of StateChange message (NOTE. the message is sent whenever a switch performs the handshake with controller)
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if ev.state == MAIN_DISPATCHER:
            port_name = self._get_port_name(datapath.id, 4294967294)
            if not datapath.id in self.switch_dpid_name:
                self.switch_dpid_name[datapath.id] = port_name
                self.logger.debug("[TIMER (%s)] [SC-HANDLER] Switch %s registered on the controller, datapath.id  =  %s", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'), str(port_name), datapath.id)
                self.connections_name_dpid[str(port_name)] = datapath

                #Tell the eswitch to send msgs to the Controller in case of table miss
                match = parser.OFPMatch()
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                self.add_flow(datapath, 0, match, actions)

				# ARP
				match = parser.OFPMatch(eth_type = 2054)
                actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                self.add_flow(datapath, 1, match, actions)
                self.logger.debug("**Installo regole ARP")

				
				# ICMP
				match = parser.OFPMatch(eth_type = 2048, ip_proto=1)
                actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                self.add_flow(datapath, 1, match, actions)
                self.logger.debug("**Installo regole ICMP")

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.switch_dpid_name:
                self.logger.debug("[TIMER (%s)] [SC-HANDLER] Switch %s disconnected", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'), self.switch_dpid_name[datapath.id])
                del self.connections_name_dpid[self.switch_dpid_name[datapath.id]]
                del self.switch_dpid_name[datapath.id] 


    def connectionForBridge(self, bridge):
        return self.connections_name_dpid[bridge]

    #Add flow
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=timeout, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=timeout, priority=priority, match=match, instructions=inst)

        datapath.send_msg(mod)
        
    #Handle PacketIn event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
		global ofproto
        ofproto = datapath.ofproto
		global parser
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)

        in_port = msg.match['in_port']

	self.logger.debug("[PACKET-IN]  (%s) in port: %s , datapath id: %s", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'), in_port, datapath.id)

        np = len(pkt.get_protocols(ethernet.ethernet))
        self.logger.debug("[PKT-HANDLER]  (%s) Number of detected protocols: %d", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'), np)
        if np == 1:
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            eth_type = eth.ethertype
            eth_src = eth.src
            eth_dst = eth.dst
            self.logger.debug("[PKT-HANDLER] (%s) PacketIn from DPID = %s - in_port=%d dl_type=%s eth_src=%s eth_dst=%s", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'), ev.msg.datapath.id, in_port, str(eth_type), str(eth_src), str(eth_dst))

            if eth_type == ether.ETH_TYPE_IP: # IP packets ...
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                ip_proto = ip_pkt.proto
                ip_src = ip_pkt.src
                ip_dst = ip_pkt.dst
                if ip_proto == 6 and (in_port==1 or in_port==2): # ..TCP
                    self.logger.debug("[PKT-HANDLER] (%s) TCP packets detected ", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
                    self.logger.debug("[PKT-HANDLER]  (%s) CHECKING protocol detected - ip_proto=%s ip_src=%s ip_dst=%s inet_PROTO=%s", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'), ip_proto, ip_src, ip_dst, inet.IPPROTO_TCP)

                    #TIMEOUT GLOBALE
                    global timeout
                    timeout=40

                    #PRIORITA'
                    global prio
                    prio=prio+1

                    # STEERING TCP TRAFFIC
                    match = parser.OFPMatch(in_port = in_port, eth_type = ether.ETH_TYPE_IP, ip_proto = inet.IPPROTO_TCP, ipv4_src = ip_src, ipv4_dst = ip_dst)
                    actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:03"), parser.OFPActionOutput(3)]
                    self.add_flow(datapath, prio, match, actions, timeout=timeout)

                    dp = self.connectionForBridge("s2")
                    match = parser.OFPMatch(in_port = 1, eth_type = ether.ETH_TYPE_IP, ip_proto = inet.IPPROTO_TCP, ipv4_src = ip_src, ipv4_dst = ip_dst)
                    actions = [parser.OFPActionOutput(5)]
                    self.add_flow(dp, prio, match, actions, timeout=timeout)

                    #Handle bidirectional flows
                    match = parser.OFPMatch(in_port = 3, eth_type = ether.ETH_TYPE_IP, ip_proto = inet.IPPROTO_TCP, ipv4_src = ip_dst, ipv4_dst = ip_src)
                    actions = [parser.OFPActionOutput(in_port)]
                    self.add_flow(datapath, prio, match, actions, timeout=timeout)

                    match = parser.OFPMatch(in_port = 5, eth_type = ether.ETH_TYPE_IP, ip_proto = inet.IPPROTO_TCP, ipv4_src = ip_dst, ipv4_dst = ip_src)
                    actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:04"), parser.OFPActionOutput(1)]
                    self.add_flow(dp, prio, match, actions, timeout=timeout)

                    #AVVIO nDPI
                    self.logger.debug("[TIMER (%s)]", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
                    self.logger.debug("**start ndpiReader")
                    os.chdir("/home/green/nDPI_Tool/nDPI/example")
                    os.system("sudo ./ndpiReader -i s1-eth3 -v 2 -j /home/green/dpi-output/l2-test/netsoft-s1-eth3.json &")
                    self.logger.debug("*nDPI ATTIVO*")

                    #ATTESA DI 60 SECONDI E FINE ANALISI
                    t=Timer(60.0, self.end_analysis)
                    t.start()
            else:
                self.logger.debug("[PKT-HANDLER] Other protocol detected: %s", str(eth_type))
        else:
            self.logger.debug("More than one protocol detected")

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
          
        if host_a == "10.10.10.2" or host_b == "10.10.10.2" :        #CODICE RELATIVO AL RESUSER
            if ru == 0 :
                ru=1

	#FASE DI CONGESTIONAMENTO
	if bu==1 or ru==1 :
		self.congested_case()      #AVVIO CASO DI CONGESTIONAMENTO

        #ATTESA DI 1 SECONDO E POSSIBILE FASE DI NON CONGESTIONAMENTO
        nc=Timer(1.0, self.non_congested_case )
        if (ru == 0 or bu == 0) :
            nc.start()

        json_data.close()

    def congested_case(self):
        self.logger.debug("**** CONGESTED CASE at [TIMER (%s)]", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        
        global ru
        global bu
        global parser
		global ofproto

        #AUMENTO PRIORITA'
        global prio
        prio = prio+1
        
        global timeout 
        
        #DATAPATH SWITCH 1 e 2
        dp1 = self.connectionForBridge("s1")
        dp2 = self.connectionForBridge("s2")

        if bu == 1 :
            self.logger.debug("**** STEERING BUSUSER FLOWS ****")

            #REGOLE STEERING SWITCH 1
            self.logger.debug("**bu_c: 1 _ TCP pkt from VMU1 steered to WANA (LAN port) ****")
            match = parser.OFPMatch(in_port=1, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:05"), parser.OFPActionOutput(4)]
            self.add_flow(dp1, prio, match, actions, timeout=timeout)

            self.logger.debug("**bu_c: 2 _ TCP pkt from WANA (LAN port) to VMU1 ****")
            match = parser.OFPMatch(in_port=4, ipv4_dst = '10.10.10.1', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(dp1, prio, match, actions, timeout=timeout)
    
            #REGOLE STEERING SWITCH 2
            self.logger.debug("**bu_c: 3 _ TCP pkt to VMU1 steered to WANA (WAN port) ****")
            match = parser.OFPMatch(in_port = 5, ipv4_dst = '10.10.10.1', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:06"), parser.OFPActionOutput(2)]
            self.add_flow(dp2, prio, match, actions, timeout=timeout)

            self.logger.debug("**bu_c: 4 _ TCP pkt from WANA (WAN port) to destination ****")
            match = parser.OFPMatch(in_port = 2, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(5)]
            self.add_flow(dp2, prio, match, actions, timeout=timeout)
        if ru == 1 :
            self.logger.debug("**** STEERING RESUSER FLOWS ****")
            
            #REGOLE STEERING SWITCH 1
            self.logger.debug("**ru_c: 1 _ TCP pkt from VMU2 steered to TC ****")
            match = parser.OFPMatch(in_port=2, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:07"), parser.OFPActionOutput(5)]
            self.add_flow(dp1, prio, match, actions, timeout=timeout)

            self.logger.debug("**ru_c: 2 _ TCP pkt from TC to VMU2 ****")
            match = parser.OFPMatch(in_port = 5, ipv4_dst = '10.10.10.2', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(dp1, prio, match, actions, timeout=timeout)
    
            #STEERING DAL TC ALLA DESTINAZIONE 
            self.logger.debug("**ru_c: 3 _ TCP pkt from TC (2nd port) to destination ****")
            match = parser.OFPMatch(in_port = 3, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(5)]
            self.add_flow(dp2, prio, match, actions, timeout=timeout)

            self.logger.debug("**ru_c: 4 _ TCP pkt to VMU2 steered to TC (2nd port) ****")
            match = parser.OFPMatch(in_port = 5, ipv4_dst = '10.10.10.2', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:08"), parser.OFPActionOutput(3)]
            self.add_flow(dp2, prio, match, actions, timeout=timeout)
    
    def non_congested_case(self):
        self.logger.debug("**** NON CONGESTED CASE at [TIMER (%s)]", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        
        global ru
        global bu
        global parser
	global ofproto
        
        #AUMENTO PRIORITA'
        global prio
        prio = prio+1

        global timeout
        
        #DATAPATH SWITCH 1 e 2
        dp1 = self.connectionForBridge("s1")
        dp2 = self.connectionForBridge("s2")

        if bu == 1 :
            self.logger.debug("**** RESTORING BUSUSER FLOWS ****")

            #REGOLE PACCHETTI BU
            self.logger.debug("**bu_nc: 1 _ TCP pkt from VMU1 to destination ****")
            match = parser.OFPMatch(in_port=1, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:09"), parser.OFPActionOutput(6)]
            self.add_flow(dp1, prio, match, actions, timeout=timeout)
                            
            self.logger.debug("**bu_nc: 2 _ TCP pkt from VMU1 to destination ****")
            match = parser.OFPMatch(in_port=6, ipv4_dst = '10.10.10.1', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(dp1, prio, match, actions, timeout=timeout)
                        
            self.logger.debug("**bu_nc: 3 _ TCP pkt to VMU1 ****")
            match = parser.OFPMatch(in_port = 5, ipv4_dst = '10.10.10.1', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:0A"), parser.OFPActionOutput(4)]
            self.add_flow(dp2, prio, match, actions, timeout=timeout)
   
            self.logger.debug("**bu_nc: 4 _ TCP pkt to VMU1 ****")
            match = parser.OFPMatch(in_port = 4, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(5)]
            self.add_flow(dp2, prio, match, actions, timeout=timeout)
    
        if ru == 1 :
            self.logger.debug("**** RESTORING RESUSER FLOWS ****")

            #REGOLE PACHETTI RU
            self.logger.debug("**ru_nc: 1 _ TCP pkt from VMU2 to destination ****")
            match = parser.OFPMatch(in_port=2, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:09"), parser.OFPActionOutput(6)]
            self.add_flow(dp1, prio, match, actions, timeout=timeout)

            self.logger.debug("**ru_nc: 2 _ TCP pkt from VMU2 to destination ****")
            match = parser.OFPMatch(in_port=6, ipv4_dst = '10.10.10.2', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(dp1, prio, match, actions, timeout=timeout)
                                                                                            
            self.logger.debug("**ru_nc: 3 _ TCP pkt to VMU2 ****")
            match = parser.OFPMatch(in_port = 5, ipv4_dst = '10.10.10.2', eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:0A"), parser.OFPActionOutput(4)]
            self.add_flow(dp2, prio, match, actions, timeout=timeout)
        
            self.logger.debug("**ru_nc: 4 _ TCP pkt to VMU2 ****")
            match = parser.OFPMatch(in_port = 4, eth_type = 2048 , ip_proto=6)
            actions = [parser.OFPActionOutput(5)]
            self.add_flow(dp2, prio, match, actions, timeout=timeout)
