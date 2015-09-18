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
from ryu.lib.packet import tcp
from ryu.ofproto import inet
from ryu.lib.packet import ether_types as ether
from threading import Timer
import os
import json
import time
import datetime
import subprocess
import threading

class BasicOpenStackL3Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet}

	# INITIALIZE GLOBAL VARIABLES
	global flow_id
	flow_id=0
	global flows_state
	flows_state = [] # List of flows 
	global active_flows
	active_flows = [] # List of active flows
	global classified_flows
	classified_flows = [] # List of classified flows (after the preventive enforcement)
	global  hipriousers
	hipriousers = [] #List of high priority users
	global flowlimit
	flowlimit = 3	#Max flow in Not Enforcement case

	def __init__(self, *args, **kwargs):
		super(BasicOpenStackL3Controller, self).__init__(*args, **kwargs)
		self.dpset = kwargs['dpset'] #NOTE. dpset (argument of kwargs) is the name specified in the contexts variable
		#VARIABLES
		self.switch_dpid_name = {} #Keep track of each switch by mapping dpid to name
		self.connections_name_dpid = {} #Keep track name and connection
		#Set of general parameters
		self.net_topo = ['br-int', 'br3', 'br4'] # NT
		self.users = ['BusUser', 'ResUser'] # U
		self.net_func = ['DPI', 'TC', 'Wana', 'WanaDec', 'gw', 'gw_dest', 'vr', 'vr_dest'] # NF
		#switch_ports = {'br-int1': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 'br3': [1, 2, 3], 'br4': [1, 2, 3]} # SWj

		self.bususer = 35
		self.tp_port_bususer = 50000
		self.tp_port_resuser = 50001
		self.resuser = 45
		self.int_network_vid = 9
		self.gw_network_vid = 10
		self.wana_port1 = 37
		self.wana_port2 = 38
		self.tc_port1 = 39
		self.tc_port2 = 40
		self.dpi_port1 = 43
		self.dpi_port2 = 44
		self.gw_port1 =
		self.gw_port2 =
		self.outport = 1
		self.outport_dest = 6

		self.wana_dest_port1 = 9
		self.wana_dest_port2 = 9
		self.gw_dest_port1 = 7
		self.gw_dest_port2 = 6
		self.sink = 7

		self.bcast = "ff:ff:ff:ff:ff:ff"
		self.ip_resuser = "10.10.0.9"
		self.ip_bususer = "10.10.0.3"
		self.ip_gw = "10.10.0.1"
		self.ip_router_vr = "10.0.0.1"
		self.ip_nat = "10.250.0.106"
		self.ip_sink = "10.30.0.2"

		# HIGH PRIORITY USERS LIST
		self.hipriousers=[ip_bususer]

		# MAC DICTIONARY
		self.dpi_mac={'eth1':"fa:16:3e:99:75:f9", 'eth2':"fa:16:3e:c5:5a:d4"}
		self.wana_mac={'eth1':"fa:16:3e:bd:66:77", 'eth2':"fa:16:3e:3b:3a:cf"}
		self.tc_mac={'eth1':"fa:16:3e:59:67:60", 'eth2':"fa:16:3e:bb:d6:ab"}
		self.gw_mac={'eth1':"fa:16:3e:f1:cc:7b", 'eth2':"fa:16:3e:a4:16:7a"}

		self.wana_dest_mac={'eth1':"52:54:00:a9:08:67", 'eth2':"52:54:00:8c:55:14"}
		self.gw_dest_mac={'eth1':"52:54:00:bb:3c:d1", 'eth2':"52:54:00:12:5f:5f"}


		self.dpiExePath = '/home/ubuntu/nDPI_Tool/nDPI/example/ndpiReader'
		self.dpiCapPath = '/home/ubuntu/nDPI_Tool/nDPI/example/cattura.json'
		self.a = 0
		self.b = 0
		self.DPIcredentials='ubuntu@192.168.122.64'

	# GET MAC ADDRESS
	def get_in_mac_address(self, host, direction):
		intf=None		
		if direction == 'outbound':
			intf='eth1'
		elif direction == 'inbound':
			intf='eth2'
		if host =='DPI' :
			return self.dpi_mac[intf]
		elif host =='Wana' :
			return self.wana_mac[intf]
		elif host =='TC' :
			return self.tc_mac[intf]
		elif host =='GW' :
			return self.gw_mac[intf]
		elif host =='WanaDec' :
			return self.wana_dest_mac[intf]
		elif host =='GWDest' :
			return self.gw_dest_mac[intf]

	# GET IN PORT
	def get_in_port(self, nf, d):
		result_tuple = []
	
		for dpid in topology_info.keys(): # For each switch...
			connected_elem = topology_info[dpid]
			if nf in connected_elem: # ...check if the user is connected
				#nface = connected_elem.count(nf) # count the number of the nf'interfaces on the switch
				result_tuple.append(dpid)
				nf_traffic_dir = port_direction[nf]
				p = nf_traffic_dir[d]
				result_tuple.append(p[0])
		return result_tuple

	# ANALIZE ACTIVE FLOWS REQUEST
	def _request_stats(self):
        self.logger.debug('FLOW CONTROL request')		
        datapath = self.connectionForBridge("br-int")
        threading.Timer(30.0, self._request_stats).start()
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

	# ANALIZE ACTIVE FLOWS REPLY
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
		global active_flows
		global classified_flows
		global flows_state
        body = ev.msg.body
		self.logger.debug('FLOW CONTROL reply at %s',datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
		for flow_id in active_flows :		
        	valid=0
		    for stat in sorted([flow for flow in body if flow.priority >= 34500 ],
		                       key=lambda flow: (flow.priority)):
		        try:
		            if (stat.match['ipv4_src'] == flows_state[flow_id]['ip_src']) and (stat.match['tcp_src'] == flows_state[flow_id]['port_src']):
		                valid=1
		        except:
		            pass
		        try:
		            if (stat.match['ipv4_dst'] == flows_state[flow_id]['ip_src']) and (stat.match['tcp_dst'] == flows_state[flow_id]['port_src']):
		                valid=1
		        except:
		            pass
			if valid == 1 :
		    	self.logger.info('flow %s is active', flow_id)
			elif valid == 0 :
		    	self.logger.info('flow %s is not active', flow_id)
				active_flows.remove(flow_id)
		    	self.logger.info('flow %s removed from active_flows', flow_id)
				try:
					classified_flows.remove(flow_id)
		    		self.logger.info('flow %s removed from classified_flows', flow_id)
				except:
		            pass
		self.logger.info('[ %s ]: flows active: %s',datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'), active_flows)
		# ANALIZE IF CONGESTION ARISE
		if len(active_flows) <= flowlimit :
			self.logger.debug('Not Enforcement State')
			self._handle_NotEnforcement_N_State()
		else
			self.logger.debug('WARNING! - Too many active flows: Enforcement State')
			self._handle_Enforcement_E_State()

	# DPI FUNCTIONS
	def startDPI(self):
		os.system("ssh ubuntu@10.15.0.1 -p 44444 'sudo nohup  %s -i eth0 -v 2 -j %s  > foo.out 2> foo.err < /dev/null & '" % (self.dpiExePath, self.dpiCapPath))
		self.logger.debug("[CONTROLLER - TIMER (%s)] DPI started!\n\n\n\n", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')) 

	def stopDPI(self):
		os.system("ssh ubuntu@10.15.0.1 -p 44444 'sudo kill -2 $(pgrep ndpi) '")
		self.logger.debug("[CONTROLLER - TIMER (%s)] DPI stopped!", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))

	def cleanDPI(self):
		os.system("ssh ubuntu@10.15.0.1 -p 44444 'sudo killall  ndpi '")

	def obtain_DPI_output(self):
		#return subprocess.check_output(['ssh', 'ubuntu@10.15.0.1', '-p', '44444', 'sudo cat %s' % self.dpiCapPath ]) 
		result = None
		try:
			result = subprocess.check_output(['ssh', 'ubuntu@10.15.0.1', '-p', '44444', 'sudo cat %s' % self.dpiCapPath ])
		except subprocess.CalledProcessError as e:
			result = e.output
		return result

	def _get_ports_info(self, dpid): #Return information about all port on a switch
		return self.dpset.get_ports(dpid)

	def _get_port_name(self, dpid, port): #Return the name associated to the specified port number on the specified switch
		return self.dpset.get_port(dpid, port).name

	def connectionForBridge(self, bridge):
		if bridge in self.connections_name_dpid:
			return self.connections_name_dpid[bridge]
		else:
			return -1

	#function executed after DPI analysis
	def dpi_analysis_finished (self, flow_id):
		
		global flow_id
		
		# Step 1: stop DPI
		self.stopDPI()
		time.sleep(0.15)
   
		self.logger.debug("[DEBUG - READING JSON FILE] ") 
		# Step 2: read json output file (DPI classification)
		json_data = self.obtain_DPI_output() 
		self.logger.debug("[DEBUG - JSON] %s", str(json_data))
		data = json.loads(json_data)
		list_of_flows = data["known.flows"]

		# Cycle over the known flows captured by nDPI
		for i in list_of_flows:
			if i['protocol'] == "TCP" or i['protocol'] == "UDP":  
				host_a = i["host_a.name"]
				host_b = i["host_b.name"]
				port_a = i["host_a.port"]
				port_b = i["host_n.port"]
				str_host_a = str(host_a)
				str_host_b = str(host_b)
				str_port_a = str(port_a)
				str_port_b = str(port_b)
				self.logger.debug("[CONTROLLER - TIMER (%s)] Host %s:%s is exchanging packets with Host %s:%s, via %s ", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'), i["host_a.name"], i["host_a.port"], i["host_b.name"], i["host_n.port"], i['protocol'])

				# UPDATING FLOW INFORMATIONS
				if host_a == self.ip_bususer or host_a == self.ip_resuser or host_b == self.ip_bususer or host_b == self.ip_resuser :   
					self._memFlow(flow_id, ip_src=host_a, port_src=port_a, ip_dst=host_b, port_dst=port_b)
					time.sleep(0.10)
					self._handle_PreventiveEnforcement_E_State(flow_id)

	def add_flow(self, datapath, priority, match, actions, h_timeout=0, buffer_id=None, timeout=0):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=timeout, hard_timeout=h_timeout, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=timeout, hard_timeout=h_timeout, priority=priority, match=match, instructions=inst)
  
		datapath.send_msg(mod)

	# UTILITY
	def _memFlow(self, flow_id, ip_src="0.0.0.0", port_src=0, ip_dst="0.0.0.0", port_dst=0, in_port=0, ip_proto=0, state="X", rules=[]) :

		global flows_state
		global active_flows

		if flow_id in active_flows :
			if ip_src != "0.0.0.0" :
				flows_state[flow_id]['ip_src'] = ip_src
			if port_src != 0 :
				flows_state[flow_id]['port_src'] = port_src
			if ip_dst != "0.0.0.0" :
				flows_state[flow_id]['ip_dst'] = ip_dst
			if port_dst != 0 :
				flows_state[flow_id]['port_dst'] = port_dst
			if in_port != 0 :
				flows_state[flow_id]['in_port'] = in_port
			if ip_proto != 0 :
				flows_state[flow_id]['ip_proto'] = ip_proto
			if state != "X" :
				flows_state[flow_id]['state'] = state
			if rules != [] :
				flows_state[flow_id]['rules'] = rules
		else	#NEW FLOW
			flow={}
			flow['flow_id'] = flow_id
			flow['ip_src'] = ip_src
			flow['port_src'] = port_src
			flow['ip_dst'] = ip_dst
			flow['port_dst'] = port_dst
			flow['in_port'] = in_port
			flow['ip_proto'] = ip_proto
			flow['state'] = state
			flow['rules'] = rules
			flows_state.append(flow)
			active_flows.append(flow_id)

	#UPDATE LOG
	self.logger.debug("**FLOW UPGRADED** : %s", flows_state[flow_id])

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

				# ARP and ICMP
				_handle_Initial_Init_State(self, datapath)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.switch_dpid_name:
                self.logger.debug("[TIMER (%s)] [SC-HANDLER] Switch %s disconnected", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'), self.switch_dpid_name[datapath.id])
                del self.connections_name_dpid[self.switch_dpid_name[datapath.id]]
                del self.switch_dpid_name[datapath.id] 

	#Handle PacketIn event
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):

		global flow_id
		self.logger.debug("[DEBUG] FLOW-ID %s", flow_id)

		msg = ev.msg
		pkt = packet.Packet(msg.data)

		header = pkt.get_protocol(ipv4.ipv4)
		self.logger.debug("[DEBUG] ip_proto=%s ip_src=%s ip_dst=%s in_port=%d", header.proto, header.src, header.dst, in_port)

		np = len(pkt.get_protocols(ethernet.ethernet))
		self.logger.debug("[PKT-HANDLER]  (%s) Number of detected protocols: %d", datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'), np)
		if np == 1:

			self._handle_Classification_C_State(flow_id, msg)

			#ATTESA DI 60 SECONDI E FINE ANALISI
            t=Timer(60.0, self.dpi_analysis_finished(flow_id):)
            t.start()

		else:
			self.logger.debug("More than one protocol detected")




	# STATE MACHINE -----------------------------------------------------------------


	# ----------------------INITIAL STATE----------------------

	def _handle_Initial_Init_State(self, dp):
		tmp_list_opts = []
		tmp_list_actions = []
		tmp_dict_match = {}
		tmp_dict_actions = {}
	
		# ARP packets
		switch_port = []
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
		msg = parser.OFPFlowMod( instructions=inst, priority = 32000, match = parser.OFPMatch(eth_type = 2054) )
		dp.send(msg)	
		# Add the previous rule to internal memory
		# Options
		tmp_dict_opts['priority'] = msg.priority
		# Matching rule
		tmp_dict_match['eth_type'] = msg.match.eth_type
		# Actions
		switch_port.append('OFPP_NORMAL')
		tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
		tmp_dict_actions['port'] = switch_port[0]
		tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
		tmp_dict_actions.clear() # Empty dict_actions

		tmp_list_opts = []
		tmp_list_actions = []
		tmp_dict_match = {}
		tmp_dict_actions = {}

		# ICMP packets
		switch_port = []
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
		msg = parser.OFPFlowMod( instructions=inst, priority = 32000, match = parser.OFPMatch(eth_type = 2048, ip_proto=1) )
		dp.send(msg)	
		# Add the previous rule to internal memory
		# Options
		tmp_dict_opts['priority'] = msg.priority
		# Matching rule
		tmp_dict_match['eth_type'] = msg.match.eth_type
		tmp_dict_match['ip_proto'] = msg.match.ip_proto
		# Actions
		switch_port.append('OFPP_NORMAL')
		tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
		tmp_dict_actions['port'] = switch_port[0]
		tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
		tmp_dict_actions.clear() # Empty dict_actions 

		tmp_list_opts = []
		tmp_list_actions = []
		tmp_dict_match = {}
		tmp_dict_actions = {}

	# ----------------------CLASSIFICATION STATE----------------------

	def _handle_Classification_C_State(self, flow_id, match_from_packet): 
		global active_flows
		tmp_list_opts = []
		tmp_list_actions = []
		tmp_dict_match = {}
		tmp_dict_actions = {}
	
		rules_list = []

		datapath = match_from_packet.datapath
		parser = datapath.ofproto_parser
		coming_port =  match_from_packet.match['in_port']
	
		pkt = packet.Packet(match_from_packet.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]
		eth_type = eth.ethertype 
	
		if eth_type == ether.ETH_TYPE_IP :		# TCP or UDP CASE
		
			pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
			nw_src = pkt_ipv4.src
			nw_dst = pkt_ipv4.dst
			pkt_tcp = pkt.get_protocol(tcp.tcp)
		
			# br-int internal network, outbound traffic, from User to DPI, MAC_DST is changed
			switch_port = []
			action=[]
			switch_port = self.get_in_port('DPI', 'outbound')		#2 elements vector, at 0 switchname, 1 port
			mac_addr = self.get_in_mac_address('DPI', 'outbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action.append( parser.OFPActionSetField(eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through...
			action.append( parser.OFPActionOutput( switch_port[1] ) ) #...DPI
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( hard_timeout=270, priority=34500, match=parser.OFPMatch( in_port = coming_port, eth_type = 2048, ip_proto=pkt_ipv4.proto, ipv4_src = nw_src, tcp_src = pkt_tcp.src_port), instructions=inst )
			dp.send_msg(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['hard_timeout'] = msg.hard_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
			tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
			tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]	
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}	
			rules_list.append(rule)

			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# br-int internal network, inbound traffic, from DPI to User
			switch_port = []
			switch_port = self.get_in_port('DPI', 'outbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( hard_timeout=270, priority = 34500, match = parser.OFPMatch( in_port = switch_port[1], eth_type = 2048, ip_proto=pkt_ipv4.proto, ipv4_dst = nw_src, tcp_dst = pkt_tcp.src_port), instructions=inst )
			dp.send(msg)	
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['hard_timeout'] = msg.hard_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
	  		switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[2]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions 
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
	
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# br-int Gateway network, inbound traffic, from br4 to DPI, MAC_DST is changed
			switch_port = []
			action=[]
			switch_port = self.get_in_port('DPI', 'inbound')
			mac_addr = self.get_in_mac_address('DPI', 'inbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action.append( parser.OFPActionSetField( eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
			action.append( parser.OFPActionOutput( switch_port[1] ) ) #...DPI
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( hard_timeout=270, priority=34500, match=parser.OFPMatch( in_port = self.outport, eth_type = 2048, ip_proto=pkt_ipv4.proto, ipv4_dst = nw_src, tcp_dst = pkt_tcp.src_port ), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['hard_timeout'] = msg.hard_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
			tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
			tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions 

			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)

			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# br-int Gateway network, outbound traffic, from DPI to br4
			switch_port = []
			switch_port = self.get_in_port('DPI', 'inbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( hard_timeout=270, priority = 34500, match = parser.OFPMatch(in_port = switch_port[1], eth_type = 2048, ip_proto=pkt_ipv4.proto, ipv4_src = nw_src,  tcp_src = pkt_tcp.src_port), instructions=inst )
			dp.send(msg)	
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['hard_timeout'] = msg.hard_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
	  		switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[2]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
	
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}
	
			# br4, outbound traffic
			switch_port = []	
			switch_port.append('br4')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( hard_timeout=270, priority = 34500, match = parser.OFPMatch( eth_type = 2048, ip_proto=pkt_ipv4.proto, ipv4_src = nw_src,  tcp_src = pkt_tcp.src_port), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['hard_timeout'] = msg.hard_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
	  		switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions 
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
	
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}
	
			# br4, inbound traffic
			switch_port = []	
			switch_port.append('br4')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( hard_timeout=270, priority = 34500, match = parser.OFPMatch( eth_type = 2048, ip_proto=pkt_ipv4.proto, ipv4_dst = nw_src,  tcp_dst = pkt_tcp.src_port), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['hard_timeout'] = msg.hard_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
	  		switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions 
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
	
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# br3, outbound traffic
			switch_port = []	
			switch_port.append('br3')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( hard_timeout=270, priority = 34500, match = parser.OFPMatch(eth_type = 2048, ip_proto=pkt_ipv4.proto, ipv4_src = nw_src,  tcp_src = pkt_tcp.src_port), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['hard_timeout'] = msg.hard_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
	  		switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
	
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# br3, inbound traffic
			switch_port = []	
			switch_port.append('br3')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( hard_timeout=270, priority = 34500, match = parser.OFPMatch(eth_type = 2048, ip_proto=pkt_ipv4.proto, ipv4_dst = nw_src,  tcp_dst = pkt_tcp.src_port), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['hard_timeout'] = msg.hard_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
	  		switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
	
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# START DPI
			self.startDPI()

			# UPDATE ACTIVE FLOWS
			active_flows.append(flow_id)

		else :			# D CASE
	
			self._handle_NotCompliant_D_State(flow_id, datapath)

		# SAVING CURRENT FLOW IN FLOW_STATE
		self._memFlow(flow_id, state = 'C', rules = rules_list)

	# ----------------------NOT COMPLIANT STATE----------------------

	def _handle_NotCompliant_D_State(self, flow_id, datapath): 
		tmp_list_opts = []
		tmp_list_actions = []
		tmp_dict_match = {}
		tmp_dict_actions = {}
	
		rules_list = []
	
		global flow_state

		# packet dropping rules
		switch_port = []
		action=[]
		ofproto = dp.ofproto
		parser = datapath.ofproto_parser
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
		msg = parser.OFPFlowMod(priority=30000, match=parser.OFPMatch( in_port = flow_state[flow_id]['in_port'], eth_type = eth.ethertype, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_src = flow_state[flow_id]['ip_src'], tcp_src = flow_state[flow_id]['port_src'] ), instructions=inst)
		datapath.send_msg(msg)
		# Add the previous rule to internal memory
		# Options
		tmp_dict_opts['priority'] = msg.priority
		# Matching rule
		tmp_dict_match['in_port'] = msg.match.in_port
		tmp_dict_match['eth_type'] = msg.match.eth_type
		tmp_dict_match['ip_proto'] = msg.match.ip_proto
		tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
		tmp_dict_match['tcp_src'] = msg.match.tcp_src
		# Actions
	  	switch_port.append('OFPP_F')
		tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
		tmp_dict_actions['port'] = switch_port[1]
		tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
		tmp_dict_actions.clear() # Empty dict_actions

		rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
		rules_list.append(rule)

		tmp_list_opts = []
		tmp_list_actions = []
		tmp_dict_match = {}
		tmp_dict_actions = {}

		# SAVING CURRENT FLOW IN FLOW_STATE
		self._memFlow(flow_id, state = 'D', rules = rules_list)


	# ----------------------PREVENTIVE ENFORCEMENT STATE----------------------

	def _handle_PreventiveEnforcement_E_State(self, flow_id): 
		tmp_list_opts = []
		tmp_list_actions = []
		tmp_dict_match = {}
		tmp_dict_actions = {}
	
		rules_list = []
	
		global flow_state
		global classified_flows
		global hipriousers

	
		if flow_state[flow_id]['ip_src'] in hipriousers :		#HIGH PRIORITY CASE
			
			# br-int internal network, outbound traffic, from HiPrioUser to Wana (LAN port), MAC_DST is changed
			switch_port = []
			action=[]
			switch_port = self.get_in_port('Wana', 'outbound')
			mac_addr = self.get_in_mac_address('Wana', 'outbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action.append( parser.OFPActionSetField(eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
			action.append( parser.OFPActionOutput( switch_port[1] ) ) #...WANA (LAN port)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod(idle_timeout=60, priority=34501, match=parser.OFPMatch( in_port = flow_state[flow_id]['in_port'], eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_src = flow_state[flow_id]['ip_src'], tcp_src = flow_state[flow_id]['port_src'] ), instructions=inst )
			dp.send_msg(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
			tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
			tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]	
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions

			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)

			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}
			

			# br-int internal network, inbound traffic, from Wana (LAN port) to HiPrioUser
			switch_port = []
			switch_port = self.get_in_port('Wana', 'outbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch	( in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_dst = flow_state[flow_id]['ip_src'],  tcp_dst = flow_state[flow_id]['port_src']), instructions=inst )
			dp.send(msg)	
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
			switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[2]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions 
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
		
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# br-int Gateway network, inbound traffic, from br4 to Wana (WAN port), MAC_DST is changed
			switch_port = []
			action=[]
			switch_port = self.get_in_port('Wana', 'inbound')
			mac_addr = self.get_in_mac_address('Wana', 'inbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action.append( parser.OFPActionSetField( eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
			action.append( parser.OFPActionOutput( switch_port[1] ) ) #...Wana (WAN port)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority=34501, match=parser.OFPMatch( in_port = self.outport, eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_dst = flow_state[flow_id]['ip_src'], tcp_dst = flow_state[flow_id]['port_src'] ), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
			tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
			tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions 	

			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)

			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# br-int Gateway network, outbound traffic, from Wana (WAN port) to br4
			switch_port = []
			switch_port = self.get_in_port('Wana', 'inbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch(in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_src = flow_state[flow_id]['ip_src'],  tcp_src = flow_state[flow_id]['port_src']), instructions=inst )
			dp.send(msg)	
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
			switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[2]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
		
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
		
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# br4, outbound traffic, to WanaDec
			switch_port = []
			action=[]
			switch_port = self.get_in_port('WanaDec', 'outbound')		#vettore con due elementi, indice 0 nome switch, indice 1 porta
			mac_addr = self.get_in_mac_address('WanaDec', 'outbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action.append( parser.OFPActionSetField(eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
			action.append( parser.OFPActionOutput( switch_port[1] ) ) #...WanaDec (WAN port)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority=34501, match=parser.OFPMatch( eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_src = flow_state[flow_id]['ip_src'], tcp_src = flow_state[flow_id]['port_src'] ), instructions=inst )
			dp.send_msg(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
			tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
			tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]	
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions

			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)

			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# br4, inbound traffic, from WanaDec
			switch_port = []
			switch_port = self.get_in_port('WanaDec', 'outbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod(idle_timeout=60, priority = 34501, match = parser.OFPMatch(in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_dst = flow_state[flow_id]['ip_src'],  tcp_dst = flow_state[flow_id]['port_src']), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
			switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[2]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions 

			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
	
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# br3, outbound traffic, from WanaDec
			switch_port = []
			switch_port = self.get_in_port('WanaDec', 'inbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod(idle_timeout=270, priority = 34501, match = parser.OFPMatch(in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_src = flow_state[flow_id]['ip_src'], tcp_src = flow_state[flow_id]['port_src']), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
			switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[2]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
		
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
	
			tmp_list_opts = []
			tmp_list_actions = []	
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# br3, inbound traffic
			switch_port = []
			action=[]
			switch_port = self.get_in_port('WanaDec', 'inbound')
			mac_addr = self.get_in_mac_address('WanaDec', 'inbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action.append( parser.OFPActionSetField( eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
			action.append( parser.OFPActionOutput( switch_port[1] ) ) #...WanaDec (LAN port)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority=34501, match=parser.OFPMatch(eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_dst = flow_state[flow_id]['ip_src'], tcp_dst = flow_state[flow_id]['port_src'] ), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
			tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
			tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
	
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

		else		#LOW PRIORITY CASE

			# TCP : br-int internal network, outbound traffic, from LowPrioUser to TC (1st port), MAC_DST is changed
			switch_port = []
			action=[]
			switch_port = self.get_in_port('TC', 'outbound')	
			mac_addr = self.get_in_mac_address('TC', 'outbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action.append( parser.OFPActionSetField(eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
			action.append( parser.OFPActionOutput( switch_port[1] ) ) #...TC (1st port)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod(idle_timeout=60, priority=34501, match=parser.OFPMatch( in_port = flow_state[flow_id]['in_port'], eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_src = flow_state[flow_id]['ip_src'], tcp_src = flow_state[flow_id]['port_src'] ), instructions=inst )
			dp.send_msg(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
			tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
			tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]	
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# TCP : br-int internal network, inbound traffic, from TC (1st port) to LowPrioUser
			switch_port = []
			switch_port = self.get_in_port('TC', 'outbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch	( in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_dst = flow_state[flow_id]['ip_src'],  tcp_dst = flow_state[flow_id]['port_src']), instructions=inst )
			dp.send(msg)	
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
			switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[2]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions 
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
		
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# TCP : br-int Gateway network, inbound traffic, from br4 to TC (2nd port), MAC_DST is changed
			switch_port = []
			action=[]
			switch_port = self.get_in_port('Wana', 'inbound')
			mac_addr = self.get_in_mac_address('Wana', 'inbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action.append( parser.OFPActionSetField( eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
			action.append( parser.OFPActionOutput( switch_port[1] ) ) #...TC (2nd port)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority=34501, match=parser.OFPMatch( in_port = self.outport, eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_dst = flow_state[flow_id]['ip_src'], tcp_dst = flow_state[flow_id]['port_src'] ), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
			tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
			tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions 	

			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)

			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# TCP : br-int Gateway network, outbound traffic, from TC (2nd port) to br4
			switch_port = []
			switch_port = self.get_in_port('TC', 'inbound')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch(in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_src = flow_state[flow_id]['ip_src'],  tcp_src = flow_state[flow_id]['port_src']), instructions=inst )
			dp.send(msg)	
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['in_port'] = msg.match.in_port
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
			switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[2]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
		
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
		
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}
	
			# TCP : br4, outbound traffic
			switch_port = []	
			switch_port.append('br4')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch( eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'],  ipv4_src = flow_state[flow_id]['ip_src'],  tcp_src = flow_state[flow_id]['port_src']), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
			switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions 
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
	
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}
	
			# TCP : br4, inbound traffic
			switch_port = []	
			switch_port.append('br4')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch	( eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_dst = flow_state[flow_id]['ip_src'], tcp_dst = flow_state[flow_id]['port_src']), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
			switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions 
		
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
		
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

			# TCP : br3, outbound traffic
			switch_port = []	
			switch_port.append('br3')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch(eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'],  ipv4_src = flow_state[flow_id]['ip_src'],  tcp_src = flow_state[flow_id]['port_src']), instructions=inst )
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
			tmp_dict_match['tcp_src'] = msg.match.tcp_src
			# Actions
			switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
	
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
		
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}
	
			# TCP : br3, inbound traffic
			switch_port = []
			switch_port.append('br3')
			dp=connectionForBridge(switch_port[0])
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
			action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
			msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch(eth_type = 2048, ip_proto=flow_state[flow_id]['ip_proto'], ipv4_dst = flow_state[flow_id]['ip_src'], tcp_dst = flow_state[flow_id]['port_src']), instructions=inst )	
			dp.send(msg)
			# Add the previous rule to internal memory
			# Options
			tmp_dict_opts['idle_timeout'] = msg.idle_timeout
			tmp_dict_opts['priority'] = msg.priority
			# Matching rule
			tmp_dict_match['eth_type'] = msg.match.eth_type
			tmp_dict_match['ip_proto'] = msg.match.ip_proto
			tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
			tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
			# Actions
			switch_port.append('OFPP_NORMAL')
			tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
			tmp_dict_actions['port'] = switch_port[1]
			tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
			tmp_dict_actions.clear() # Empty dict_actions
		
			rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
			rules_list.append(rule)
		
			tmp_list_opts = []
			tmp_list_actions = []
			tmp_dict_match = {}
			tmp_dict_actions = {}

		# SAVING CURRENT FLOW IN FLOW_STATE
		self._memFlow(flow_id, state = 'E', rules = rules_list)

		# ADD THE FLOW TO THE CLASSIFIED LIST
		classified_flows.append(flow_id)

		# FLOWS CONTROL START WHEN FIRST FLOW
		if flow_id=0 :
			self._request_stats()

		# UPDATE FLOW-ID
		time.sleep(0.10)
		global flow_id
		flow_id=flow_id+1

	# ----------------------ENFORCEMENT STATE----------------------

	def _handle_Enforcement_E_State(self): 
		tmp_list_opts = []
		tmp_list_actions = []
		tmp_dict_match = {}
		tmp_dict_actions = {}
	
		rules_list = []
	
		global flows_state
		global classified_flows
		global hipriousers

		for flow in classified_flows :
			if flow_state[flow]['state'] != 'E' :
				if flow_state[flow]['ip_src'] in hipriousers :		#HIGH PRIORITY CASE
				
					# br-int internal network, outbound traffic, from HiPrioUser to Wana (LAN port), MAC_DST is changed
					switch_port = []
					action=[]
					switch_port = self.get_in_port('Wana', 'outbound')
					mac_addr = self.get_in_mac_address('Wana', 'outbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action.append( parser.OFPActionSetField(eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
					action.append( parser.OFPActionOutput( switch_port[1] ) ) #...WANA (LAN port)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod(idle_timeout=60, priority=34501, match=parser.OFPMatch( in_port = flow_state[flow]['in_port'], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_src = flow_state[flow]['ip_src'], tcp_src = flow_state[flow]['port_src'] ), instructions=inst )
					dp.send_msg(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['in_port'] = msg.match.in_port
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
					tmp_dict_match['tcp_src'] = msg.match.tcp_src
					# Actions
					tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
					tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[1]	
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions

					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)

					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}
			
					# br-int internal network, inbound traffic, from Wana (LAN port) to HiPrioUser
					switch_port = []
					switch_port = self.get_in_port('Wana', 'outbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch	( in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src']), instructions=inst )
					dp.send(msg)	
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['in_port'] = msg.match.in_port
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
					tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
					# Actions
					switch_port.append('OFPP_NORMAL')
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[2]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions 

					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
		
					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}

					# br-int Gateway network, inbound traffic, from br4 to Wana (WAN port), MAC_DST is changed
					switch_port = []
					action=[]
					switch_port = self.get_in_port('Wana', 'inbound')
					mac_addr = self.get_in_mac_address('Wana', 'inbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action.append( parser.OFPActionSetField( eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
					action.append( parser.OFPActionOutput( switch_port[1] ) ) #...WANA (WAN port)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority=34501, match=parser.OFPMatch( in_port = self.outport, eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src'] ), instructions=inst )
					dp.send(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['in_port'] = msg.match.in_port
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
					tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
					# Actions
					tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
					tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[1]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions

					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)

					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}

					# br-int Gateway network, outbound traffic, from Wana (WAN port) to br4
					switch_port = []
					switch_port = self.get_in_port('Wana', 'inbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch(in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_src = flow_state[flow]['ip_src'], tcp_src = flow_state[flow]['port_src']), instructions=inst )
					dp.send(msg)	
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['in_port'] = msg.match.in_port
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
					tmp_dict_match['tcp_src'] = msg.match.tcp_src
					# Actions
					switch_port.append('OFPP_NORMAL')
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[2]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions
		
					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
		
					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}

					# br4, outbound traffic, to WanaDec
					switch_port = []
					action=[]
					switch_port = self.get_in_port('WanaDec', 'outbound')
					mac_addr = self.get_in_mac_address('WanaDec', 'outbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action.append( parser.OFPActionSetField(eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
					action.append( parser.OFPActionOutput( switch_port[1] ) ) #... WanaDec (WAN port)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority=34501, match=parser.OFPMatch( eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_src = flow_state[flow]['ip_src'], tcp_src = flow_state[flow]['port_src'] ), instructions=inst )
					dp.send_msg(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
					tmp_dict_match['tcp_src'] = msg.match.tcp_src
					# Actions
					tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
					tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[1]	
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions

					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)

					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}

					# br4, inbound traffic, from WanaDec
					switch_port = []
					switch_port = self.get_in_port('WanaDec', 'outbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod(idle_timeout=60, priority = 34501, match = parser.OFPMatch(in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'],  tcp_dst = flow_state[flow]['port_src']), instructions=inst )
					dp.send(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['in_port'] = msg.match.in_port
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
					tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
					# Actions
					switch_port.append('OFPP_NORMAL')
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[2]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions 
	
					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
	
					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}

					# br3, outbound traffic, from WanaDec
					switch_port = []
					switch_port = self.get_in_port('WanaDec', 'inbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod(idle_timeout=270, priority = 34501, match = parser.OFPMatch(in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_src = flow_state[flow]['ip_src'],  tcp_src = flow_state[flow]['port_src']), instructions=inst )
					dp.send(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['in_port'] = msg.match.in_port
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
					tmp_dict_match['tcp_src'] = msg.match.tcp_src
					# Actions
					switch_port.append('OFPP_NORMAL')
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[2]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions
		
					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
	
					tmp_list_opts = []
					tmp_list_actions = []	
					tmp_dict_match = {}
					tmp_dict_actions = {}

					# br3, inbound traffic
					switch_port = []
					action=[]
					switch_port = self.get_in_port('WanaDec', 'inbound')
					mac_addr = self.get_in_mac_address('WanaDec', 'inbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action.append( parser.OFPActionSetField( eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
					action.append( parser.OFPActionOutput( switch_port[1] ) ) #... WanaDec (LAN port)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority=34501, match=parser.OFPMatch(eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src'] ), instructions=inst )
					dp.send(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
					tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
					# Actions
					tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
					tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[1]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions
	
					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
	
					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}
			
				else	#LOW PRIORITY CASE

					# br-int internal network, outbound traffic, from LowPrioUser to TC (1st port), MAC_DST is changed
					switch_port = []
					action=[]
					switch_port = self.get_in_port('TC', 'outbound')		
					mac_addr = self.get_in_mac_address('TC', 'outbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action.append( parser.OFPActionSetField(eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
					action.append( parser.OFPActionOutput( switch_port[1] ) ) #...TC (1st port)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod(idle_timeout=60, priority=34501, match=parser.OFPMatch( in_port = flow_state[flow]['in_port'], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_src = flow_state[flow]['ip_src'], tcp_src = flow_state[flow]['port_src'] ), instructions=inst )
					dp.send_msg(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['in_port'] = msg.match.in_port
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
					tmp_dict_match['tcp_src'] = msg.match.tcp_src
					# Actions
					tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
					tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[1]	
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions
					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}

					# br-int internal network, inbound traffic, from TC (1st port) to LowPrioUser
					switch_port = []
					switch_port = self.get_in_port('TC', 'outbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch	( in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'],  tcp_dst = flow_state[flow]['port_src']), instructions=inst )
					dp.send(msg)	
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['in_port'] = msg.match.in_port
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
					tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
					# Actions
					switch_port.append('OFPP_NORMAL')
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[2]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions 
	
					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
		
					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}

					# br-int Gateway network, inbound traffic, from br4 to TC (2nd port), MAC_DST is changed
					switch_port = []
					action=[]
					switch_port = self.get_in_port('TC', 'inbound')
					mac_addr = self.get_in_mac_address('TC', 'inbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action.append( parser.OFPActionSetField( eth_dst= mac_addr ) ) # Change MAC_DST because packets must go through ...
					action.append( parser.OFPActionOutput( switch_port[1] ) ) #...TC (2nd port)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority=34501, match=parser.OFPMatch( in_port = self.outport, eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src'] ), instructions=inst )
					dp.send(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['in_port'] = msg.match.in_port
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
					tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
					# Actions
					tmp_dict_actions['type'] = 'OFPAT_SET_DL_DST'
					tmp_dict_actions['dl_addr'] = mac_addr # string format: remember to convert to EthAddr()
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[1]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions 	

					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)

					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}

					# br-int Gateway network, outbound traffic, from TC (2nd port) to br4
					switch_port = []
					switch_port = self.get_in_port('TC', 'inbound')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch(in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_src = flow_state[flow]['ip_src'],  tcp_src = flow_state[flow]['port_src']), instructions=inst )
					dp.send(msg)	
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['in_port'] = msg.match.in_port
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
					tmp_dict_match['tcp_src'] = msg.match.tcp_src
					# Actions
					switch_port.append('OFPP_NORMAL')
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[2]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions
		
					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
		
					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}
	
					# br4, outbound traffic
					switch_port = []
					switch_port.append('br4')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch( eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'],  ipv4_src = flow_state[flow]['ip_src'],  tcp_src = flow_state[flow]['port_src']), instructions=inst )	
					dp.send(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
					tmp_dict_match['tcp_src'] = msg.match.tcp_src
					# Actions
					switch_port.append('OFPP_NORMAL')
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[1]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions 
	
					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
	
					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}
	
					# br4, inbound traffic
					switch_port = []	
					switch_port.append('br4')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch	( eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src']), instructions=inst )
					dp.send(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
					tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
					# Actions
					switch_port.append('OFPP_NORMAL')
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[1]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions 
		
					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
		
					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}

					# br3, outbound traffic
					switch_port = []
					switch_port.append('br3')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch(eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'],  ipv4_src = flow_state[flow]['ip_src'],  tcp_src = flow_state[flow]['port_src']), instructions=inst )	
					dp.send(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
					tmp_dict_match['tcp_src'] = msg.match.tcp_src
					# Actions
					switch_port.append('OFPP_NORMAL')
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[1]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions

					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
		
					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}
	
					# br3, inbound traffic
					switch_port = []	
					switch_port.append('br3')
					dp=connectionForBridge(switch_port[0])
					ofproto = dp.ofproto
					parser = dp.ofproto_parser
					action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
					inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
					msg = parser.OFPFlowMod( idle_timeout=60, priority = 34501, match = parser.OFPMatch(eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src']), instructions=inst )
					dp.send(msg)
					# Add the previous rule to internal memory
					# Options
					tmp_dict_opts['idle_timeout'] = msg.idle_timeout
					tmp_dict_opts['priority'] = msg.priority
					# Matching rule
					tmp_dict_match['eth_type'] = msg.match.eth_type
					tmp_dict_match['ip_proto'] = msg.match.ip_proto
					tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
					tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
					# Actions
					switch_port.append('OFPP_NORMAL')
					tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
					tmp_dict_actions['port'] = switch_port[1]
					tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
					tmp_dict_actions.clear() # Empty dict_actions

					rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
					rules_list.append(rule)
		
					tmp_list_opts = []
					tmp_list_actions = []
					tmp_dict_match = {}
					tmp_dict_actions = {}

				# DELETE NOT ENFORCEMENT STATE RULES------------------------

				# br-int internal network, outbound traffic, from User to gw
				switch_port = []
				switch_port = self.get_in_port('gw', 'outbound')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod(idle_timeout=60, priority=34502, match=parser.OFPMatch( in_port = flow_state[flow]['in_port'], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_src = flow_state[flow]['ip_src'], tcp_src = flow_state[flow]['port_src'] ), instructions=inst, command=ofproto.OFPFC_DELETE  )
				dp.send_msg(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['in_port'] = msg.match.in_port
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
				tmp_dict_match['tcp_src'] = msg.match.tcp_src
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[2]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions

				rule = {'switch': switch_port[0].id, 'op': 'DEL', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)

				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br-int internal network, inbound traffic, from gw to User
				switch_port = []
				switch_port = self.get_in_port('gw', 'outbound')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch	( in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'],  tcp_dst = flow_state[flow]['port_src']), instructions=inst, command=ofproto.OFPFC_DELETE  )
				dp.send(msg)	
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['in_port'] = msg.match.in_port
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
				tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[2]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions 
	
				rule = {'switch': switch_port[0].id, 'op': 'DEL', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
		
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br-int Gateway network, inbound traffic, from br4 to gw
				switch_port = []
				switch_port = self.get_in_port('gw', 'inbound')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority=34502, match=parser.OFPMatch( in_port = self.outport, eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src'] ), instructions=inst, command=ofproto.OFPFC_DELETE  )
				dp.send(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['in_port'] = msg.match.in_port
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
				tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[2]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions 

				rule = {'switch': switch_port[0].id, 'op': 'DEL', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)

				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br-int Gateway network, outbound traffic, from gw to br4
				switch_port = []
				switch_port = self.get_in_port('gw', 'inbound')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch(in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_src = flow_state[flow]['ip_src'],  tcp_src = flow_state[flow]['port_src']), instructions=inst, command=ofproto.OFPFC_DELETE  )
				dp.send(msg)	
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['in_port'] = msg.match.in_port
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
				tmp_dict_match['tcp_src'] = msg.match.tcp_src
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[2]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions
		
				rule = {'switch': switch_port[0].id, 'op': 'DEL', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
		
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br4, outbound traffic
				switch_port = []	
				switch_port.append('br4')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch( eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'],  ipv4_src = flow_state[flow]['ip_src'], tcp_src = flow_state[flow]['port_src']), instructions=inst, command=ofproto.OFPFC_DELETE  )
				dp.send(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
				tmp_dict_match['tcp_src'] = msg.match.tcp_src
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[1]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions 
	
				rule = {'switch': switch_port[0].id, 'op': 'DEL', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
	
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br4, inbound traffic
				switch_port = []
				switch_port.append('br4')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch	( eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src']), instructions=inst, command=ofproto.OFPFC_DELETE  )	
				dp.send(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
				tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[1]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions 
	
				rule = {'switch': switch_port[0].id, 'op': 'DEL', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
	
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br3, outbound traffic
				switch_port = []
				switch_port.append('br3')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch(eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'],  ipv4_src = flow_state[flow]['ip_src'], tcp_src = flow_state[flow]['port_src']), instructions=inst, command=ofproto.OFPFC_DELETE )
				dp.send(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
				tmp_dict_match['tcp_src'] = msg.match.tcp_src
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[1]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions
	
				rule = {'switch': switch_port[0].id, 'op': 'DEL', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
	
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br3, inbound traffic
				switch_port = []
				switch_port.append('br3')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch(eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src']), instructions=inst, command=ofproto.OFPFC_DELETE )	
				dp.send(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
				tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[1]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions
		
				rule = {'switch': switch_port[0].id, 'op': 'DEL', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
		
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# SAVING CURRENT FLOW IN FLOW_STATE
				self._memFlow(flow, state = 'E', rules = rules_list)


	# ----------------------NOT ENFORCEMENT STATE----------------------

	def _handle_NotEnforcement_N_State(self):
		tmp_list_opts = []
		tmp_list_actions = []
		tmp_dict_match = {}
		tmp_dict_actions = {}
	
		rules_list = []
	
		global flows_state
		global classified_flows

		for flow in classified_flows :
			if flow_state[flow]['state'] != 'N' :

				# br-int internal network, outbound traffic, from User to gw
				switch_port = []
				switch_port = self.get_in_port('gw', 'outbound')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod(idle_timeout=60, priority=34502, match=parser.OFPMatch( in_port = flow_state[flow]['in_port'], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_src = flow_state[flow]['ip_src'], tcp_src = flow_state[flow]['port_src'] ), instructions=inst  )
				dp.send_msg(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['in_port'] = msg.match.in_port
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
				tmp_dict_match['tcp_src'] = msg.match.tcp_src
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[2]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions

				rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)

				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br-int internal network, inbound traffic, from gw to User
				switch_port = []
				switch_port = self.get_in_port('gw', 'outbound')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch	( in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'],  tcp_dst = flow_state[flow]['port_src']), instructions=inst  )
				dp.send(msg)	
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['in_port'] = msg.match.in_port
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
				tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[2]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions 
	
				rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
		
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br-int Gateway network, inbound traffic, from br4 to gw
				switch_port = []
				switch_port = self.get_in_port('gw', 'inbound')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority=34502, match=parser.OFPMatch( in_port = self.outport, eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src'] ), instructions=inst  )
				dp.send(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['in_port'] = msg.match.in_port
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
				tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[2]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions 

				rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)

				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br-int Gateway network, outbound traffic, from gw to br4
				switch_port = []
				switch_port = self.get_in_port('gw', 'inbound')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch(in_port = switch_port[1], eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_src = flow_state[flow]['ip_src'],  tcp_src = flow_state[flow]['port_src']), instructions=inst  )
				dp.send(msg)	
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['in_port'] = msg.match.in_port
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
				tmp_dict_match['tcp_src'] = msg.match.tcp_src
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[2]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions
		
				rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
		
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br4, outbound traffic
				switch_port = []	
				switch_port.append('br4')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch( eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'],  ipv4_src = flow_state[flow]['ip_src'], tcp_src = flow_state[flow]['port_src']), instructions=inst  )
				dp.send(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
				tmp_dict_match['tcp_src'] = msg.match.tcp_src
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[1]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions 
	
				rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
	
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br4, inbound traffic
				switch_port = []
				switch_port.append('br4')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch	( eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src']), instructions=inst  )	
				dp.send(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
				tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[1]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions 
	
				rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
	
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br3, outbound traffic
				switch_port = []
				switch_port.append('br3')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch(eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'],  ipv4_src = flow_state[flow]['ip_src'], tcp_src = flow_state[flow]['port_src']), instructions=inst )
				dp.send(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_src'] = msg.match.ipv4_src
				tmp_dict_match['tcp_src'] = msg.match.tcp_src
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[1]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions
	
				rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
	
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# br3, inbound traffic
				switch_port = []
				switch_port.append('br3')
				dp=connectionForBridge(switch_port[0])
				ofproto = dp.ofproto
				parser = dp.ofproto_parser
				action=parser.OFPActionOutput(ofp.OFPP_NORMAL)
				inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
				msg = parser.OFPFlowMod( idle_timeout=60, priority = 34502, match = parser.OFPMatch(eth_type = 2048, ip_proto=flow_state[flow]['ip_proto'], ipv4_dst = flow_state[flow]['ip_src'], tcp_dst = flow_state[flow]['port_src']), instructions=inst )	
				dp.send(msg)
				# Add the previous rule to internal memory
				# Options
				tmp_dict_opts['idle_timeout'] = msg.idle_timeout
				tmp_dict_opts['priority'] = msg.priority
				# Matching rule
				tmp_dict_match['eth_type'] = msg.match.eth_type
				tmp_dict_match['ip_proto'] = msg.match.ip_proto
				tmp_dict_match['ipv4_dst'] = msg.match.ipv4_dst
				tmp_dict_match['tcp_dst'] = msg.match.tcp_dst
				# Actions
				switch_port.append('OFPP_NORMAL')
				tmp_dict_actions['type'] = 'OFPAT_OUTPUT'
				tmp_dict_actions['port'] = switch_port[1]
				tmp_list_actions.append(tmp_dict_actions) # Add actions to the list of actions
				tmp_dict_actions.clear() # Empty dict_actions
		
				rule = {'switch': switch_port[0].id, 'op': 'ADD', 'options': tmp_dict_opts, 'match': tmp_dict_match, 'actions': tmp_list_actions}
				rules_list.append(rule)
		
				tmp_list_opts = []
				tmp_list_actions = []
				tmp_dict_match = {}
				tmp_dict_actions = {}

				# SAVING CURRENT FLOW IN FLOW_STATE
				self._memFlow(flow, state = 'N', rules = rules_list)
