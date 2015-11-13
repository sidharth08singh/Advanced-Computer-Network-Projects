from pox.core import core
from pox.openflow import *
import string
import time
import threading
import pdb
from utils import *
from SimpleL2Learning import SimpleL2LearningSwitch
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.vlan import vlan
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.tcp import tcp
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.udp import udp

log = core.getLogger() # Use central logging service

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))

FLOW_HARD_TIMEOUT = 30
FLOW_IDLE_TIMEOUT = 10

class PfrSwitch(SimpleL2LearningSwitch):
	def __init__(self, connection, config):
		SimpleL2LearningSwitch.__init__(self, connection, False)
        	self._connection = connection;
		self._serverip1 = config['server_ip1']
		self._serverip1_mac = config['server_ip1_mac']    #MAC Address of the Neighbour connected to Backup Link
		self._serverip2 = config['server_ip2']
		self._serverip2_mac = config['server_ip2_mac']
		self._p1_total_bw = float(config['p1_total_bw']) * 1024 * 1024
		self._p2_total_bw = float(config['p2_total_bw']) * 1024 * 1024
		self._p1_delay = float(config['p1_delay'])
		self._p2_delay = float(config['p2_delay'])
		self._delay_threshold = float(config['delay_threshold'])
		self.FLAG = 0
		
		
	
	def _handle_PacketIn(self, event):
		self.packet = event.parsed
	        self.event = event
	        self.macLearningHandle()
		if packetIsTCP(self.packet, log) :
		        self._handle_PacketInTCP(event)
		        return
		elif packetIsUDP(self.packet, log):
			self._handle_PacketInUDP(event)
			return	
	        SimpleL2LearningSwitch._handle_PacketIn(self, event) #Default traffic, need to decide where to send
	
	def _handle_PacketInUDP(self,event):
		inport = event.port
        	actions = []	
		if ((self._p1_total_bw == self._p2_total_bw) and (self._p1_delay == self._p2_delay)):
			if packetDstIp(self.packet, self._serverip2, log ):
				if self.FLAG == 0:
					newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip1_mac, log)
					actions.append(newaction)
					newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
					actions.append(newaction)
					newaction = createOFAction(of.OFPAT_SET_TP_DST, 5004, log)
					actions.append(newaction)
					self.FLAG = 1
					out_port = 3
					newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
					actions.append(newaction)
					match = getFullMatch(self.packet, inport)
	        			msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  	FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        			event.connection.send(msg.pack())
				else:
					SimpleL2LearningSwitch._handle_PacketIn(self, event)
					self.FLAG = 0
			elif packetSrcIp(self.packet, self._serverip1, log ):
				newaction = createOFAction(of.OFPAT_SET_NW_SRC, self._serverip2, log)
				actions.append(newaction)
				newaction = createOFAction(of.OFPAT_SET_TP_SRC, 5001, log)
				actions.append(newaction)
				out_port = self.get_out_port()
				newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
				actions.append(newaction)
				match = getFullMatch(self.packet, inport)
				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                	FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        		event.connection.send(msg.pack())
			else:
				SimpleL2LearningSwitch._handle_PacketIn(self, event)

		elif ((self._p1_total_bw == self._p2_total_bw) and (self._p1_delay < self._p2_delay)):
			if packetDstIp(self.packet, self._serverip2, log ):
		  		if packetDstUDPPort(self.packet,5001, log):  #RTP Traffic
					SimpleL2LearningSwitch._handle_PacketIn(self, event)	
			elif packetSrcIp(self.packet, self._serverip1, log ):
				newaction = createOFAction(of.OFPAT_SET_NW_SRC, self._serverip2, log)
				actions.append(newaction)
				out_port = self.get_out_port()
				newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
				actions.append(newaction)
				match = getFullMatch(self.packet, inport)
				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        		event.connection.send(msg.pack())
			else:
				SimpleL2LearningSwitch._handle_PacketIn(self, event)
		elif ((self._p1_total_bw == self._p2_total_bw) and (self._p1_delay > self._p2_delay)):
			if packetDstIp(self.packet, self._serverip2, log ):
				if packetDstUDPPort(self.packet,5001, log):  #RTP Traffic
					self.backup_udp_route(event)
				else:
					self.backup_route(event)
			elif packetSrcIp(self.packet, self._serverip1, log ):
				newaction = createOFAction(of.OFPAT_SET_NW_SRC, self._serverip2, log)
				actions.append(newaction)
				newaction = createOFAction(of.OFPAT_SET_TP_SRC, 5001, log)
				actions.append(newaction)
				out_port = self.get_out_port()
				newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
				actions.append(newaction)
				match = getFullMatch(self.packet, inport)
				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        		event.connection.send(msg.pack())
			else:
				SimpleL2LearningSwitch._handle_PacketIn(self, event)
		elif ((self._p1_total_bw > self._p2_total_bw) and (self._p2_delay <= self._delay_threshold)):
			if packetDstIp(self.packet, self._serverip2, log ):
				if packetDstUDPPort(self.packet,5001, log):  #RTP Traffic
					self.backup_udp_route(event)
			elif packetSrcIp(self.packet, self._serverip1, log ):
				newaction = createOFAction(of.OFPAT_SET_NW_SRC, self._serverip2, log)
				actions.append(newaction)
				newaction = createOFAction(of.OFPAT_SET_TP_SRC, 5001, log)
				actions.append(newaction)
				out_port = self.get_out_port()
				newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
				actions.append(newaction)
				match = getFullMatch(self.packet, inport)
				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        		event.connection.send(msg.pack())
			else:
				SimpleL2LearningSwitch._handle_PacketIn(self, event)
		elif ((self._p1_total_bw > self._p2_total_bw) and (self._p2_delay > self._delay_threshold)):
			if packetDstIp(self.packet, self._serverip2, log ):
				if packetDstUDPPort(self.packet,5001, log):  #RTP Traffic
					SimpleL2LearningSwitch._handle_PacketIn(self, event)
				else:
					self.backup_route(event)
			else:
				SimpleL2LearningSwitch._handle_PacketIn(self, event)


	def _handle_PacketInTCP(self, event) :
		inport = event.port
        	actions = []
		if ((self._p1_total_bw == self._p2_total_bw) and (self._p1_delay == self._p2_delay)):
			if packetDstIp(self.packet, self._serverip2, log ):
				if self.FLAG == 0:
					newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip1_mac, log)
					actions.append(newaction)
					newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
					actions.append(newaction)
					self.FLAG = 1
					out_port = 3
					newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
					actions.append(newaction)
					match = getFullMatch(self.packet, inport)
	        			msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  	FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        			event.connection.send(msg.pack())
				else:
					SimpleL2LearningSwitch._handle_PacketIn(self, event)
					self.FLAG = 0
			elif packetSrcIp(self.packet, self._serverip1, log ):
				newaction = createOFAction(of.OFPAT_SET_NW_SRC, self._serverip2, log)
				actions.append(newaction)
				out_port = self.get_out_port()
				newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
				actions.append(newaction)
				match = getFullMatch(self.packet, inport)
				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        		event.connection.send(msg.pack())
			else:
				SimpleL2LearningSwitch._handle_PacketIn(self, event)			

		elif ((self._p1_total_bw == self._p2_total_bw) and (self._p1_delay < self._p2_delay)):
			if packetDstIp(self.packet, self._serverip2, log ):
		  		if packetDstTCPPort(self.packet,5001, log):  #Transient Traffic
					SimpleL2LearningSwitch._handle_PacketIn(self, event)
				elif packetDstTCPPort(self.packet,5002, log):
					self.backup_route(event)
				elif (packetDstTCPPort(self.packet,20, log) or packetDstTCPPort(self.packet,21, log)):  #FTP Traffic
					newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip1_mac, log)
					actions.append(newaction)
					newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
					actions.append(newaction)
					out_port = 3
					newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
					actions.append(newaction)
					match = getFullMatch(self.packet, inport)
					msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  	  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        			event.connection.send(msg.pack())
				elif (packetDstTCPPort(self.packet,80, log) or packetDstTCPPort(self.packet,8080, log)) :   #Web Traffic
					if self.FLAG == 0:
						newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip1_mac, log)
						actions.append(newaction)
						newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
						actions.append(newaction)
						self.FLAG = 1
						out_port = 3
						newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
						actions.append(newaction)
						match = getFullMatch(self.packet, inport)
	        				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  		  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        				event.connection.send(msg.pack())
					else:
						SimpleL2LearningSwitch._handle_PacketIn(self, event)
						self.FLAG = 0
				else:
					SimpleL2LearningSwitch._handle_PacketIn(self, event)

			elif packetSrcIp(self.packet, self._serverip1, log ):
				newaction = createOFAction(of.OFPAT_SET_NW_SRC, self._serverip2, log)
				actions.append(newaction)
				out_port = self.get_out_port()
				newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
				actions.append(newaction)
				match = getFullMatch(self.packet, inport)
				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        		event.connection.send(msg.pack())
			else:
				SimpleL2LearningSwitch._handle_PacketIn(self, event)
		elif ((self._p1_total_bw == self._p2_total_bw) and (self._p1_delay > self._p2_delay)):
			if packetDstIp(self.packet, self._serverip2, log ):
				if packetDstTCPPort(self.packet,5001, log):  #Transient Traffic
					SimpleL2LearningSwitch._handle_PacketIn(self, event)	
				elif packetDstTCPPort(self.packet,5002, log):
					self.backup_route(event)
				elif (packetDstTCPPort(self.packet,20, log) or packetDstTCPPort(self.packet,21, log)):  #FTP Traffic
					SimpleL2LearningSwitch._handle_PacketIn(self, event)
				elif (packetDstTCPPort(self.packet,80, log) or packetDstTCPPort(self.packet,8080, log)) :
					if self.FLAG == 0:
						self.backup_route(event)
						self.FLAG = 1	
					else:
						SimpleL2LearningSwitch._handle_PacketIn(self, event)
						self.FLAG = 0
				else:
					SimpleL2LearningSwitch._handle_PacketIn(self, event)
			elif packetSrcIp(self.packet, self._serverip1, log ):
				newaction = createOFAction(of.OFPAT_SET_NW_SRC, self._serverip2, log)
				actions.append(newaction)
				out_port = self.get_out_port()
				newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
				actions.append(newaction)
				match = getFullMatch(self.packet, inport)
				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        		event.connection.send(msg.pack())
			else:	
				SimpleL2LearningSwitch._handle_PacketIn(self, event)
		elif ((self._p1_total_bw > self._p2_total_bw) and (self._p2_delay <= self._delay_threshold)):
			if packetDstIp(self.packet, self._serverip2, log ):
				if packetDstTCPPort(self.packet,5001, log):  #Transient Traffic
					SimpleL2LearningSwitch._handle_PacketIn(self, event)
				elif packetDstTCPPort(self.packet,5002, log):
					self.backup_route(event)
				elif packetDstTCPPort(self.packet,20, log) or packetDstTCPPort(self.packet,21, log):  #FTP Traffic
					SimpleL2LearningSwitch._handle_PacketIn(self, event)
				elif (packetDstTCPPort(self.packet,80, log) or packetDstTCPPort(self.packet,8080, log)) :
					if self.FLAG == 0:
						self.backup_route(event)
						self.FLAG = 1	
					else:
						SimpleL2LearningSwitch._handle_PacketIn(self, event)
						self.FLAG = 0
				else:
					SimpleL2LearningSwitch._handle_PacketIn(self, event)
			elif packetSrcIp(self.packet, self._serverip1, log ):
				newaction = createOFAction(of.OFPAT_SET_NW_SRC, self._serverip2, log)
				actions.append(newaction)
				out_port = self.get_out_port()
				newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
				actions.append(newaction)
				match = getFullMatch(self.packet, inport)
				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        		event.connection.send(msg.pack())
			else:
				SimpleL2LearningSwitch._handle_PacketIn(self, event)

		elif ((self._p1_total_bw > self._p2_total_bw) and (self._p2_delay > self._delay_threshold)):
			if packetDstIp(self.packet, self._serverip2, log ):
				if (packetDstTCPPort(self.packet,20, log) or packetDstTCPPort(self.packet,21, log) or packetDstTCPPort(self.packet,80, log) or packetDstTCPPort(self.packet,8080, log)):
					SimpleL2LearningSwitch._handle_PacketIn(self, event)
				else:
					self.backup_route(event)	
			elif packetSrcIp(self.packet, self._serverip1, log ):
				newaction = createOFAction(of.OFPAT_SET_NW_SRC, self._serverip2, log)
				actions.append(newaction)
				out_port = self.get_out_port()
				newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
				actions.append(newaction)
				match = getFullMatch(self.packet, inport)
				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        		event.connection.send(msg.pack())	
			else:
				SimpleL2LearningSwitch._handle_PacketIn(self, event)			
		else:
			SimpleL2LearningSwitch._handle_PacketIn(self, event)
			
	def backup_route(self,event):	#Diverts traffic to the backup path
		inport = event.port
        	actions = []
		newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip1_mac, log)
		actions.append(newaction)
		newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
		actions.append(newaction)
		out_port = 3
		newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
		actions.append(newaction)
		match = getFullMatch(self.packet, inport)
		msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        event.connection.send(msg.pack())	

	def backup_udp_route(self,event):	#Diverts UDP traffic to backup path
		inport = event.port
        	actions = []
		newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip1_mac, log)
		actions.append(newaction)
		newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
		actions.append(newaction)
		newaction = createOFAction(of.OFPAT_SET_TP_DST, 5004, log)
		actions.append(newaction)
		out_port = 3
		newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
		actions.append(newaction)
		match = getFullMatch(self.packet, inport)
		msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        event.connection.send(msg.pack())	
		
class Pfr(object):
    def __init__(self, config):
        core.openflow.addListeners(self)
	self._config=config 
    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection,))
        PfrSwitch(event.connection, self._config)
	


def launch(config_file=os.path.join(SCRIPT_PATH, "pfr.config")):
	log.debug("Performance Routing " + config_file);
	config = readConfigFile(config_file, log)
    	core.registerNew(Pfr,config["general"])
