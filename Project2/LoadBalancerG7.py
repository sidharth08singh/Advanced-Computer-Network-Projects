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
from pox.lib.addresses import IPAddr, EthAddr
import urllib2

log = core.getLogger() # Use central logging service

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))

FLOW_HARD_TIMEOUT = 30
FLOW_IDLE_TIMEOUT = 10


class LoadBalancerSwitch(SimpleL2LearningSwitch):
	def __init__(self, connection, config):
		SimpleL2LearningSwitch.__init__(self, connection, False)
        	self._connection = connection;
		self._serverip1 = config['server_ip1']
		self._serverip2 = config['server_ip2']   #This will be the LoadBalancer IP
		self._serverip1_mac = config['server_ip1_mac']
		self._serverip2_mac = config['server_ip2_mac']
		self._ts1_total_bw = float(config['ts1_total_bw']) * 1024 * 1024
		self._ts2_total_bw = float(config['ts2_total_bw']) * 1024 * 1024
		self.FLAG = 0
		self.Weight = 0.2
		self.lock1 = threading.Lock() 
		self.lock2 = threading.Lock()
		self.total_ts1_bytes = 0
		self.total_ts1_queue = 0
		self.total_ts2_bytes = 0
		self.total_ts2_queue = 0
		self.thread_flag = 1
		self.threshold = 0.50 
		self.ts1_path_counter = 0  #These two values are purely for experimental purposes
		self.ts2_path_counter = 0
		self.ts1_bw_threshold_more_available_bw = 0 
		self.ts2_bw_threshold_more_available_bw = 0 
		self.ts1_bw_threshold_equal_bw_lower_q = 0 
		self.ts2_bw_threshold_equal_bw_lower_q = 0 
		self.ts1_q_threshold_lower_q = 0 
		self.ts2_q_threshold_lower_q = 0 
		self.ts1_q_threshold_equal_more_available_bw = 0 
		self.ts2_q_threshold_equal_more_available_bw = 0 
		self.ts1_roundrobin = 0 
		self.ts2_roundrobin = 0 
	 

	def _handle_PacketIn(self, event):
	        #log.debug("Got a packet : " + str(event.parsed))
	        self.packet = event.parsed
	        self.event = event
	        self.macLearningHandle()
		if self.thread_flag == 1:
			thr1 = threading.Thread(target = self.TS1_info)
			thr2 = threading.Thread(target = self.TS2_info)
			thr1.start()
			thr2.start()
			self.thread_flag = 0
	        if packetIsTCP(self.packet, log) :
		          self._handle_PacketInTCP(event)
		          return
	        SimpleL2LearningSwitch._handle_PacketIn(self, event)
	
	def _handle_PacketInTCP(self, event) :
		inport = event.port
        	actions = []
        	if packetDstIp(self.packet, self._serverip2, log ):
		  if packetDstTCPPort(self.packet,5001, log):
			self.lock1.acquire()
			try:
				temp_ts1_bw = self.total_ts1_bytes * 8 #to convert bytes into bits
				temp_ts1_queue = self.total_ts1_queue
			finally:
				self.lock1.release()
			self.lock2.acquire()
			try:
				temp_ts2_bw = self.total_ts2_bytes * 8
				temp_ts2_queue = self.total_ts2_queue
			finally:
				self.lock2.release()
			log.info("TS1 Bandwidth Utilization  %.4f" % temp_ts1_bw + "  TS1 Queue %.4f " % temp_ts1_queue)
			log.info("TS2 Bandwidth Utilization  %.4f" % temp_ts2_bw + "  TS2 Queue %.4f " % temp_ts2_queue)
			if (self.threshold <= (temp_ts1_bw / self._ts1_total_bw)) or (self.threshold <= (temp_ts2_bw / self._ts2_total_bw)):
				if (self._ts2_total_bw - temp_ts2_bw) > (self._ts1_total_bw - temp_ts1_bw):
					#TS2 path is less loaded and hence flow is routed that path
					log.info("Path Selected: TS2, Reason: More Bandwidth Available on TS2")
					self.ts2_path_counter = self.ts2_path_counter + 1
					self.ts2_bw_threshold_more_available_bw = self.ts2_bw_threshold_more_available_bw + 1
					newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip1_mac, log)
					actions.append(newaction)
					newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
					log.debug("MAC %s IP %s"%(self._serverip1_mac,self._serverip1))
					actions.append(newaction)
					out_port = 3
					newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
					actions.append(newaction)
					match = getFullMatch(self.packet, inport)
	        			msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  	  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        			event.connection.send(msg.pack())
				elif (self._ts2_total_bw - temp_ts2_bw) == (self._ts1_total_bw - temp_ts1_bw) :
					if temp_ts2_queue < temp_ts1_queue:
						#if both links are equally utilized, choose path whose queue is smaller
						log.info("Path Selected: TS2, Reason: Equal Bandwidth Available on TS1 and TS2, Smaller Queue Size on TS2")
						self.ts2_path_counter = self.ts2_path_counter + 1
						self.ts2_bw_threshold_equal_bw_lower_q = self.ts2_bw_threshold_equal_bw_lower_q + 1
						newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip1_mac, log)
						actions.append(newaction)
						newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
						log.debug("MAC %s IP %s"%(self._serverip1_mac,self._serverip1))
						actions.append(newaction)
						out_port = 3
						newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
						actions.append(newaction)
						match = getFullMatch(self.packet, inport)
	        				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  	  	  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        				event.connection.send(msg.pack())
					else:
						log.info("Path Selected: TS1, Reason: Equal Bandwidth Available on TS1 and TS2, Smaller Queue Size on TS1")
						self.ts1_path_counter = self.ts1_path_counter + 1
						self.ts1_bw_threshold_equal_bw_lower_q = self.ts1_bw_threshold_equal_bw_lower_q + 1 
						SimpleL2LearningSwitch._handle_PacketIn(self, event) #Go Through TS1 path
				else:
					log.info("Path Selected: TS1, Reason: More Bandwidth Available on TS1")
					self.ts1_path_counter = self.ts1_path_counter + 1
					self.ts1_bw_threshold_more_available_bw = self.ts1_bw_threshold_more_available_bw + 1
					SimpleL2LearningSwitch._handle_PacketIn(self, event)   # Go through TS1	path
			elif (self.threshold < (temp_ts1_queue / 10.0)) or (self.threshold < (temp_ts2_queue / 10.0)):
				#Queue Depth is of 10 Packets. Checks if any Queue Depth is over 50%
				if temp_ts2_queue < temp_ts1_queue:
						log.info("Path Selected: TS2, Reason: Bandwidth below Threshold on TS1 and TS2,  Smaller Queue Size on TS2")
						self.ts2_path_counter = self.ts2_path_counter + 1
						self.ts2_q_threshold_lower_q = self.ts2_q_threshold_lower_q + 1 
						newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip1_mac, log)
						actions.append(newaction)
						newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
						log.debug("MAC %s IP %s"%(self._serverip1_mac,self._serverip1))
						actions.append(newaction)
						out_port = 3
						newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
						actions.append(newaction)
						match = getFullMatch(self.packet, inport)
	        				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  	  	  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        				event.connection.send(msg.pack())
				elif temp_ts2_queue == temp_ts1_queue:
					if (self._ts2_total_bw - temp_ts2_bw) > (self._ts1_total_bw - temp_ts1_bw):
						log.info("Path Selected: TS2, Reason: Bandwidth below Threshold on TS1 and TS2, Queue Sizes equal on TS1 and TS2, More Bandwidth available on TS2")
						self.ts2_path_counter = self.ts2_path_counter + 1
						self.ts2_q_threshold_equal_more_available_bw = self.ts2_q_threshold_equal_more_available_bw
						newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip1_mac, log)
						actions.append(newaction)
						newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
						log.debug("MAC %s IP %s"%(self._serverip1_mac,self._serverip1))
						actions.append(newaction)
						out_port = 3
						newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
						actions.append(newaction)
						match = getFullMatch(self.packet, inport)
	        				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, 
                                  	  	  FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        				event.connection.send(msg.pack())
					else:
						log.info("Path Selected: TS1, Reason: Bandwidth below Threshold on TS1 and TS2, Queue Sizes equal on TS1 and TS2, More Bandwidth available on TS1")
						self.ts1_path_counter = self.ts1_path_counter + 1
						self.ts1_q_threshold_equal_more_available_bw = self.ts1_q_threshold_equal_more_available_bw
						SimpleL2LearningSwitch._handle_PacketIn(self, event)
				else:
					log.info("Path Selected: TS1, Reason: Bandwidth below Threshold on TS1 and TS2, Smaller Queue Size on TS2")
					self.ts1_path_counter = self.ts1_path_counter + 1
					self.ts1_q_threshold_lower_q = self.ts1_q_threshold_lower_q + 1
					SimpleL2LearningSwitch._handle_PacketIn(self, event)
			elif self.FLAG == 0:
				log.debug("Packet is TCP destined to %s:" % (self._serverip2))
				log.info("Path Selected: TS2, Reason: Round Robin")
				self.ts2_path_counter = self.ts2_path_counter + 1
				self.ts2_roundrobin = self.ts2_roundrobin + 1
				newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip1_mac, log)
				actions.append(newaction)
				newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
				log.debug("MAC %s IP %s"%(self._serverip1_mac,self._serverip1))
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
				log.info("Path Selected: TS1, Reason: Round Robin")
				self.ts1_path_counter = self.ts1_path_counter + 1
				self.ts1_roundrobin = self.ts1_roundrobin + 1 
				SimpleL2LearningSwitch._handle_PacketIn(self, event)
				self.FLAG = 0
				
		  log.info(" ts1_total_loadbalanced : %d " % self.ts1_path_counter)
		  log.info(" TS2 total_loadbalanced : %d " % self.ts2_path_counter)
		  log.info(" ts1_bw_threshold_more_available_bw : %d" % self.ts1_bw_threshold_more_available_bw)
		  log.info(" ts2_bw_threshold_more_available_bw : %d" % self.ts2_bw_threshold_more_available_bw) 
		  log.info(" ts1_bw_threshold_equal_bw_lower_q : %d" % self.ts1_bw_threshold_equal_bw_lower_q) 
	          log.info(" ts2_bw_threshold_equal_bw_lower_q : %d" % self.ts2_bw_threshold_equal_bw_lower_q) 
		  log.info(" ts1_q_threshold_lower_q : %d" % self.ts1_q_threshold_lower_q) 
		  log.info(" ts2_q_threshold_lower_q : %d" % self.ts2_q_threshold_lower_q) 
		  log.info(" ts1_q_threshold_equal_more_available_bw : %d" % self.ts1_q_threshold_equal_more_available_bw) 
		  log.info(" ts2_q_threshold_equal_more_available_bw : %d" % self.ts2_q_threshold_equal_more_available_bw) 
		  log.info(" ts1_roundrobin : %d" % self.ts1_roundrobin)
		  log.info(" ts2_roundrobin : %d" % self.ts2_roundrobin) 
			
		elif packetSrcIp(self.packet, self._serverip1, log ):
			log.debug("Packet is sourced by TCP at %s:" % (self._serverip1))
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
		
			
	def TS1_info(self):
		index = 0
		while 1:
			temp = urllib2.urlopen("http://10.0.0.3:8000/qinfo/" + str(index)).read()
			temp_list = temp.split('\n')
			for t in temp_list[:-1]:
				timestamp , bytes , qdepth = t.split(' ')
				self.lock1.acquire()
				try:
					if timestamp <= index:
						continue
					elif index == 0:
						self.total_ts1_bytes = int(bytes)
						self.total_ts1_queue = int(qdepth)
					else:
						self.total_ts1_bytes = int(bytes) * self.Weight + (self.total_ts1_bytes * (1 - self.Weight))
						self.total_ts1_queue = int(qdepth) * self.Weight + self.total_ts1_queue * (1 -self.Weight)		
				finally:
					self.lock1.release()
				index = timestamp
			time.sleep(5)
	def TS2_info(self):
		index = 0
		while 1:
			temp = urllib2.urlopen("http://10.0.0.4:8000/qinfo/" + str(index)).read()
			temp_list = temp.split('\n')
			for t in temp_list[:-1]:
				timestamp , bytes , qdepth = t.split(' ')
				self.lock2.acquire()
				try:
					if timestamp <= index:
						continue
					elif index == 0:
						self.total_ts2_bytes = int(bytes)
						self.total_ts2_queue = int(qdepth)
					else:
						self.total_ts2_bytes = int(bytes) * self.Weight + self.total_ts2_bytes * (1 - self.Weight)
						self.total_ts2_queue = int(qdepth) * self.Weight + self.total_ts2_queue * (1 -self.Weight)		
				finally:
					self.lock2.release()
				index = timestamp
			time.sleep(5)
class LoadBalancer(object):
    def __init__(self, config):
        core.openflow.addListeners(self)
	self._config=config 
    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection,))
        LoadBalancerSwitch(event.connection, self._config)
	


def launch(config_file=os.path.join(SCRIPT_PATH, "load.config")):
	log.debug("LoadBalancing " + config_file);
	config = readConfigFile(config_file, log)
    	core.registerNew(LoadBalancer,config["general"])
