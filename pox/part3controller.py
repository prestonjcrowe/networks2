# Part 3 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

log = core.getLogger()

#statically allocate a routing table for hosts
#MACs used in only in part 4
IPS = {
  "h10" : ("10.0.1.10", '00:00:00:00:00:01'),
  "h20" : ("10.0.2.20", '00:00:00:00:00:02'),
  "h30" : ("10.0.3.30", '00:00:00:00:00:03'),
  "serv1" : ("10.0.4.10", '00:00:00:00:00:04'),
  "hnotrust" : ("172.16.10.100", '00:00:00:00:00:05'),
}

class Part3Controller (object):
  """
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    print (connection.dpid)
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
    #use the dpid to figure out what switch is being created
    if (connection.dpid == 1):
      self.s1_setup()
    elif (connection.dpid == 2):
      self.s2_setup()
    elif (connection.dpid == 3):
      self.s3_setup()
    elif (connection.dpid == 21):
      self.cores21_setup()
    elif (connection.dpid == 31):
      self.dcs31_setup()
    else:
      print ("UNKNOWN SWITCH")
      exit(1)


  def flood(self):
    msg = of.ofp_flow_mod()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(msg)

  def ip_to_port(self, ip, port):
    msg = of.ofp_flow_mod()
    msg.priority = 0
    msg.match.dl_type = 0x0800 #IPv4
    msg.match.nw_dst = ip
    msg.actions.append(of.ofp_action_output(port=port))
    self.connection.send(msg)

  # Set switches s1, s2, s3, cores21 to broadcast all packets
  def s1_setup(self):
      self.flood()

  def s2_setup(self):
      self.flood()

  def s3_setup(self):
      self.flood()

  # Here we need to parse out src / dst IP and route accordingly
  def cores21_setup(self):
      ips_to_ports = {
        "10.0.1.10" : 1,
        "10.0.2.20" : 2,
        "10.0.3.30" : 3,
        "10.0.4.40" : 4,
        "172.16.10.100" : 5, 
      }

      # Block ICMP from hnotrust with high priority
      msg = of.ofp_flow_mod()
      msg.priority = 1
      msg.match.dl_type = 0x0800 #IPv4
      msg.match.nw_proto = 1     #ICMP
      msg.match.in_port = ips_to_ports[IPS["hnotrust"][0]]
      msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
      self.connection.send(msg)

      # Block IPv4 from hnotrust to serv1 with high priority
      msg = of.ofp_flow_mod()
      msg.priority = 1
      msg.match.dl_type = 0x0800 #IPv4
      msg.match.nw_src = IPS["hnotrust"][0]
      msg.match.nw_dst = IPS["serv1"][0]
      msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
      self.connection.send(msg)
      
      # Pass all other IP traffic to correct port
      for ip in ips_to_ports:
          self.ip_to_port(ip, ips_to_ports[ip])

      # Flood remainder
      msg = of.ofp_flow_mod()
      msg.priority = 0
      msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      self.connection.send(msg)


  def dcs31_setup(self):
      self.flood()

  #used in part 4 to handle individual ARP packets
  #not needed for part 3 (USE RULES!)
  #causes the switch to output packet_in on out_port
  def resend_packet(self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)
    self.connection.send(msg)

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp
    print ("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Part3Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
