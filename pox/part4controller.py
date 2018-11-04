# Part 4 of UWCSE's Project 3
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

class Part4Controller (object):
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
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    self.connection.send(msg)

  # Set switches s1, s2, s3, cores21 to broadcast all packets
  def s1_setup(self):
      self.flood()

  def s2_setup(self):
      self.flood()

  def s3_setup(self):
      self.flood()

  def cores21_setup(self):
      # drop all IP communication from hnotrust to serv1
      msg = of.ofp_flow_mod()
      msg.priority = 1
      msg.match.dl_type = 0x800
      msg.match.nw_src = IPS["hnotrust"][0]
      msg.match.nw_dst = IPS["serv1"][0]
      self.connection.send(msg)

      # drop all ICMP from hnotrust
      msg = of.ofp_flow_mod()
      msg.priority = 1
      msg.match.dl_type = 0x800
      msg.match.nw_proto = 1
      msg.match.nw_src = IPS["hnotrust"][0]
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

    # arbitrary
    our_mac = EthAddr('00:00:00:00:00:07')

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    if packet.type == 0x806:  # ARP
        a = packet.payload

        # install flow based on ARP: for all IP packets addressed
        # to a.protosrc (whoever sent the ARP), change the ethernet
        # header to theirs (a.hwsrc) and send it out on event.port
        # (where we recieved this ARP from)
        msg = of.ofp_flow_mod()
        msg.priority = 0
        msg.match.dl_type = 0x800  # IPv4
        msg.match.nw_dst = a.protosrc
        msg.actions.append(of.ofp_action_dl_addr.set_dst(a.hwsrc))
        msg.actions.append(of.ofp_action_output(port=event.port))
        self.connection.send(msg)

        # respond to the ARP with our MAC address so that we can handle
        # their IP traffic in the future
        a.opcode = 2 # REPLY
        tmp = a.protodst
        a.protodst = a.protosrc
        a.protosrc = tmp
        a.hwdst = a.hwsrc
        a.hwsrc = our_mac
        packet.dst = packet.src
        packet.src = our_mac
        self.resend_packet(packet, event.port)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Part4Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
