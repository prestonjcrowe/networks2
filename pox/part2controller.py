# Part 2 of UWCSE's Project 3
#
# based on Lab 4 from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    #add switch rules here
   
  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed
    print("Recieved packet {} -> {}".format(packet.src, packet.dst))
    # ARP  -> packet.type == 0x806

    # Create flow that simply broadcasts any packet received
    # The first time this is called, the router rules are set up.
    # This method is not called for subsequent packets - the 
    # router rules should forward them

    msg = of.ofp_flow_mod() 
    msg.idle_timeout = 10
    msg.hard_timeout = 15

    #msg.match.dl_type = 0x0806
    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
    self.connection.send(msg)

    packet_in = event.ofp # The actual ofp_packet_in message.
    
def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
