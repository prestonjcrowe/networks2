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
    
    # Creates a new entry in the flow table that matches ARP traffic
    msg = of.ofp_flow_mod() 
    msg.match.dl_type = 0x0806

    # Create a new action that floods matching packets to all ports except
    # the port on which the packet was recieved
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    connection.send(msg)
    
    # Creates a new entry in the flow table that matches IP traffic
    # (need to be a bit more specific here to filter on ICMP)
    msg = of.ofp_flow_mod() 
    msg.match.dl_type = 0x0800

    # Create a new action that floods matching packets to all ports except
    # the port on which the packet was recieved
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    connection.send(msg)
   
  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """
    packet = event.parsed
    packet_in = event.ofp # The actual ofp_packet_in message.
    print("Dropping packet {}".format(packet))

    
def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
