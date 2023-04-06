Name: Mirza Ana-Maria
Group: 321CA


### Homework 1 - Dataplane Router -

For the implementation of this router, first I checked that the packet
received had either an ipv4 or arp protocol. Also, if the packet was not
destined for the router, the packet was ignored.

## Ipv4 Packet
First, if ipv4 packet was destined for the router, an icmp reply will be sent
by the router. Next, the router checks the checksum to be correct, if not, the
packet is ignored. The ttl is also checked and decremented, if over 1. If ttl
was 1 or 0, the router sends an icmp "Time exceeded" packet and drops the ipv4
packet.

Next, the best route is searched in the routing table for the destination ip.
The next hop is determined using binary search. If no route was found in the
table, the router send an icmp "Destination unreacheable" packet back to the
source of the packet. If next hop was found, the checksum is set and the mac
address of next hop is taken from the arp table if found. If not, an arp request
is sent to next hop and the packet is placed in a queue until the arp reply with
the next hop mac arrives and the ipv4 packet can be sent.

## ARP Packet
For an ARP packet, the router checks the type: request of reply and bases its
action based on it.

If the ARP packet is a reply, the new mac is added to the arp table with its
corresponding ip address and the packet waiting for it is sent on its way.

If the router received a request ARP packet and the destination is the router,
the router send an ARP reply with its mac address.
