#!/usr/bin/env python3

from math import log
from itertools import cycle
from ipaddress import ip_network, ip_address, IPv4Address
import asyncio
import struct
import socket, IN
import time
import io

import messages
from protocol import DDHCPProtocol
from ddhcp import DDHCP
import dhcp
import dhcpoptions

# Erstmal nur Blöcke verwalten. Testcase: alle paar Sekunden einen Block belegen und manchmal einen anderen freigeben
# TODO dhcp options: subnet mask before router! (RFC 1533)
# TODO Konfliktauflösug
# TODO Übergang von DISPUTE zu OURS oder CLAIMED
# TODO DHCP für Clients
# TODO normalize case of functions
# TODO block_index may be outside permittable range
# TODO Split large packets automatically?
# TODO Python unit tests? zwei instanzen, die einen Konflikt haben?

MYPORT = 1234
MYGROUP = 'ff02::1234'
MYINTERFACE = 'veth1'
MYCLIENTIF = 'client0'
MYCLIENTIP = '10.0.0.1'

config = { "prefix": ip_network("10.0.0.0/27"),
           "prefixlen": 24,
           "blocksize": 4,
           "blocked": list(range(0, 1)),
           #"blocked": list(range(0, 64)),
           "gateway": ip_address("10.0.0.1"),
           "dns": [ip_address("10.130.0.255"), ip_address("10.130.0.254")],
           "domain": "ffhl",
           "blocktimeout": 30,
           "tentativetimeout": 15
         }

class DHCPProtocol:
    def __init__(self, ddhcp, config):
        self.config = config
        self.ddhcp = ddhcp

    def connection_made(self, transport):
        self.transport = transport
        print("Connection made")

    def datagram_received(self, data, addr):
        # TODO verify packet somehow
        msg = dhcp.DHCPPacket()
        msg.deserialize(io.BytesIO(data))

        print(addr, msg)

        msgtype = next(filter(lambda o: o.__class__ == dhcpoptions.DHCPMessageType, msg.options)).type

        msg.op = msg.BOOTREPLY
        msg.options = []
        msg.siaddr = IPv4Address("10.0.0.1")

        if msgtype == dhcpoptions.DHCPMessageType.TYPES.DHCPDISCOVER:
            msg.yiaddr = IPv4Address("10.0.0.2")
            msg.options.append(dhcpoptions.DHCPMessageType(dhcpoptions.DHCPMessageType.TYPES.DHCPOFFER))
            msg.options.append(dhcpoptions.IPAddressLeaseTime(30))

            self.transport.sendto(msg.serialize(), ("<broadcast>", 68))
        elif msgtype == dhcpoptions.DHCPMessageType.TYPES.DHCPREQUEST:
            msg.yiaddr = IPv4Address("10.0.0.2")
            msg.options.append(dhcpoptions.DHCPMessageType(dhcpoptions.DHCPMessageType.TYPES.DHCPACK))
            msg.options.append(dhcpoptions.IPAddressLeaseTime(30))

            self.transport.sendto(msg.serialize(), ("<broadcast>", 68))

# freie IP suchen, als reserviert markieren
# offer senden
# bei request nachschauen und ack senden
# leasetime vom client kann kürzer als die angebotene sein!
# ParameterRequestList beachten!
# ansonsten nak
# dhcprelease auch noch handhaben




def main():
    ddhcp = DDHCP(config)
    loop = asyncio.get_event_loop()


    # DHCP Socket

    def dhcp_factory():
        return DHCPProtocol(ddhcp, config)

    listen = loop.create_datagram_endpoint(dhcp_factory, family=socket.AF_INET, local_addr=("0.0.0.0", 67))
    transport, protocol = loop.run_until_complete(listen)

    sock = transport.get_extra_info("socket")

    sock.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, bytes(MYCLIENTIF + '\0', "UTF-8"))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)


    # DDHCP Socket

    def ddhcp_factory():
        return DDHCPProtocol(loop, (MYGROUP, MYPORT), ddhcp, config)

    listen = loop.create_datagram_endpoint(ddhcp_factory, family=socket.AF_INET6, local_addr=('::', MYPORT))
    transport, protocol = loop.run_until_complete(listen)

    sock = transport.get_extra_info("socket")

    ifn = socket.if_nametoindex(MYINTERFACE)
    ifn = struct.pack("I", ifn)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifn)

    # Join group
    group_bin = socket.inet_pton(socket.AF_INET6, MYGROUP)
    mreq = group_bin + ifn
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

    # Do not loopback multicast packets
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    transport.close()
    loop.close()


if __name__ == '__main__':
    main()
