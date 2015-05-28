#!/usr/bin/env python3

from math import log
from itertools import cycle
from ipaddress import ip_network, ip_address
import asyncio
import struct
import socket
import time

import messages
from protocol import DDHCPProtocol
from ddhcp import DDHCP

# Erstmal nur Blöcke verwalten. Testcase: alle paar Sekunden einen Block belegen und manchmal einen anderen freigeben
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

config = { "prefix": ip_network("10.130.0.0/27"),
           "blocksize": 4,
           "blocked": list(range(0, 1)),
           #"blocked": list(range(0, 64)),
           "gateway": ip_address("10.130.0.255"),
           "dns": [ip_address("10.130.0.255"), ip_address("10.130.0.254")],
           "domain": "ffhl",
           "blocktimeout": 30,
           "tentativetimeout": 15
         }


def main():
    ddhcp = DDHCP(config)
    loop = asyncio.get_event_loop()

    def ddhcp_factory():
        return DDHCPProtocol(loop, (MYGROUP, MYPORT), ddhcp, config)

    listen = loop.create_datagram_endpoint(ddhcp_factory, family=socket.AF_INET6, local_addr=('::', MYPORT))
    transport, protocol = loop.run_until_complete(listen)

    sock = transport.get_extra_info("socket")

    # TODO bind to link local

    ifn = socket.if_nametoindex(MYINTERFACE)
    ifn = struct.pack("I", ifn)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifn)

    # Join group
    group_bin = socket.inet_pton(socket.AF_INET6, MYGROUP)
    mreq = group_bin + ifn
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

    # Do not loopback multicast packets
    #sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    transport.close()
    loop.close()


if __name__ == '__main__':
    main()
