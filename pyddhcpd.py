#!/usr/bin/env python3

import asyncio
import struct
import socket, IN
import logging
import fcntl

from protocol import DDHCPProtocol
from dhcpprotocol import DHCPProtocol
from ddhcp import DDHCP

from config import config


def main():
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%m-%d %H:%M')

    logging.info("START")

    ddhcp = DDHCP(config)
    loop = asyncio.get_event_loop()


    # DHCP Socket

    def dhcp_factory():
        # waw socket for sending unicast replies
        rawsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        rawsock.bind((config["clientif"], 0))

        servermac = fcntl.ioctl(rawsock.fileno(), 0x8927, struct.pack('256s', bytes(config["clientif"], "UTF-8")[:15]))[18:24]

        return DHCPProtocol(loop, ddhcp, rawsock, servermac)

    dhcplisten = loop.create_datagram_endpoint(dhcp_factory, family=socket.AF_INET, local_addr=("0.0.0.0", 67))
    dhcptransport, dhcpprotocol = loop.run_until_complete(dhcplisten)

    sock = dhcptransport.get_extra_info("socket")

    sock.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, bytes(config["clientif"] + '\0', "UTF-8"))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)


    # DDHCP Socket

    def ddhcp_factory():
        return DDHCPProtocol(loop, (config["mcgroup"], config["mcport"]), ddhcp, config)

    listen = loop.create_datagram_endpoint(ddhcp_factory, family=socket.AF_INET6, local_addr=('::', config["mcport"]))
    transport, protocol = loop.run_until_complete(listen)

    sock = transport.get_extra_info("socket")

    ifn = socket.if_nametoindex(config["mcif"])
    ifn = struct.pack("I", ifn)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifn)

    # Join group
    group_bin = socket.inet_pton(socket.AF_INET6, config["mcgroup"])
    mreq = group_bin + ifn
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

    # Do not loopback multicast packets
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    dhcptransport.close()
    transport.close()
    loop.close()


if __name__ == '__main__':
    main()
