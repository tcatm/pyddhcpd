#!/usr/bin/env python3

from math import log
from itertools import cycle
from ipaddress import IPv4Address
import asyncio
import binascii
import struct
import socket, IN
import time
import io

import messages
from protocol import DDHCPProtocol
from ddhcp import DDHCP
import dhcp
import dhcpoptions

from config import config

# TODO brauchen wir TENTATIVE überhaupt?
# TODO Konfliktauflösug
# TODO REQUEST forwarding
# TODO block_index may be outside permittable range
# TODO Split large packets automatically?


class Lease:
    def __init__(self):
        self.addr = IPv4Address("0.0.0.0")
        self.leasetime = 0
        self.valid_until = 0
        self.chaddr = b""
        self.routers = []
        self.dns = []

    def renew(self, now):
        self.valid_until = now + 2 * self.leasetime

    def isValid(self, now):
        return self.valid_until > now

    def __repr__(self):
        return "Lease(addr=%s, chaddr=%s, valid_until=%i)" % (self.addr, binascii.hexlify(self.chaddr).decode("UTF-8"), self.valid_until)


class DHCPProtocol:
    def __init__(self, ddhcp, config):
        self.config = config
        self.ddhcp = ddhcp

    def connection_made(self, transport):
        self.transport = transport
        print("Connection made")

    def datagram_received(self, data, addr):
        # TODO verify packet somehow
        req = dhcp.DHCPPacket()
        req.deserialize(io.BytesIO(data))

        if req.op != req.BOOTREQUEST:
            return

        reqtype = next(filter(lambda o: o.__class__ == dhcpoptions.DHCPMessageType, req.options)).type

        msg = dhcp.DHCPPacket()
        msg.xid = req.xid
        msg.flags = req.flags
        msg.giaddr = req.giaddr
        msg.op = msg.BOOTREPLY
        msg.chaddr = req.chaddr
        msg.htype = 1

        now = time.time()

        if reqtype == dhcpoptions.DHCPMessageType.TYPES.DHCPDISCOVER:
            msg.options.append(dhcpoptions.DHCPMessageType(dhcpoptions.DHCPMessageType.TYPES.DHCPOFFER))

            blocks = self.ddhcp.our_blocks()
            for block in blocks:
                block.purge_leases(now)

            blocks = filter(lambda b: b.hosts() - set(b.leases.keys()), blocks)

            # TODO den "besten" Block, nicht irgendeinen nehmen (Fragmentierung vermeiden)

            block = next(blocks)

            addrs = block.hosts() - set(block.leases.keys())

            lease = Lease()
            lease.addr = addrs.pop()
            lease.leasetime = self.config["leasetime"]
            lease.renew(now)
            lease.chaddr = req.chaddr
            lease.routers = self.config["routers"]
            lease.dns = self.config["dns"]

            block.leases[lease.addr] = lease

            msg.yiaddr = lease.addr
            msg.options.append(dhcpoptions.IPAddressLeaseTime(lease.leasetime))

        elif reqtype == dhcpoptions.DHCPMessageType.TYPES.DHCPREQUEST:
            try:
                reqip = next(filter(lambda o: o.__class__ == dhcpoptions.RequestedIPAddress, req.options)).addr
            except StopIteration:
                reqip = req.ciaddr

            try:
                block = self.ddhcp.block_from_ip(reqip)
                block.purge_leases(now)

                print(block)

                lease = block.leases[reqip]

                if lease.chaddr != req.chaddr:
                    raise KeyError("MAC address does not match lease")

                lease.renew(now)

                msg.options.append(dhcpoptions.DHCPMessageType(dhcpoptions.DHCPMessageType.TYPES.DHCPACK))
                msg.yiaddr = lease.addr
                msg.options.append(dhcpoptions.IPAddressLeaseTime(lease.leasetime))
                msg.options.append(dhcpoptions.SubnetMask(self.config["prefixlen"]))
                msg.options.append(dhcpoptions.RouterOption(lease.routers))
                msg.options.append(dhcpoptions.DomainNameServerOption(lease.dns))

            except KeyError:
                msg.options.append(dhcpoptions.DHCPMessageType(dhcpoptions.DHCPMessageType.TYPES.DHCPNAK))

        else:
            return

        print(msg)

        if addr[0] == '0.0.0.0' or msg.flags & 1:
            self.transport.sendto(msg.serialize(), ("<broadcast>", 68))
        else:
            self.transport.sendto(msg.serialize(), addr)


def main():
    ddhcp = DDHCP(config)
    loop = asyncio.get_event_loop()


    # DHCP Socket

    def dhcp_factory():
        return DHCPProtocol(ddhcp, config)

    listen = loop.create_datagram_endpoint(dhcp_factory, family=socket.AF_INET, local_addr=("0.0.0.0", 67))
    transport, protocol = loop.run_until_complete(listen)

    sock = transport.get_extra_info("socket")

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

    transport.close()
    loop.close()


if __name__ == '__main__':
    main()
