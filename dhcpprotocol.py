import asyncio
import io
import time
import dhcp
import dhcpoptions
import logging
import struct
from lease import Lease
from ipaddress import IPv4Address

def mkEthernetPacket(dst, src, type, payload):
    r = struct.pack("!6s6sH", dst, src, type)
    r += payload

    return r


def mkIPv4Packet(dst, src, protocol, payload):
    def mkHeader(checksum):
        r = bytes()
        r += struct.pack("!BB", 4 * 16 + 5, 0) # IPv4 + IHL 5, DSCP / ECN
        r += struct.pack("!H", 20 + len(payload))
        r += struct.pack("!HH", 0, 0) # Identification, Flags and Fragmentation
        r += struct.pack("!B", 255) # TTL
        r += struct.pack("!BH", protocol, checksum)
        r += src.packed
        r += dst.packed

        return r

    def mkChecksum(header):
        s = sum(struct.unpack("!10H", header))

        return 0xffff ^ ((s & 0xffff) + (s >> 16))

    r = mkHeader(mkChecksum(mkHeader(0)))
    r += payload

    return r


def mkUDPPacket(dst, src, payload):
    r = struct.pack("!4H", src, dst, len(payload), 0)
    r += payload

    return r


class DHCPProtocol:
    def __init__(self, loop, ddhcp, rawsock, servermac):
        self.loop = loop
        self.ddhcp = ddhcp
        self.rawsock = rawsock
        self.servermac = servermac

    def connection_made(self, transport):
        self.transport = transport

    def sendmsg(self, msg):
        broadcast = msg.flags & 1 or msg.yiaddr == IPv4Address("0.0.0.0")

        if broadcast:
            self.transport.sendto(msg.serialize(), ("<broadcast>", 68))
        else:
            udpPacket = mkUDPPacket(68, 67, msg.serialize())
            ipPacket = mkIPv4Packet(msg.yiaddr, self.ddhcp.config["siaddr"], 17, udpPacket)
            ethPacket = mkEthernetPacket(msg.chaddr, self.servermac, 0x0800, ipPacket)

            self.rawsock.send(ethPacket)


    def datagram_received(self, data, addr):
        # TODO verify packet somehow
        req = dhcp.DHCPPacket()
        req.deserialize(io.BytesIO(data))

        if req.op != req.BOOTREQUEST:
            return

        self.loop.create_task(self.handle_request(req, addr))

    @asyncio.coroutine
    def handle_request(self, req, addr):
        reqtype = next(filter(lambda o: o.__class__ == dhcpoptions.DHCPMessageType, req.options)).type

        try:
            client_id = next(filter(lambda o: o.__class__ == dhcpoptions.ClientIdentifier, req.options)).data
        except StopIteration:
            client_id = req.chaddr

        msg = dhcp.DHCPPacket()
        msg.xid = req.xid
        msg.flags = req.flags
        msg.giaddr = req.giaddr
        msg.op = msg.BOOTREPLY
        msg.chaddr = req.chaddr
        msg.htype = 1

        msg.options.append(dhcpoptions.ServerIdentifier(self.ddhcp.config["siaddr"]))

        now = time.time()

        if reqtype == dhcpoptions.DHCPMessageType.TYPES.DHCPDISCOVER:
            logging.info("%s from %s", reqtype.name, client_id)

            msg.options.append(dhcpoptions.DHCPMessageType(dhcpoptions.DHCPMessageType.TYPES.DHCPOFFER))

            try:
                lease = yield from self.ddhcp.get_new_lease(client_id)
            except KeyError:
                return

            msg.yiaddr = lease.addr
            msg.options.append(dhcpoptions.IPAddressLeaseTime(lease.leasetime))
            msg.options.append(dhcpoptions.SubnetMask(self.ddhcp.config["prefixlen"]))
            msg.options.append(dhcpoptions.RouterOption(lease.routers))
            msg.options.append(dhcpoptions.DomainNameServerOption(lease.dns))

            self.sendmsg(msg)

            logging.info("DHCPOFFER to %s, address %s", client_id, msg.yiaddr)

        elif reqtype == dhcpoptions.DHCPMessageType.TYPES.DHCPREQUEST:
            try:
                reqip = next(filter(lambda o: o.__class__ == dhcpoptions.RequestedIPAddress, req.options)).addr
            except StopIteration:
                reqip = req.ciaddr

            logging.info("%s from %s for %s", reqtype.name, client_id, reqip)

            try:
                lease = yield from self.ddhcp.get_lease(reqip, client_id)

                msg.options.append(dhcpoptions.DHCPMessageType(dhcpoptions.DHCPMessageType.TYPES.DHCPACK))
                msg.yiaddr = lease.addr
                msg.options.append(dhcpoptions.IPAddressLeaseTime(lease.leasetime))
                msg.options.append(dhcpoptions.SubnetMask(self.ddhcp.config["prefixlen"]))
                msg.options.append(dhcpoptions.RouterOption(lease.routers))
                msg.options.append(dhcpoptions.DomainNameServerOption(lease.dns))

                logging.info("DHCPACK to %s for %s", client_id, msg.yiaddr)

            except KeyError:
                msg.options.append(dhcpoptions.DHCPMessageType(dhcpoptions.DHCPMessageType.TYPES.DHCPNAK))
                logging.info("DHCPNAK to %s", client_id)

            self.sendmsg(msg)

        elif reqtype == dhcpoptions.DHCPMessageType.TYPES.DHCPRELEASE:
            logging.info("%s from %s for %s", reqtype.name, client_id, req.ciaddr)
            self.ddhcp.release(req.ciaddr, client_id)

        elif reqtype == dhcpoptions.DHCPMessageType.TYPES.DHCPDECLINE:
            logging.info("%s from %s for %s", reqtype.name, client_id, req.ciaddr)
            logging.debug("DECLINE not yet handled")
