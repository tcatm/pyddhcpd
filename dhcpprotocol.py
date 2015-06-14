import asyncio
import io
import time
import dhcp
import dhcpoptions
import logging
from lease import Lease


class DHCPProtocol:
    def __init__(self, loop, ddhcp):
        self.loop = loop
        self.ddhcp = ddhcp

    def connection_made(self, transport):
        self.transport = transport

    def sendmsg(self, msg, addr):
        if addr[0] == '0.0.0.0' or msg.flags & 1:
            self.transport.sendto(msg.serialize(), ("<broadcast>", 68))
        else:
            self.transport.sendto(msg.serialize(), addr)

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

            self.sendmsg(msg, addr)

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

            self.sendmsg(msg, addr)

        elif reqtype == dhcpoptions.DHCPMessageType.TYPES.DHCPRELEASE:
            logging.info("%s from %s for %s", reqtype.name, client_id, req.ciaddr)
            self.ddhcp.release(req.ciaddr, client_id)

        elif reqtype == dhcpoptions.DHCPMessageType.TYPES.DHCPDECLINE:
            logging.info("%s from %s for %s", reqtype.name, client_id, req.ciaddr)
            logging.debug("DECLINE not yet handled")
