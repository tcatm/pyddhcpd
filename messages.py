import binascii
import struct
from ipaddress import IPv4Address, IPv4Network, IPv4Address

from lease import Lease

class UpdateClaim:
    """Claim a block"""
    command = 1

    def __init__(self):
        self.block_index = 0
        self.timeout = 0
        self.usage = 0

    def deserialize(self, f):
        self.block_index = struct.unpack("!I", f.read(4))[0]
        self.timeout = struct.unpack("!H", f.read(2))[0]
        self.usage = struct.unpack("!B", f.read(1))[0]

    def serialize(self):
        r = b""
        r += struct.pack("!I", self.block_index)
        r += struct.pack("!H", self.timeout)
        r += struct.pack("!B", self.usage)
        return r

    def __repr__(self):
        return "UpdateClaim(block=%i, timeout=%i, usage=%i)" % (self.block_index, self.timeout, self.usage)


class InquireBlock:
    """Ask any holder of a specific block to claim it."""
    command = 2

    def __init__(self):
        self.block_index = 0

    def deserialize(self, f):
        self.block_index = struct.unpack("!I", f.read(4))[0]

    def serialize(self):
        r = b""
        r += struct.pack("!I", self.block_index)
        return r

    def __repr__(self):
        return "InquireBlock(block=%i)" % (self.block_index)


class RenewLease:
    """Ask for a renewed lease."""
    command = 16

    def __init__(self, addr=IPv4Address("0.0.0.0"), chaddr=b""):
        self.addr = addr
        self.chaddr = chaddr

    def deserialize(self, f):
        self.addr = IPv4Address(f.read(4))
        self.chaddr = f.read(6)

    def serialize(self):
        r = b""
        r += self.addr.packed
        r += struct.pack("!6s", self.chaddr)
        return r

    def __repr__(self):
        return "RenewLease(addr=%s, chaddr=%s)" % (str(self.addr), binascii.hexlify(self.chaddr).decode("UTF-8"))


class LeaseNAK:
    """Deny renewal of lease."""
    command = 18

    def __init__(self, addr=IPv4Address("0.0.0.0")):
        self.addr = addr

    def deserialize(self, f):
        self.addr = IPv4Address(f.read(4))

    def serialize(self):
        return self.addr.packed

    def __repr__(self):
        return "LeaseNAK(addr=%s)" % (str(self.addr))


class Release:
    """Release a lease. There will be no response."""
    command = 19

    def __init__(self, addr=IPv4Address("0.0.0.0"), chaddr=b""):
        self.addr = addr
        self.chaddr = chaddr

    def deserialize(self, f):
        self.addr = IPv4Address(f.read(4))
        self.chaddr = f.read(6)

    def serialize(self):
        r = b""
        r += self.addr.packed
        r += struct.pack("!6s", self.chaddr)
        return r

    def __repr__(self):
        return "Release(addr=%s, chaddr=%s)" % (str(self.addr), binascii.hexlify(self.chaddr).decode("UTF-8"))


msgmap = {
    1: UpdateClaim,
    2: InquireBlock,
    16: RenewLease,
    17: Lease,
    18: LeaseNAK,
    19: Release
}


class Header:
    """Header shared by all packets"""
    def __init__(self):
        self.prefix = IPv4Network("0.0.0.0/0")
        self.node = 0
        self.blocksize = 0
        self.command = 0
        self.count = 0
        self.payload = []

    @property
    def msg_type(self):
        return type(msgmap[self.command]()).__name__

    def append(self, payload):
        if len(self.payload) == 0:
            self.command = payload.command

        if self.command != payload.command:
            raise TypeError("Payload command does not match message command")

        self.payload.append(payload)
        self.count = len(self.payload)

    def deserialize(self, f):
        self.node = struct.unpack("!Q", f.read(8))[0]
        self.prefix = IPv4Network(f.read(4))
        self.prefix = self.prefix.supernet(new_prefix= struct.unpack("!B", f.read(1))[0])
        self.blocksize = struct.unpack("!B", f.read(1))[0]
        self.command = struct.unpack("!B", f.read(1))[0]
        self.count = struct.unpack("!B", f.read(1))[0]

    def serialize(self):
        r = b""
        r += struct.pack("!Q", self.node)
        r += self.prefix.network_address.packed
        r += struct.pack("!B", self.prefix.prefixlen)
        r += struct.pack("!B", self.blocksize)
        r += struct.pack("!B", self.command)
        r += struct.pack("!B", self.count)

        for payload in self.payload:
            r += payload.serialize()

        return r

    def __repr__(self):
        return "Header(node=%i, prefix=%s, blocksize=%i, command=%i, count=%i, payload=[%s])" % (self.node, self.prefix.compressed, self.blocksize, self.command, self.count, ", ".join(map(repr, self.payload)))


def message_read(f):
    header = Header()
    try:
        header.deserialize(f)

        if not header.command in msgmap:
            raise TypeError("Unknown command: %i" % header.command)

        for i in range(0, header.count):
            msg = msgmap[header.command]()
            msg.deserialize(f)
            header.append(msg)

    except struct.error:
        raise TypeError("Can not deserialize message")

    return header

