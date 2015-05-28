import struct
from ipaddress import IPv4Address, IPv4Network, IPv4Address

class UpdateClaim:
    """Claim a block"""
    command = 1

    def __init__(self):
        self.block_index = 0
        self.timeout = 0
        self.reserved = 0

    def deserialize(self, f):
        self.block_index = struct.unpack("!I", f.read(4))[0]
        self.timeout = struct.unpack("!H", f.read(2))[0]
        self.reserved = struct.unpack("!H", f.read(2))[0]

    def serialize(self):
        r = b""
        r += struct.pack("!I", self.block_index)
        r += struct.pack("!H", self.timeout)
        r += struct.pack("!H", self.reserved)
        return r

    def __repr__(self):
        return "UpdateClaim(block=%i, timeout=%i)" % (self.block_index, self.timeout)


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


msgmap = {
    1: UpdateClaim,
    2: InquireBlock
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

