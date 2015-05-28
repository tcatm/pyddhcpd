import binascii
import struct
from ipaddress import IPv4Address

import dhcpoptions

class DHCPPacket:
    BOOTREQUEST = 1
    BOOTREPLY = 2
    MAGIC = bytes([99, 130, 83, 99])

    def __init__(self):
        self.op = 0
        self.htype = 0
        self.hops = 0
        self.xid = 0
        self.secs = 0
        self.flags = 0
        self.ciaddr = IPv4Address("0.0.0.0")
        self.yiaddr = IPv4Address("0.0.0.0")
        self.siaddr = IPv4Address("0.0.0.0")
        self.giaddr = IPv4Address("0.0.0.0")
        self.chaddr = b""
        self.sname = b""
        self.files = b""
        self.magic = self.MAGIC
        self.options = []

    def isValid(self):
        """Validates packet. Checks magic values."""
        if self.magic != self.MAGIC:
            return false

    def serialize(self):
        r = b""
        r += struct.pack("!B", self.op)
        r += struct.pack("!B", self.htype)
        r += struct.pack("!B", len(self.chaddr))
        r += struct.pack("!B", self.hops)
        r += struct.pack("!L", self.xid)
        r += struct.pack("!H", self.secs)
        r += struct.pack("!H", self.flags)
        r += self.ciaddr.packed
        r += self.yiaddr.packed
        r += self.siaddr.packed
        r += self.giaddr.packed
        r += struct.pack("!16s", self.chaddr)
        r += struct.pack("!64s", self.sname)
        r += struct.pack("!128s", self.files)
        r += struct.pack("!4s", self.magic)
        r += b"".join(map(lambda o: o.serialize(), self.options))
        r += struct.pack("!B", 255) # Option End
        return r

    def deserialize(self, f):
        self.op = struct.unpack("!B", f.read(1))[0]
        self.htype = struct.unpack("!B", f.read(1))[0]
        hlen = struct.unpack("!B", f.read(1))[0]
        self.hops = struct.unpack("!B", f.read(1))[0]
        self.xid = struct.unpack("!L", f.read(4))[0]
        self.secs = struct.unpack("!H", f.read(2))[0]
        self.flags = struct.unpack("!H", f.read(2))[0]
        self.ciaddr = IPv4Address(f.read(4))
        self.yiaddr = IPv4Address(f.read(4))
        self.siaddr = IPv4Address(f.read(4))
        self.giaddr = IPv4Address(f.read(4))
        self.chaddr = f.read(16)[0:hlen]
        self.sname = f.read(64)
        self.file = f.read(128)
        self.magic = f.read(4)

        while True:
            tag = struct.unpack("!B", f.read(1))[0]

            if tag == 0:
                continue

            if tag == 255:
                break

            tlen = struct.unpack("!B", f.read(1))[0]

            try:
                option = dhcpoptions.optionmap[tag]()
                option.deserialize(tlen, f)
                self.options.append(option)
            except KeyError:
                # skip unknown option
                f.read(tlen)

    def __repr__(self):
        return "DHCP(op=%i, htype=%i, hops=%i, xid=%i, secs=%i, flags=%i, ciaddr=%s, yiaddr=%s, siaddr=%s, giaddr=%s, chaddr=%s, magic=%s, options=[%s])" % (self.op, self.htype, self.hops, self.xid, self.secs, self.flags, str(self.ciaddr), str(self.yiaddr), str(self.siaddr), str(self.giaddr), binascii.hexlify(self.chaddr).decode("UTF-8"), binascii.hexlify(self.magic).decode("UTF-8"), ", ".join(map(repr, self.options)))
