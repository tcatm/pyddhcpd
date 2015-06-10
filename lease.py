import binascii
import struct
from ipaddress import IPv4Address


class Lease:
    command = 17

    def __init__(self):
        self.addr = IPv4Address("0.0.0.0")
        self.leasetime = 0
        self.valid_until = 0
        self.client_id = b""
        self.routers = []
        self.dns = []

    def renew(self, now):
        self.valid_until = now + 2 * self.leasetime

    def isValid(self, now):
        return self.valid_until > now

    def deserialize(self, f):
        self.addr = IPv4Address(f.read(4))
        self.leasetime = struct.unpack("!L", f.read(4))[0]

        idlen = struct.unpack("!B", f.read(1))[0]
        self.client_id = f.read(idlen)

        n = struct.unpack("!B", f.read(1))[0]
        self.routers = []
        for i in range(0, n):
            self.routers.append(IPv4Address(f.read(4)))

        n = struct.unpack("!B", f.read(1))[0]
        self.routers = []
        for i in range(0, n):
            self.dns.append(IPv4Address(f.read(4)))

    def serialize(self):
        r = b""
        r += self.addr.packed
        r += struct.pack("!L", self.leasetime)

        r += struct.pack("!B", len(self.client_id))
        r += self.client_id

        r += struct.pack("!B", len(self.routers))
        r += b"".join(map(lambda r: r.packed, self.routers))

        r += struct.pack("!B", len(self.dns))
        r += b"".join(map(lambda r: r.packed, self.dns))

        return r

    def __repr__(self):
        return "Lease(addr=%s, client_id=%s, leasetime=%i)" % (self.addr, binascii.hexlify(self.client_id).decode("UTF-8"), self.leasetime)
