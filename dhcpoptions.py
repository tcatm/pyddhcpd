import struct
from enum import Enum
from ipaddress import IPv4Address, IPv4Network


class SubnetMask:
    CODE = 1

    def __init__(self, prefixlen=0):
        self.prefixlen = prefixlen

    def deserialize(self, len, f):
        self.prefixlen = IPv4Network("0.0.0.0/" + str(IPv4Address(f.read(len)))).prefixlen

    def serialize(self):
        r = b""
        r += struct.pack("!B", self.CODE)
        r += struct.pack("!B", 4)
        r += IPv4Network("0.0.0.0").supernet(new_prefix=self.prefixlen).netmask.packed
        return r

    def __repr__(self):
        return "SubnetMask(%i)" % self.prefixlen


class RouterOption:
    CODE = 3

    def __init__(self, addrs=[]):
        self.addrs = addrs

    def deserialize(self, len, f):
        self.addrs = []
        for i in range(0, int(len / 4)):
            self.addrs.append(IPv4Address(f.read(4)))

    def serialize(self):
        r = b""
        r += struct.pack("!B", self.CODE)
        r += struct.pack("!B", len(self.addrs) * 4)
        r += b"".join(map(lambda a: a.packed, self.addrs))
        return r

    def __repr__(self):
        return "RouterOption(%s)" % (", ".join(map(repr, self.addrs)))


class DomainNameServerOption:
    CODE = 6

    def __init__(self, addrs=[]):
        self.addrs = addrs

    def deserialize(self, len, f):
        self.addrs = []
        for i in range(0, int(len / 4)):
            self.addrs.append(IPv4Address(f.read(4)))

    def serialize(self):
        r = b""
        r += struct.pack("!B", self.CODE)
        r += struct.pack("!B", len(self.addrs) * 4)
        r += b"".join(map(lambda a: a.packed, self.addrs))
        return r

    def __repr__(self):
        return "DomainNameServerOption(%s)" % (", ".join(map(repr, self.addrs)))


class RequestedIPAddress:
    CODE = 50

    def __init__(self):
        self.addr = IPv4Address("0.0.0.0")

    def deserialize(self, len, f):
        self.addr = IPv4Address(f.read(len))

    def serialize(self):
        r = b""
        r += struct.pack("!B", self.CODE)
        r += struct.pack("!B", 4)
        r += self.addr.packed
        return r

    def __repr__(self):
        return "RequestedIPAddress(%s)" % str(self.addr)


class IPAddressLeaseTime:
    CODE = 51

    def __init__(self, time=0):
        self.time = time

    def deserialize(self, len, f):
        self.time = struct.unpack("!L", f.read(len))[0]

    def serialize(self):
        r = b""
        r += struct.pack("!B", self.CODE)
        r += struct.pack("!B", 4)
        r += struct.pack("!L", self.time)
        return r

    def __repr__(self):
        return "IPAddressLeaseTime(%i)" % self.time


class DHCPMessageType:
    CODE = 53

    TYPES = Enum("Types", "DHCPDISCOVER DHCPOFFER DHCPREQUEST DHCPDECLINE DHCPACK DHCPNAK DHCPRELEASE DHCPINFORM")

    def __init__(self, type=TYPES.DHCPDISCOVER):
        self.type = type

    def deserialize(self, len, f):
        self.type = self.TYPES(struct.unpack("!B", f.read(len))[0])

    def serialize(self):
        r = b""
        r += struct.pack("!B", self.CODE)
        r += struct.pack("!B", 1)
        r += struct.pack("!B", self.type.value)
        return r

    def __repr__(self):
        return "DHCPMessageType(%s)" % self.type.name


class ServerIdentifier:
    CODE = 54

    def __init__(self, addr=IPv4Address("0.0.0.0")):
        self.addr = addr

    def deserialize(self, len, f):
        self.addr = IPv4Address(f.read(4))

    def serialize(self):
        r = b""
        r += struct.pack("!B", self.CODE)
        r += struct.pack("!B", 4)
        r += self.addr.packed
        return r

    def __repr__(self):
        return "ServerIdentifier(%s)" % str(self.addr)


class ParameterRequestList:
    CODE = 55

    def __init__(self):
        self.list = []

    def deserialize(self, len, f):
        self.list = struct.unpack("!%iB" % len, f.read(len))

    def serialize(self):
        r = b""
        r += struct.pack("!B", self.CODE)
        r += struct.pack("!B", len(self.list))
        r += struct.pack("!%iB" % len(self.list), *self.list)
        return r

    def __repr__(self):
        return "ParameterRequestList(%s)" % ", ".join(map(str, self.list))


class ClientIdentifier:
    CODE = 61

    def __init__(self):
        self.data = bytes([0, 0])

    def deserialize(self, len, f):
        self.data = f.read(len)

    def serialize(self):
        r = b""
        r += struct.pack("!B", self.CODE)
        r += struct.pack("!B", len(self.data))
        r += self.data
        return r

    def __repr__(self):
        return "ClientIdentifier(%s)" % self.data


optionmap = {
    1: SubnetMask,
    3: RouterOption,
    6: DomainNameServerOption,
    50: RequestedIPAddress,
    51: IPAddressLeaseTime,
    53: DHCPMessageType,
    54: ServerIdentifier,
    55: ParameterRequestList,
    61: ClientIdentifier
}
