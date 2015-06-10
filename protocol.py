import messages
import io

class DDHCPProtocol:
    def __init__(self, loop, group_addr, ddhcp, config):
        self.config = config
        self.loop = loop
        self.group_addr = group_addr
        self.ddhcp = ddhcp
        self.ddhcp.set_protocol(self)

    def connection_made(self, transport):
        self.transport = transport
        self.loop.create_task(self.ddhcp.start(self.loop))

    def prepare_header(self):
        header = messages.Header()
        header.prefix = self.config["prefix"]
        header.blocksize = self.config["blocksize"]
        header.node = self.ddhcp.id

        return header

    def msgsto(self, msgs, addr):
        header = self.prepare_header()

        for msg in msgs:
            header.append(msg)

        self.transport.sendto(header.serialize(), addr)

    def msgsto_group(self, msgs):
        self.msgsto(msgs, self.group_addr)

    def msgto(self, msg, addr):
        self.msgto([msg], addr)

    def msgto_group(self, msg):
        self.msgsto_group([msg])

    def datagram_received(self, data, addr):
        try:
            msg = messages.message_read(io.BytesIO(data))
        except TypeError:
            return

        # Ignore our own packets
        if msg.node == self.ddhcp.id:
            return

        if msg.prefix != self.config["prefix"] or msg.blocksize != self.config["blocksize"]:
            return

        method = getattr(self.ddhcp, "handle_" + msg.msg_type)

        for payload in msg.payload:
            method(payload, msg.node, addr)
