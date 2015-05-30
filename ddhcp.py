import asyncio
import random
import time
from math import log
from enum import Enum
from ipaddress import IPv4Network

import messages
from lease import Lease

# BlockStates
#   FREE      - may be claimed after inquiry
#   TENTATIVE - another node is inquiring this block. This block may be in use.
#   CLAIMED   - a node claims this block
#   OURS      - this node claims this block
#   BLOCKED   - block may not be used

BlockState = Enum("BlockState", "FREE TENTATIVE CLAIMED OURS BLOCKED")


class Block:
    def __init__(self, subnet):
        self.subnet = subnet
        self.index = 0
        self.reset()

    def reset(self):
        self.scheduled = False
        self.state = BlockState.FREE
        self.valid_until = 0
        self.addr = None
        self.leases = dict()

    def hosts(self):
        return set(self.subnet.hosts()) | set([self.subnet.network_address, self.subnet.broadcast_address])

    def purge_leases(self, now):
        self.leases = dict(map(lambda l: (l.addr, l), filter(lambda l: l.isValid(now), self.leases.values())))

    def hasFreeAddress(self):
        return bool(self.hosts() - set(self.leases.keys()))

    def get_lease(self, now, addr, chaddr, f=None):
        """Gets an existing matching lease or creates a new one if addr is None.
           Raises KeyError in case of failure."""

        self.purge_leases(now)

        if addr is None:
            addr = (self.hosts() - set(self.leases.keys())).pop()
        elif not self.subnet.overlaps(IPv4Network(addr)):
            raise KeyError("Address not managed by this block")

        try:
            lease = self.leases[addr]

        except KeyError:
            lease = Lease()
            lease.addr = addr
            lease.chaddr = chaddr
            self.leases[addr] = lease

            if f:
                f(now, lease)

        if lease.chaddr != chaddr:
            raise KeyError("chaddr does not match lease")

        lease.renew(now)

        return lease

    def __repr__(self):
        return "Block(%s, index=%i, state=%s, valid=%i, addr=%s, leases=[%s])"  % (self.subnet, self.index, self.state, min(0, self.valid_until - time.time()), self.addr, ", ".join(map(repr, self.leases.values())))


class DDHCP:
    def __init__(self, config):
        # TODO hier etwas aufräumen. config reicht evtl...
        self.config = config
        self.id = random.getrandbits(64)
        self.blocktimeout = config["blocktimeout"]
        self.tentativetimeout = config["tentativetimeout"]
        nAddresses = config["prefix"].num_addresses
        prefixDiff = int(32 - log(config["blocksize"], 2) - config["prefix"].prefixlen)
        subnets = config["prefix"].subnets(prefixlen_diff=prefixDiff)

        self.blocks = list(map(Block, subnets))

        for i, block in enumerate(self.blocks):
            block.index = i

        for i in config["blocked"]:
            self.blocks[i].state = BlockState.BLOCKED

        self.own_blocks = dict()

        self.lease_queues = dict()
        self.claim_queues = dict()

    def block_from_ip(self, addr):
        """Given an IPv4Address return the block (or KeyError exception)"""
        net = IPv4Network(addr)

        for block in self.blocks:
            if block.subnet.overlaps(net):
                return block

        raise KeyError("Address not managed by any block")

    def prepare_lease(self, now, lease):
        lease.leasetime = self.config["leasetime"]
        lease.routers = self.config["routers"]
        lease.dns = self.config["dns"]

    @asyncio.coroutine
    def get_lease(self, addr, chaddr):
        now = time.time()

        if addr == None:
            # TODO Most likely a discover. select a new, empty block
            blocks = self.our_blocks()
            for block in blocks:
                block.purge_leases(now)

            blocks = filter(lambda b: b.hasFreeAddress(), blocks)

            # TODO den "besten" Block, nicht irgendeinen nehmen (Fragmentierung vermeiden)
            # TODO this may fail...

            try:
                block = next(blocks)
            except StopIteration:
                # TODO Try to get a block here?
                raise KeyError("No free block")

            return block.get_lease(now, addr, chaddr, self.prepare_lease)

        else:
            block = self.block_from_ip(addr)

            if block.state == BlockState.BLOCKED:
                raise KeyError("Blocked address")
            elif block.state == BlockState.OURS:
                return block.get_lease(now, addr, chaddr, self.prepare_lease)
            elif block.state in (BlockState.CLAIMED, BlockState.TENTATIVE):
                # ask peer, if it fails mark block as free and try to claim it

                queue = asyncio.Queue(loop=self.loop)
                self.lease_queues[addr] = queue

                msg = messages.RenewLease(addr, chaddr)
                self.protocol.msgto(msg, block.addr)

                try:
                    return (yield from asyncio.wait_for(queue.get(), timeout=3, loop=self.loop))
                except asyncio.TimeoutError:
                    # TODO -> Inquiry
                    block.reset()
                finally:
                    del self.lease_queues[addr]

            # This block is now free
            # Try to claim it. If someone else claims it try one more time to get a lease from him.
            # Else: Claim it, assign a new lease.
            print(block)

            # Only case left: BlockState.FREE
            # try to claim block, then get a lease
            # oberen if-teil refactoren?
            # alles zur coroutine machen?


        raise KeyError("TODO")
# forward request to peer. returns lease
# ein paket RenewLease
# antwortpaket Lease
# antwort anhand IP zuordnen

# peer per unicast erreichen
# timeout von X sekunden
# fehlschlag: block inquiry, 3x, dann nochmal mit neuer adresse versuchen
# falls inquiry fehlschlägt: block claimen, IP vergeben

# wir brauchen hier also: antworten auf RenewLease Pakete
# antworten auf UpdateClaim (anhand des Blocks)

# danach diese funktion refactoren


    def dump_blocks(self):
        blocks = ""

        m = { BlockState.FREE:      ".",
              BlockState.TENTATIVE: "-",
              BlockState.CLAIMED:   "C",
              BlockState.OURS:      "o",
              BlockState.BLOCKED:   "X"
            }

        for block in self.blocks:
            blocks += m[block.state]

        print("\nBlocks at", time.time())

        import re
        for b in re.findall('.{0,80}', blocks):
            print(b)

        for block in self.blocks:
            print(block)

    def set_protocol(self, protocol):
        self.protocol = protocol

    def free_blocks(self):
        return list(filter(lambda d: d.state == BlockState.FREE, self.blocks))

    def our_blocks(self):
        return list(filter(lambda d: d.state == BlockState.OURS, self.blocks))

    def randomFreeBlock(self):
        try:
            return random.choice(self.free_blocks())
        except IndexError:
            return None

    @asyncio.coroutine
    def schedule_block(self, block, now):
        timeout = block.valid_until - now

        yield from asyncio.sleep(timeout)

        if not block.scheduled:
            return

        block.scheduled = False

        now = time.time()
        # TODO when OURS und keine leases, ggf. freigeben (sofern wir noch n Blöcke behalten werden)
        block.purge_leases(now)

        if block.valid_until - now > 0:
            return

        if block.state == BlockState.TENTATIVE:
            block.reset()
        elif block.state == BlockState.CLAIMED:
            block.reset()
        elif block.state == BlockState.OURS:
            block.reset()

        self.block_changed()

    def block_changed(self):
        self.dump_blocks()

        now = time.time()

        due_blocks = filter(lambda d: d.valid_until > 0, self.blocks)
        due_blocks = sorted(due_blocks, key=lambda d: d.valid_until)

        if len(due_blocks) == 0:
            return

        for block in due_blocks:
            if block.scheduled:
                continue

            block.scheduled = True
            self.loop.create_task(self.schedule_block(block, now))

    def update_claims(self):
        # TODO don't update all free blocks. only keep one
        blocks = self.our_blocks()

        msgs = []

        now = time.time()

        for block in blocks:
            msg = messages.UpdateClaim()
            msg.block_index = block.index
            msg.timeout = self.blocktimeout
            block.valid_until = now + self.blocktimeout
            msgs.append(msg)

        self.protocol.msgsto_group(msgs)

    @asyncio.coroutine
    def update_claims_task(self):
        while True:
            yield from asyncio.sleep(15)
            self.update_claims()

    @asyncio.coroutine
    def start(self, loop):
        self.loop = loop

        self.loop.create_task(self.update_claims_task())

        # TODO add a random delay here to avoid congestion

        for x in range(0, 10):
            block = self.randomFreeBlock()
            yield from asyncio.sleep(1)

            if block == None:
                continue

            ret = yield from self.claimBlock(block)


    @asyncio.coroutine
    def claimBlock(self, block):
        for i in range(0, 3):
            msg = messages.InquireBlock()
            msg.block_index = block.index

            self.protocol.msgto_group(msg)
            yield from asyncio.sleep(0.2)

            if block.state != BlockState.FREE:
                return False

        msg = messages.UpdateClaim()
        msg.block_index = block.index
        msg.timeout = self.blocktimeout

        block.state = BlockState.OURS
        block.valid_until = time.time() + self.blocktimeout
        self.block_changed()

        self.protocol.msgto_group(msg)

        return True

    def handle_UpdateClaim(self, msg, node, addr):
        block = self.blocks[msg.block_index]

        if block.state == BlockState.BLOCKED:
            print(addr, "is claiming blocked block", block)
            return

        if block.state == BlockState.OURS:
            dispute_won = self.id < node
            print("DISPUTE", "WON" if dispute_won else "LOST", block)

            if dispute_won:
                return

            # Sicht des Blocks an den Gewinner schicken
            # TODO resolve dispute here (IPs überantworten und sowas)


        block.reset()

        # msg.timeout == 0 frees a block
        if msg.timeout > 0:
            block.state = BlockState.CLAIMED
            block.addr = addr
            block.valid_until = time.time() + msg.timeout

        self.block_changed()

    def handle_InquireBlock(self, msg, node, addr):
        block = self.blocks[msg.block_index]

        if block.state == BlockState.OURS:
            # TODO maybe sent all claimed blocks?
            msg = messages.UpdateClaim()
            msg.block_index = block.index
            msg.timeout = self.blocktimeout

            self.protocol.msgto(msg, addr)

        if block.state == BlockState.FREE:
            block.state = BlockState.TENTATIVE
            block.valid_until = time.time() + self.tentativetimeout

    def handle_RenewLease(self, msg, node, addr):
        now = time.time()

        print("Renewing lease", node, msg)

        try:
            block = self.block_from_ip(msg.addr)

            if block.state == BlockState.OURS:
                lease = block.get_lease(now, msg.addr, msg.chaddr, self.prepare_lease)
                self.protocol.msgto(lease, addr)

        except KeyError:
            pass

    def handle_Lease(self, msg, node, addr):
        try:
            queue = self.lease_queues[msg.addr]
            self.loop.create_task(queue.put(msg))
        except KeyError:
            pass

    def handle_LeaseNAK(self, msg, node, addr):
        # queue!
        print(msg)
