import asyncio
import random
import time
from math import log, ceil, floor
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
        self.state = BlockState.FREE
        self.valid_until = 0
        self.addr = None
        self.leases = dict()

    def reset_if_due(self, now):
        if self.state not in (BlockState.FREE, BlockState.BLOCKED)  and self.valid_until - now < 0:
            self.reset()

    @property
    def usage(self):
        return len(self.leases)

    def hosts(self):
        return set(self.subnet.hosts()) | set([self.subnet.network_address, self.subnet.broadcast_address])

    def purge_leases(self, now):
        self.leases = dict(map(lambda l: (l.addr, l), filter(lambda l: l.isValid(now), self.leases.values())))

    def hasFreeAddress(self):
        return bool(self.hosts() - set(self.leases.keys()))

    def release(self, addr, client_id):
        """Release a lease if it exists."""

        try:
            lease = self.leases[addr]
            if lease.client_id == client_id:
                del self.leases[addr]
        except KeyError:
            pass

    def get_lease(self, now, addr, client_id, f=None):
        """Gets an existing matching lease or creates a new one if addr is None.
           Raises KeyError in case of failure."""

        if addr is None:
            addr = (self.hosts() - set(self.leases.keys())).pop()
        elif not self.subnet.overlaps(IPv4Network(addr)):
            raise KeyError("Address not managed by this block")

        try:
            lease = self.leases[addr]

        except KeyError:
            lease = Lease()
            lease.addr = addr
            lease.client_id = client_id
            self.leases[addr] = lease

            if f:
                f(now, lease)

        if lease.client_id != client_id:
            raise KeyError("client_id does not match lease")

        lease.renew(now)

        return lease

    def __repr__(self):
        return "Block(%s, index=%i, state=%s, valid_until=%i, addr=%s, leases=[%s])"  % (self.subnet, self.index, self.state, self.valid_until, self.addr, ", ".join(map(repr, self.leases.values())))


def wrap_housekeeping(f):
    def inner(self, *args, **kwargs):
        try:
            return f(self, *args, **kwargs)
        finally:
            self.loop.create_task(self.housekeeping())

    return inner


class DDHCP:
    def __init__(self, config):
        # TODO hier etwas aufräumen. config reicht evtl...
        self.config = config
        self.id = random.getrandbits(64)
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

        self.housekeeping_lock = asyncio.Lock()
        self.housekeeping_call = None

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
    def get_lease_from_peer(self, addr, client_id, peer):
        queue = asyncio.Queue(loop=self.loop)
        self.lease_queues[addr] = queue

        msg = messages.RenewLease(addr, client_id)
        self.protocol.msgto(msg, peer)

        try:
            lease = yield from asyncio.wait_for(queue.get(), timeout=3, loop=self.loop)

            if lease is None:
                raise KeyError("LeaseNAΚ from peer")

            return lease
        except asyncio.TimeoutError:
            return None
        finally:
            del self.lease_queues[addr]

    @asyncio.coroutine
    @wrap_housekeeping
    def get_new_lease(self, client_id):
        now = time.time()

        blocks = self.our_blocks()
        for block in blocks:
            block.purge_leases(now)

        # If we already manage a lease for this client_id, return it
        for lease in [l for sublist in [b.leases.values() for b in self.our_blocks()] for l in sublist]:
            if lease.client_id == client_id:
                return lease

        blocks = filter(lambda b: b.hasFreeAddress(), blocks)
        blocks = reversed(sorted(blocks, key=lambda b: b.usage))

        try:
            block = next(blocks)
        except StopIteration:
            # TODO Try to get a block here?
            raise KeyError("No free block")

        return block.get_lease(now, None, client_id, self.prepare_lease)

    @asyncio.coroutine
    @wrap_housekeeping
    def get_lease(self, addr, client_id):
        now = time.time()
        block = self.block_from_ip(addr)

        if block.state == BlockState.BLOCKED:
            raise KeyError("Blocked address")
        elif block.state == BlockState.OURS:
            return block.get_lease(now, addr, client_id, self.prepare_lease)
        elif block.state in (BlockState.CLAIMED, BlockState.TENTATIVE):
            lease = yield from self.get_lease_from_peer(addr, client_id, block.addr)

            if lease:
                return lease
            else:
                block.reset()

            result = yield from self.claim_block(block)
            if result:
                # This is block is now managed by us.
                return block.get_lease(now, addr, client_id, self.prepare_lease)

            # Try to reach peer again (addr might have changed)
            lease = yield from self.get_lease_from_peer(addr, client_id, block.addr)

            if lease:
                return lease

            raise KeyError("Unable to reach peer")

        raise KeyError("Block is not managed by anyone")

    @wrap_housekeeping
    def release(self, addr, client_id):
        print("RELEASE", addr, client_id)

        block = self.block_from_ip(addr)

        if block.state == BlockState.OURS:
            block.release(addr, client_id)

        elif block.state in (BlockState.CLAIMED, BlockState.TENTATIVE):
            msg = messages.Release(addr, client_id)
            self.protocol.msgto(msg, block.addr)

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

    def update_claims(self):
        blocks = self.our_blocks()

        msgs = []

        now = time.time()

        for block in blocks:
            msg = messages.UpdateClaim()
            msg.block_index = block.index
            msg.timeout = int(block.valid_until - now)
            msg.usage = block.usage

            if msg.timeout < 0:
                continue

            msgs.append(msg)
            print(msg)

        self.protocol.msgsto_group(msgs)

    @asyncio.coroutine
    def update_claims_task(self):
        while True:
            yield from asyncio.sleep(self.config["claiminterval"])
            self.update_claims()

    @asyncio.coroutine
    def start(self, loop):
        self.loop = loop

        self.loop.create_task(self.update_claims_task())

        yield from self.housekeeping()

    def schedule_housekeeping(self):
        self.loop.create_task(self.housekeeping())

    @asyncio.coroutine
    def housekeeping(self):
        self.housekeeping_call = None
        yield from self.housekeeping_lock.acquire()

        try:
            print("Housekeeping")

            self.dump_blocks()

            now = time.time()

            for block in self.blocks:
                block.reset_if_due(now)

            for block in self.our_blocks():
                block.purge_leases(now)

            our_blocks = self.our_blocks()

            spares = len(our_blocks) * self.config["blocksize"] - sum([b.usage for b in our_blocks]) - self.config["spares"]
            spare_blocks = abs(spares/self.config["blocksize"])

            print("Spare IP delta:", spares)

            if spares < 0:
                # too few spares. claim additional blocks
                yield from self.claim_n_blocks(ceil(spare_blocks))

            elif spares > 0:
                empty_blocks = list(filter(lambda b: b.usage == 0, our_blocks))

                for block in empty_blocks[0:floor(spare_blocks)]:
                    block.reset()

                    msg = messages.UpdateClaim()
                    msg.block_index = block.index
                    msg.timeout = 0
                    msg.usage = 0

                    self.protocol.msgto_group(msg)

                    print("Freed", block)

            for block in self.our_blocks():
                # Update all timeouts of our blocks
                block.valid_until = now + self.config["blocktimeout"]


            timeouts = [now + self.config["blocktimeout"] / 2] # Increase blockleastime early
            timeouts += [b.valid_until for b in self.blocks]
            timeouts += [l.valid_until for sublist in [b.leases.values() for b in self.our_blocks()] for l in sublist]

            try:
                timeout = min(filter(lambda t: t > now, timeouts))

                print("next housekeeping in %i seconds" % (timeout - now))

                if self.housekeeping_call:
                    self.housekeeping_call.cancel()

                self.housekeeping_call = self.loop.call_later(timeout - now, self.schedule_housekeeping)

            except ValueError:
                # no timeout due
                pass

        finally:
            self.housekeeping_lock.release()

    @asyncio.coroutine
    def claim_n_blocks(self, n):
        print("Attempting to claim %i additional blocks." % n)

        for i in range(0, n):
            yield from self.claim_any_block()

    @asyncio.coroutine
    def claim_any_block(self):
        block = self.randomFreeBlock()

        if not block:
            return None

        result = yield from self.claim_block(block)

        if result:
            return block
        else:
            return None

    @asyncio.coroutine
    def claim_block(self, block):
        for i in range(0, 3):
            msg = messages.InquireBlock()
            msg.block_index = block.index

            self.protocol.msgto_group(msg)
            yield from asyncio.sleep(0.2)

            if block.state != BlockState.FREE:
                return False

        now = time.time()

        block.state = BlockState.OURS
        block.valid_until = now + self.config["blocktimeout"]

        msg = messages.UpdateClaim()
        msg.block_index = block.index
        msg.timeout = int(block.valid_until - now)
        msg.usage = block.usage

        self.protocol.msgto_group(msg)

        print("Claimed", block)

        return True

    @wrap_housekeeping
    def handle_UpdateClaim(self, msg, node, addr):
        block = self.blocks[msg.block_index]

        if block.state == BlockState.BLOCKED:
            print(addr, "is claiming blocked block", block)
            return

        if block.state == BlockState.OURS:
            dispute_won = block.usage > msg.usage or (self.id < node and block.usage == msg.usage)
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

    @wrap_housekeeping
    def handle_InquireBlock(self, msg, node, addr):
        block = self.blocks[msg.block_index]

        now = time.time()

        if block.state == BlockState.OURS:
            # TODO maybe sent all claimed blocks?
            msg = messages.UpdateClaim()
            msg.block_index = block.index
            msg.timeout = int(block.valid_until - now)

            self.protocol.msgto(msg, addr)

        if block.state == BlockState.FREE and node < self.id:
            block.state = BlockState.TENTATIVE
            block.valid_until = now + self.config["tentativetimeout"]

    def handle_RenewLease(self, msg, node, addr):
        now = time.time()

        try:
            block = self.block_from_ip(msg.addr)

            if block.state == BlockState.OURS:
                try:
                    lease = block.get_lease(now, msg.addr, msg.client_id, self.prepare_lease)
                    self.protocol.msgto(lease, addr)
                except KeyError:
                    self.protocol.msgto(messages.LeaseNAK(msg.addr), addr)

        except KeyError:
            pass

    def handle_Lease(self, msg, node, addr):
        # handle lease for our blocks
        # add them if they are non-conflicting
        # schedule a update_claims
        # @wrap_housekeeping
        try:
            queue = self.lease_queues[msg.addr]
            self.loop.create_task(queue.put(msg))
        except KeyError:
            pass

    def handle_LeaseNAK(self, msg, node, addr):
        try:
            queue = self.lease_queues[msg.addr]
            self.loop.create_task(queue.put(None))
        except KeyError:
            pass

    @wrap_housekeeping
    def handle_Release(self, msg, node, addr):
        block = self.block_from_ip(msg.addr)

        if block.state == BlockState.OURS:
            block.release(msg.addr, msg.client_id)
