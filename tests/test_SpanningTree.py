import asyncio
from context import *
from os import urandom
import unittest


class TestSpanningTreeApplication(unittest.TestCase):
    def setUp(self) -> None:
        Packager.reset()
        mock_interface1.castbox.clear()
        mock_interface1.outbox.clear()
        mock_interface1.inbox.clear()
        castbox.clear()
        inbox.clear()
        outbox.clear()
        SpanningTree.invoke('get_seen').clear()
        SpanningTree.invoke('get_known_claims').clear()
        return super().setUp()

    def tearDown(self) -> None:
        SpanningTree.invoke('stop')
        Packager.reset()
        mock_interface1.castbox.clear()
        mock_interface1.outbox.clear()
        mock_interface1.inbox.clear()
        castbox.clear()
        inbox.clear()
        outbox.clear()
        SpanningTree.invoke('get_seen').clear()
        SpanningTree.invoke('get_known_claims').clear()
        return super().tearDown()

    def test_start_and_stop_e2e(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(SpanningTree)
        Packager.add_application(Gossip)
        assert len(Packager._hooks.get('remove_peer', [])) == 0
        assert len(Gossip.invoke('get_subscriptions')) == 0
        SpanningTree.invoke('start', sub=True)
        assert len(Packager._hooks.get('remove_peer', [])) == 1
        assert len(Gossip.invoke('get_subscriptions')) == 1
        assert len(Packager.new_events) == 1
        assert len(Packager.schedule.keys()) == 0
        asyncio.run(Packager.process())
        assert len(Packager.new_events) == 0
        assert len(Packager.schedule.keys()) == 1
        assert SpanningTree.id+b's' in Packager.schedule
        assert len(Packager.new_events) == 0

        assert len(Packager.cancel_events) == 0
        SpanningTree.invoke('stop')
        assert len(Gossip.invoke('get_subscriptions')) == 0
        assert len(Packager.cancel_events) == 2
        asyncio.run(Packager.process())
        assert len(Packager.schedule.keys()) == 0
        assert len(Packager.new_events) == 0
        assert len(Packager._hooks.get('remove_peer', [])) == 0

    def test_invoke_broadcast(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(SpanningTree)
        SpanningTree.invoke('start')
        assert len(mock_interface1.castbox) == 0
        SpanningTree.invoke('broadcast')
        assert len(mock_interface1.castbox) == 1
        assert len(castbox) == 0
        asyncio.run(Packager.process())
        assert len(castbox) == 1

    def test_receive_SEND_with_worse_claim_sends_RESPOND(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(SpanningTree)
        claim_score = lambda pid: SpanningTree.invoke('claim_score', pid)
        SpanningTree.invoke('start')
        local_claim_score = claim_score(Packager.node_id)
        assert len(Packager.node_id) == 32, len(Packager.node_id)

        # add a peer with the worse claim score peer_id
        peer_id = (local_claim_score + 11).to_bytes(32, 'big')
        peer_id = xor(peer_id, b'1234' * 8)
        their_score = claim_score(peer_id)
        while their_score <= local_claim_score:
            print('recalculating peer_id')
            peer_id = urandom(32)
            their_score = claim_score(peer_id)
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])

        # receive a SEND from that peer
        SpanningTree.invoke('start')
        tm = TreeMessage(TreeOp.SEND, now(), 0, peer_id, b'\x00' * 16, peer_id)
        package = Package.from_blob(
            SpanningTree.id, SpanningTree.invoke('serialize', tm)
        )
        assert len(outbox) == 0
        assert len(SpanningTree.invoke('get_seen')) == 0
        Packager.deliver(package, mock_interface1, b'mac0')
        assert len(SpanningTree.invoke('get_seen')) == 1
        asyncio.run(Packager.process())
        assert len(outbox) == 1, (len(outbox), len(mock_interface1.outbox))
        packet = Packet.unpack(outbox.popleft().data)
        p = Package.unpack(packet.body)
        tm = SpanningTree.invoke('deserialize', p.blob)
        assert tm.op == TreeOp.RESPOND, tm.op
        assert tm.claim == Packager.node_id, (tm.claim.hex(), Packager.node_id.hex())
        assert tm.address == b'\x00' * 16, tm.address.hex()

    def test_receive_SEND_with_better_claim_adds_to_known_claims(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(SpanningTree)
        claim_score = lambda pid: SpanningTree.invoke('claim_score', pid)
        SpanningTree.invoke('start')
        local_claim_score = claim_score(Packager.node_id)
        assert len(Packager.node_id) == 32, len(Packager.node_id)

        # add a peer with the better claim score peer_id
        peer_id = (local_claim_score - 11).to_bytes(32, 'big')
        peer_id = xor(peer_id, b'1234' * 8)
        their_score = claim_score(peer_id)
        while their_score >= local_claim_score:
            print('recalculating peer_id')
            peer_id = urandom(32)
            their_score = claim_score(peer_id)
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])

        # receive a SEND from that peer
        SpanningTree.invoke('start')
        tm = TreeMessage(TreeOp.SEND, now(), 0, peer_id, b'\x00' * 16, peer_id)
        package = Package.from_blob(
            SpanningTree.id, SpanningTree.invoke('serialize', tm)
        )
        assert len(SpanningTree.invoke('get_known_claims')) == 0
        Packager.deliver(package, mock_interface1, b'mac0')
        assert len(SpanningTree.invoke('get_known_claims')) == 1
        SpanningTree.invoke('get_known_claims').pop()

    def test_receive_RESPOND_with_better_claim_adds_to_known_claims(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(SpanningTree)
        claim_score = lambda pid: SpanningTree.invoke('claim_score', pid)
        SpanningTree.invoke('start')
        local_claim_score = claim_score(Packager.node_id)
        assert len(Packager.node_id) == 32, len(Packager.node_id)

        # add a peer with the better claim score peer_id
        peer_id = (local_claim_score - 11).to_bytes(32, 'big')
        peer_id = xor(peer_id, b'1234' * 8)
        their_score = claim_score(peer_id)
        while their_score >= local_claim_score:
            print('recalculating peer_id')
            peer_id = urandom(32)
            their_score = claim_score(peer_id)
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])

        # receive a RESPOND from that peer
        SpanningTree.invoke('start')
        tm = TreeMessage(TreeOp.RESPOND, now(), 0, peer_id, b'\x00' * 16, peer_id)
        package = Package.from_blob(
            SpanningTree.id, SpanningTree.invoke('serialize', tm)
        )
        assert len(SpanningTree.invoke('get_known_claims')) == 0
        Packager.deliver(package, mock_interface1, b'mac0')
        assert len(SpanningTree.invoke('get_known_claims')) == 1
        SpanningTree.invoke('get_known_claims').pop()

    def test_receive_REQUEST_ADDRESS_ASSIGNMENT_sends_ASSIGN_ADDRESS(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(SpanningTree)
        claim_score = lambda pid: SpanningTree.invoke('claim_score', pid)
        SpanningTree.invoke('start')
        local_claim_score = claim_score(Packager.node_id)
        local_addr = Packager.node_addrs[-1]
        assert len(Packager.node_id) == 32, len(Packager.node_id)

        # add a peer with a worse claim score peer_id
        peer_id = (local_claim_score + 11).to_bytes(32, 'big')
        peer_id = xor(peer_id, b'1234' * 8)
        their_score = claim_score(peer_id)
        while their_score <= local_claim_score:
            print('recalculating peer_id')
            peer_id = urandom(32)
            their_score = claim_score(peer_id)
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])

        # receive a REQUEST_ADDRESS_ASSIGNMENT from that peer
        SpanningTree.invoke('start')
        tm = TreeMessage(
            TreeOp.REQUEST_ADDRESS_ASSIGNMENT, now(), 0, Packager.node_id,
            b'\x00' * 16, peer_id
        )
        package = Package.from_blob(
            SpanningTree.id, SpanningTree.invoke('serialize', tm)
        )
        assert len(mock_interface1.outbox) == 0
        assert len(SpanningTree.invoke('get_current_children')) == 0
        Packager.deliver(package, mock_interface1, b'mac0')
        assert len(mock_interface1.outbox) == 1
        packet = Packet.unpack(mock_interface1.outbox.popleft().data)
        p = Package.unpack(packet.body)
        tm = SpanningTree.invoke('deserialize', p.blob)
        assert tm.op == TreeOp.ASSIGN_ADDRESS, tm.op
        assert tm.claim == Packager.node_id, (tm.claim.hex(), Packager.node_id.hex())
        assert len(SpanningTree.invoke('get_current_children')) == 1
        addr = Address(tree_state(tm.claim), address=tm.address)
        assert addr.coords == local_addr.coords + [1], (addr.coords, local_addr.coords)
        SpanningTree.invoke('get_current_children').clear()

    def test_receive_ASSIGN_ADDRESS_with_worse_claim_does_not_change_address(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(SpanningTree)
        claim_score = lambda pid: SpanningTree.invoke('claim_score', pid)
        SpanningTree.invoke('start')
        local_claim_score = claim_score(Packager.node_id)
        assert len(Packager.node_id) == 32, len(Packager.node_id)

        # add a peer with the worse claim score peer_id
        peer_id = (local_claim_score + 11).to_bytes(32, 'big')
        peer_id = xor(peer_id, b'1234' * 8)
        their_score = claim_score(peer_id)
        while their_score <= local_claim_score:
            print('recalculating peer_id')
            peer_id = urandom(32)
            their_score = claim_score(peer_id)
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])

        # receive an ASSIGN_ADDRESS from that peer
        SpanningTree.invoke('start')
        tm = TreeMessage(
            TreeOp.ASSIGN_ADDRESS, now(), 0, peer_id, b'\x10' + b'\x00' * 15,
            peer_id
        )
        package = Package.from_blob(
            SpanningTree.id, SpanningTree.invoke('serialize', tm)
        )
        addr1 = Packager.node_addrs[-1]
        Packager.deliver(package, mock_interface1, b'mac0')
        addr2 = Packager.node_addrs[-1]
        assert addr1 == addr2, (addr1, addr2)

    def test_receive_ASSIGN_ADDRESS_with_better_claim_does_change_address(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(SpanningTree)
        claim_score = lambda pid: SpanningTree.invoke('claim_score', pid)
        SpanningTree.invoke('start')
        local_claim_score = claim_score(Packager.node_id)
        assert len(Packager.node_id) == 32, len(Packager.node_id)

        # add a peer with the better claim score peer_id
        peer_id = (local_claim_score - 11).to_bytes(32, 'big')
        peer_id = xor(peer_id, b'1234' * 8)
        their_score = claim_score(peer_id)
        while their_score >= local_claim_score:
            print('recalculating peer_id')
            peer_id = urandom(32)
            their_score = claim_score(peer_id)
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])

        # receive an ASSIGN_ADDRESS from that peer
        SpanningTree.invoke('start')
        tm = TreeMessage(
            TreeOp.ASSIGN_ADDRESS, now(), 0, peer_id, b'\x10' + b'\x00' * 15,
            peer_id
        )
        package = Package.from_blob(
            SpanningTree.id, SpanningTree.invoke('serialize', tm)
        )
        addr1 = Packager.node_addrs[-1]
        Packager.deliver(package, mock_interface1, b'mac0')
        addr2 = Packager.node_addrs[-1]
        assert addr1 != addr2, (addr1, addr2)

    def test_gossip_tree_message_broadcasts_gossip_message(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(SpanningTree)
        Packager.add_application(Gossip)
        SpanningTree.invoke('start')
        assert len(mock_interface1.castbox) == 0
        SpanningTree.invoke('send_gossip_tree_message')
        assert len(mock_interface1.castbox) == 1
        packet = Packet.unpack(mock_interface1.castbox.popleft().data)
        p = Package.unpack(packet.body)
        assert p.app_id == Gossip.id
        gm = Gossip.invoke('deserialize_gm', p.blob)
        assert gm.op == GossipOp.PUBLISH, gm.op
        assert gm.topic_id == SpanningTree.id, gm.topic_id
        tm = SpanningTree.invoke('deserialize', gm.data)
        assert tm.op == TreeOp.SEND, tm.op
        assert tm.claim == Packager.node_id, (tm.claim.hex(), Packager.node_id.hex())
        assert tm.address == b'\x00' * 16, tm.address.hex()
        assert tm.node_id == Packager.node_id, (tm.node_id.hex(), Packager.node_id.hex())

    def test_set_addr_sends_gossip_message(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(SpanningTree)
        Packager.add_application(Gossip)
        SpanningTree.invoke('start')
        assert len(mock_interface1.castbox) == 0
        addr = Address(tree_state(Packager.node_id), urandom(16))
        Packager.set_addr(addr)
        assert len(mock_interface1.castbox) == 1
        packet = Packet.unpack(mock_interface1.castbox.popleft().data)
        p = Package.unpack(packet.body)
        gm = Gossip.invoke('deserialize_gm', p.blob)
        assert gm.op == GossipOp.PUBLISH, gm.op
        assert gm.topic_id == SpanningTree.id, gm.topic_id

    def test_receive_gossip_message_from_peer_adds_route(self):
        assert len(Packager.routes) == 0
        Packager.add_interface(mock_interface1)
        Packager.add_application(SpanningTree)
        Packager.add_application(Gossip)
        SpanningTree.invoke('start', sub=True)
        peer_id = urandom(32)
        another_node_id = urandom(32)
        addr = Address(tree_state(another_node_id), urandom(16))
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])
        tm = TreeMessage(
            TreeOp.SEND, now(), 0, another_node_id, addr.address, another_node_id
        )
        blob = SpanningTree.invoke('serialize', tm)
        gm = GossipMessage(GossipOp.PUBLISH, SpanningTree.id, blob)
        package = Package.from_blob(
            Gossip.id, Gossip.invoke('serialize_gm', gm)
        )
        assert len(Packager.routes) == 0, Packager.routes
        Packager.deliver(package, mock_interface1, b'mac0')
        assert len(Packager.routes) == 1, Packager.routes
        assert addr in Packager.routes
        assert Packager.routes[addr] == another_node_id


if __name__ == '__main__':
    unittest.main()
