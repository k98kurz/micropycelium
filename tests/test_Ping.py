from context import *
from hashlib import sha256
from os import urandom
from random import randint
import unittest


class TestPingApplication(unittest.TestCase):
    def setUp(self) -> None:
        Packager.reset()
        Packager.add_interface(mock_interface1)
        mock_interface1.castbox.clear()
        mock_interface1.outbox.clear()
        mock_interface1.inbox.clear()
        castbox.clear()
        inbox.clear()
        outbox.clear()
        Ping.invoke('get_ping_responses').clear()
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
        Ping.invoke('get_ping_responses').clear()
        return super().tearDown()

    def test_request_sends_ping_request(self):
        Packager.add_application(Ping)
        peer_id = urandom(32)
        peer_addr = Address.from_str('1-10::')
        remote_id = urandom(32)
        remote_addr = Address.from_str('1-15::')
        local_addr = Address.from_str('1-::')
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])
        Packager.set_addr(local_addr)
        Packager.add_route(peer_id, peer_addr)
        Packager.add_route(remote_id, remote_addr)
        assert len(mock_interface1.outbox) == 0
        Ping.invoke('request', remote_id)
        assert len(mock_interface1.outbox) == 1
        packet = Packet.unpack(mock_interface1.outbox.popleft().data)
        p = Package.unpack(packet.body)
        pm = Ping.invoke('deserialize_pm', p.blob)
        assert pm.op == PingOp.REQUEST, pm.op
        assert pm.node_id == Packager.node_id, (pm.node_id.hex(), Packager.node_id.hex())
        assert pm.address == local_addr.address, (pm.address.hex(), local_addr.address.hex())
        assert pm.tree_state == Packager.node_addrs[-1].tree_state

    def test_respond_sends_ping_response(self):
        Packager.add_application(Ping)
        peer_id = urandom(32)
        peer_addr = Address.from_str('1-10::')
        remote_id = urandom(32)
        remote_addr = Address.from_str('1-15::')
        local_addr = Address.from_str('1-::')
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])
        Packager.set_addr(local_addr)
        Packager.add_route(peer_id, peer_addr)
        Packager.add_route(remote_id, remote_addr)
        assert len(mock_interface1.outbox) == 0
        pm = PingMessage(
            PingOp.REQUEST,
            randint(0, 255),
            dTree,
            int(time()),
            0,
            0,
            remote_addr.tree_state,
            remote_addr.address,
            remote_id
        )
        assert len(mock_interface1.outbox) == 0
        Ping.invoke('respond', pm)
        assert len(mock_interface1.outbox) == 1
        packet = Packet.unpack(mock_interface1.outbox.popleft().data)
        p = Package.unpack(packet.body)
        pm = Ping.invoke('deserialize_pm', p.blob)
        assert pm.op == PingOp.RESPOND, pm.op
        assert pm.metric == dTree
        assert pm.ts1 > 0
        assert pm.ts2 > 0
        assert pm.ts3 == 0
        assert pm.node_id == remote_id, (pm.node_id.hex(), remote_id.hex())
        assert pm.address == remote_addr.address, (pm.address.hex(), remote_addr.address.hex())
        assert pm.tree_state == remote_addr.tree_state

    def test_receive_ping_request_sends_ping_response(self):
        Packager.add_application(Ping)
        peer_id = urandom(32)
        peer_addr = Address.from_str('1-10::')
        remote_id = urandom(32)
        remote_addr = Address.from_str('1-15::')
        local_addr = Address.from_str('1-::')
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])
        Packager.set_addr(local_addr)
        Packager.add_route(peer_id, peer_addr)
        Packager.add_route(remote_id, remote_addr)
        assert len(mock_interface1.outbox) == 0
        ts1 = int(time())
        pm = PingMessage(
            PingOp.REQUEST,
            randint(0, 255),
            dCPL,
            ts1,
            0,
            0,
            remote_addr.tree_state,
            remote_addr.address,
            remote_id
        )
        assert len(mock_interface1.outbox) == 0
        package = Package.from_blob(
            Ping.id, Ping.invoke('serialize_pm', pm)
        )
        Packager.deliver(package, mock_interface1, b'mac0')
        assert len(mock_interface1.outbox) == 1
        packet = Packet.unpack(mock_interface1.outbox.popleft().data)
        p = Package.unpack(packet.body)
        pm = Ping.invoke('deserialize_pm', p.blob)
        assert pm.op == PingOp.RESPOND, pm.op
        assert pm.metric == dCPL
        assert pm.ts1 == ts1
        assert pm.ts2 > 0
        assert pm.ts3 == 0
        assert pm.node_id == remote_id, (pm.node_id.hex(), remote_id.hex())
        assert pm.address == remote_addr.address, (pm.address.hex(), remote_addr.address.hex())
        assert pm.tree_state == remote_addr.tree_state

    def test_receive_ping_response_adds_to_deque(self):
        Packager.add_application(Ping)
        peer_id = urandom(32)
        peer_addr = Address.from_str('1-10::')
        remote_id = urandom(32)
        remote_addr = Address.from_str('1-15::')
        local_addr = Address.from_str('1-::')
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])
        Packager.set_addr(local_addr)
        Packager.add_route(peer_id, peer_addr)
        Packager.add_route(remote_id, remote_addr)
        assert len(Ping.invoke('get_ping_responses')) == 0
        ts1 = int(time())-2
        ts2 = int(time())-1
        pm = PingMessage(
            PingOp.RESPOND,
            randint(0, 255),
            dTree,
            ts1,
            ts2,
            0,
            local_addr.tree_state,
            local_addr.address,
            Packager.node_id
        )
        blob = Ping.invoke('serialize_pm', pm)
        package = Package.from_blob(
            Ping.id, blob
        )
        Packager.deliver(package, mock_interface1, b'mac0')
        assert len(Ping.invoke('get_ping_responses')) == 1
        pm = Ping.invoke('get_ping_responses').popleft()
        assert pm.op == PingOp.RESPOND, pm.op
        assert pm.ts1 == ts1
        assert pm.ts2 == ts2
        assert pm.ts3 >= ts2
        assert pm.node_id == Packager.node_id, (pm.node_id.hex(), Packager.node_id.hex())
        assert pm.address == local_addr.address, (pm.address.hex(), local_addr.address.hex())
        assert pm.tree_state == local_addr.tree_state

    def test_gossip_ping_request_sends_gossip_request(self):
        Packager.add_application(Ping)
        Packager.add_application(Gossip)
        peer_id = urandom(32)
        peer_addr = Address.from_str('1-10::')
        remote_id = urandom(32)
        remote_addr = Address.from_str('1-15::')
        local_addr = Address.from_str('1-::')
        topic_id = sha256(Ping.id + remote_id).digest()[:16]
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])
        Packager.set_addr(local_addr)
        Packager.add_route(peer_id, peer_addr)
        Packager.add_route(remote_id, remote_addr)
        assert len(mock_interface1.castbox) == 0
        Ping.invoke('gossip_request', remote_id)
        assert len(mock_interface1.castbox) == 1
        packet = Packet.unpack(mock_interface1.castbox.popleft().data)
        p = Package.unpack(packet.body)
        gm = Gossip.invoke('deserialize_gm', p.blob)
        assert gm.op == GossipOp.PUBLISH, gm.op
        assert gm.topic_id == topic_id, (gm.topic_id.hex(), topic_id.hex())
        pm = Ping.invoke('deserialize_pm', gm.data)
        assert pm.op == PingOp.GOSSIP_REQUEST, pm.op
        assert pm.node_id == Packager.node_id, (pm.node_id.hex(), Packager.node_id.hex())
        assert pm.address == local_addr.address, (pm.address.hex(), local_addr.address.hex())
        assert pm.tree_state == local_addr.tree_state
        assert pm.ts1 >= int(time())-1
        assert pm.ts2 == 0
        assert pm.ts3 == 0

    def test_gossip_ping_respond_sends_gossip_respond(self):
        Packager.add_application(Ping)
        Packager.add_application(Gossip)
        peer_id = urandom(32)
        peer_addr = Address.from_str('1-10::')
        remote_id = urandom(32)
        remote_addr = Address.from_str('1-15::')
        local_addr = Address.from_str('1-::')
        topic_id = sha256(Ping.id + remote_id).digest()[:16]
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])
        Packager.set_addr(local_addr)
        Packager.add_route(peer_id, peer_addr)
        Packager.add_route(remote_id, remote_addr)
        ts1 = int(time())-1
        pm = PingMessage(
            PingOp.GOSSIP_REQUEST,
            randint(0, 255),
            dTree,
            ts1,
            0,
            0,
            remote_addr.tree_state,
            remote_addr.address,
            remote_id
        )
        assert len(mock_interface1.castbox) == 0
        Ping.invoke('gossip_respond', pm)
        assert len(mock_interface1.castbox) == 1
        packet = Packet.unpack(mock_interface1.castbox.popleft().data)
        p = Package.unpack(packet.body)
        gm = Gossip.invoke('deserialize_gm', p.blob)
        assert gm.op == GossipOp.PUBLISH, gm.op
        assert gm.topic_id == topic_id, (gm.topic_id.hex(), topic_id.hex())
        pm = Ping.invoke('deserialize_pm', gm.data)
        assert pm.op == PingOp.GOSSIP_RESPOND, pm.op
        assert pm.node_id == remote_id, (pm.node_id.hex(), remote_id.hex())
        assert pm.address == remote_addr.address, (pm.address.hex(), remote_addr.address.hex())
        assert pm.tree_state == remote_addr.tree_state
        assert pm.ts1 == ts1
        assert pm.ts2 >= ts1
        assert pm.ts3 == 0

    def test_ping_test_adds_new_events(self):
        remote_id = urandom(32)
        remote_addr = Address.from_str('1-21::')
        local_addr = Address.from_str('1-12::')
        Packager.set_addr(local_addr)
        assert len(Packager.new_events) == 0
        Ping.invoke('ping', count=5, addr=remote_addr)
        assert len(Packager.new_events) == 6
        # report event
        ev = Packager.new_events[-1]
        assert ev.args[3] == remote_addr, ev.args

    def test_gossip_ping_test_adds_new_events(self):
        remote_id = urandom(32)
        remote_addr = Address.from_str('1-21::')
        local_addr = Address.from_str('1-12::')
        Packager.set_addr(local_addr)
        assert len(Packager.new_events) == 0
        Ping.invoke('gossip_ping', remote_id, 2)
        assert len(Packager.new_events) == 3
        # report event
        ev = Packager.new_events[-1]
        assert ev.args[-2] == remote_id

    def test_report_ping_test(self):
        responses = Ping.invoke('get_ping_responses')
        nonce = randint(0, 255)
        count = 4
        timeout = 30
        half_trip = timeout/2
        ts1s = [
            int(time())-timeout*4-1,
            int(time())-timeout*3-2,
            int(time())-timeout*2+1,
            int(time())-timeout+2,
        ]
        ts2s = [
            int(time())-timeout*3-half_trip,
            int(time())-timeout*2-half_trip,
            int(time())-timeout-half_trip,
            int(time())-half_trip,
        ]
        ts3s = [
            int(time())-timeout*3-1,
            int(time())-timeout*2-2,
            int(time())-timeout+1,
            int(time())+2,
        ]
        remote_id = urandom(32)
        remote_addr = Address.from_str('1-21::')
        local_addr = Address.from_str('1-12::')
        metric = dCPL if randint(0, 1) == 0 else dTree
        mode = 'routed dCPL' if metric == dCPL else 'routed dTree'
        for i in range(count):
            responses.append(PingMessage(
                PingOp.RESPOND,
                nonce,
                metric,
                ts1s[i],
                ts2s[i],
                ts3s[i],
                local_addr.tree_state,
                local_addr.address,
                Packager.node_id
            ))
        assert len(responses) == count
        report = Ping.invoke(
            'report_ping_test', nonce, mode, 4, remote_addr
        )
        assert len(responses) == 0
        assert report['mode'] == mode
        assert report['remote'] == remote_addr
        assert report['count'] == count
        assert report['there']['avg'] == 15
        assert report['there']['min'] <= report['there']['avg']
        assert report['there']['max'] >= report['there']['avg']
        assert report['back']['avg'] == 15
        assert report['back']['min'] <= report['back']['avg']
        assert report['back']['max'] >= report['back']['avg']
        assert report['round_trip']['avg'] == 30
        assert report['round_trip']['min'] <= report['round_trip']['avg']
        assert report['round_trip']['max'] >= report['round_trip']['avg']
        assert report['success_rate'] == '100%'

        # test gossip ping report
        for i in range(count):
            responses.append(PingMessage(
                PingOp.GOSSIP_RESPOND,
                nonce,
                dCPL,
                ts1s[i],
                ts2s[i],
                ts3s[i],
                local_addr.tree_state,
                local_addr.address,
                Packager.node_id
            ))
        assert len(responses) == count
        report = Ping.invoke(
            'report_ping_test', nonce, 'gossip', 4, remote_id
        )
        assert len(responses) == 0
        assert report['mode'] == 'gossip'
        assert report['remote'] == remote_id.hex()
        assert report['success_rate'] == '100%'


if __name__ == '__main__':
    unittest.main()
