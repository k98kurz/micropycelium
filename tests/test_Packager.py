import asyncio
from binascii import crc32
from collections import deque
from context import *
from hashlib import sha256
from os import urandom
from random import randint
from time import time, sleep, time_ns
import unittest


class TestPackager(unittest.TestCase):
    def setUp(self) -> None:
        inbox.clear()
        outbox.clear()
        castbox.clear()
        app_blobs.clear()
        mock_interface1.inbox.clear()
        mock_interface1.outbox.clear()
        mock_interface1.castbox.clear()
        Packager.reset()
        return super().setUp()

    def tearDown(self) -> None:
        inbox.clear()
        outbox.clear()
        castbox.clear()
        app_blobs.clear()
        mock_interface1.inbox.clear()
        mock_interface1.outbox.clear()
        mock_interface1.castbox.clear()
        Packager.reset()
        return super().tearDown()

    def test_add_interface_remove_interface_e2e(self):
        assert len(Packager.interfaces) == 0
        Packager.add_interface(mock_interface1)
        assert len(Packager.interfaces) == 1
        Packager.remove_interface(mock_interface1)
        assert len(Packager.interfaces) == 0

    def test_add_peer_remove_peer(self):
        assert len(Packager.peers.keys()) == 0
        assert len(Packager.inverse_peers.keys()) == 0
        Packager.add_peer(b'peer0', [(b'macpeer0', mock_interface1)])
        assert len(Packager.peers.keys()) == 1
        assert len(Packager.inverse_peers.keys()) == 1
        assert Packager.inverse_peers.get((b'macpeer0', mock_interface1.id)) == b'peer0'
        Packager.remove_peer(b'peer0')
        assert len(Packager.peers.keys()) == 0
        assert len(Packager.inverse_peers.keys()) == 0

    def test_add_route_remove_route(self):
        assert len(Packager.routes.keys()) == 0
        addr = Address(0, b'\x00' * 16)
        Packager.add_peer(b'peer0', [(b'macpeer0', mock_interface1)])
        Packager.add_route(b'peer0', addr)
        assert len(Packager.routes.keys()) == 1
        Packager.remove_route(addr)
        assert len(Packager.routes.keys()) == 0

    def test_ban_unban(self):
        Packager.add_peer(b'peer0', [(b'macpeer0', mock_interface1)])
        Packager.add_route(b'peer0', Address(0, b'\x00' * 16))
        assert len(Packager.peers.keys()) == 1
        assert len(Packager.routes.keys()) == 1
        Packager.ban(b'peer0')
        assert len(Packager.peers.keys()) == 0
        assert len(Packager.routes.keys()) == 0
        Packager.add_peer(b'peer0', [(b'macpeer0', mock_interface1)])
        Packager.add_route(b'peer0', Address(0, b'\x00' * 16))
        assert len(Packager.peers.keys()) == 0
        assert len(Packager.routes.keys()) == 0
        Packager.unban(b'peer0')
        Packager.add_peer(b'peer0', [(b'macpeer0', mock_interface1)])
        Packager.add_route(b'peer0', Address(0, b'\x00' * 16))
        assert len(Packager.peers.keys()) == 1
        assert len(Packager.routes.keys()) == 1

    def test_set_addr(self):
        assert len(Packager.node_addrs) == 0
        Packager.set_addr(Address(0, b'\x00' * 16))
        assert len(Packager.node_addrs) == 1
        Packager.set_addr(Address(1, b'\x01' * 16))
        assert len(Packager.node_addrs) == 2
        Packager.set_addr(Address(2, b'\x02' * 16))
        assert len(Packager.node_addrs) == 2
        assert Packager.node_addrs[0].tree_state == 1
        assert Packager.node_addrs[1].tree_state == 2

    def test_dTree_routing(self):
        # example network structure from the VOUTE paper for routing s -> e:
        # s [1] <-> r [] <-> e [2] <-> [2, 1] <-> [2, 1, 1] <-> u [2, 1, 1, 1]
        # s <-> u
        tree_state = 0
        Packager.node_id = b'0' * 32
        local_addr = Address(tree_state, coords=[2,2,3])
        peer1_id = b'1' * 32
        peer2_id = b'2' * 32
        peer1_addr = Address(tree_state, coords=[2,2,4])
        peer2_addr = Address(tree_state, coords=[2,5])
        Packager.add_peer(peer1_id, [(b'mac_peer_r', mock_interface1)])
        Packager.add_peer(peer2_id, [(b'mac_peer_u', mock_interface1)])
        Packager.add_route(peer1_id, peer1_addr)
        Packager.add_route(peer2_id, peer2_addr)
        Packager.set_addr(local_addr)

        to_addr = Address(tree_state, coords=[2,5,1])
        mac, intrfc, peer = Packager.get_interface(to_addr=to_addr, metric=dTree)
        assert mac == b'mac_peer_u', mac
        assert intrfc == mock_interface1
        assert peer.id == peer2_id, peer

        to_addr = Address(tree_state, coords=[2,2,4])
        mac, intrfc, peer = Packager.get_interface(to_addr=to_addr, metric=dTree)
        assert mac == b'mac_peer_r', mac
        assert intrfc == mock_interface1
        assert peer.id == peer1_id, peer

        to_addr = Address(tree_state, coords=[2,2,3])
        mac, intrfc, peer = Packager.get_interface(to_addr=to_addr, metric=dTree)

    def test_dTree_example_from_VOUTE_paper(self):
        # example network structure from the VOUTE paper for routing s -> e:
        # s [1] <-> r [] <-> e [2] <-> [2, 1] <-> [2, 1, 1] <-> u [2, 1, 1, 1]
        # s <-> u
        tree_state = 0
        local_addr = Address(tree_state, coords=[1])
        peer1_id = b'1' * 32
        peer2_id = b'2' * 32
        peer1_addr = Address(tree_state, coords=[]) # r
        peer2_addr = Address(tree_state, coords=[2, 1, 1, 1]) # u
        Packager.add_peer(peer1_id, [(b'mac_peer_r', mock_interface1)])
        Packager.add_peer(peer2_id, [(b'mac_peer_u', mock_interface1)])
        Packager.add_route(peer1_id, peer1_addr)
        Packager.add_route(peer2_id, peer2_addr)
        Packager.set_addr(local_addr)

        to_addr = Address(tree_state, coords=[2]) # e
        mac, intrfc, peer = Packager.get_interface(to_addr=to_addr, metric=dTree)
        assert mac == b'mac_peer_r', mac
        assert intrfc == mock_interface1
        assert peer.id == peer1_id, peer

    def test_dCPL_routing(self):
        tree_state = 0
        Packager.node_id = b'0' * 32
        local_addr = Address(tree_state, coords=[2,2,3])
        peer1_id = b'1' * 32
        peer2_id = b'2' * 32
        peer1_addr = Address(tree_state, coords=[2,2,4])
        peer2_addr = Address(tree_state, coords=[2,5])
        Packager.add_peer(peer1_id, [(b'mac_peer_r', mock_interface1)])
        Packager.add_peer(peer2_id, [(b'mac_peer_u', mock_interface1)])
        Packager.add_route(peer1_id, peer1_addr)
        Packager.add_route(peer2_id, peer2_addr)
        Packager.set_addr(local_addr)

        to_addr = Address(tree_state, coords=[2,5,1])
        mac, intrfc, peer = Packager.get_interface(to_addr=to_addr, metric=dCPL)
        assert mac == b'mac_peer_u', mac
        assert intrfc == mock_interface1
        assert peer.id == peer2_id, peer

        to_addr = Address(tree_state, coords=[2,2,4])
        mac, intrfc, peer = Packager.get_interface(to_addr=to_addr, metric=dCPL)
        assert mac == b'mac_peer_r', mac
        assert intrfc == mock_interface1
        assert peer.id == peer1_id, peer

        to_addr = Address(tree_state, coords=[2,2,3])
        mac, intrfc, peer = Packager.get_interface(to_addr=to_addr, metric=dCPL)

    def test_dCPL_example_from_VOUTE_paper(self):
        # example network structure from the VOUTE paper for routing s -> e:
        # s [1] <-> r [] <-> e [2] <-> [2, 1] <-> [2, 1, 1] <-> u [2, 1, 1, 1]
        # s <-> u
        tree_state = 0
        local_addr = Address(tree_state, coords=[1])
        peer1_id = b'1' * 32
        peer2_id = b'2' * 32
        peer1_addr = Address(tree_state, coords=[]) # r
        peer2_addr = Address(tree_state, coords=[2, 1, 1, 1]) # u
        Packager.add_peer(peer1_id, [(b'mac_peer_r', mock_interface1)])
        Packager.add_peer(peer2_id, [(b'mac_peer_u', mock_interface1)])
        Packager.add_route(peer1_id, peer1_addr)
        Packager.add_route(peer2_id, peer2_addr)
        Packager.set_addr(local_addr)

        to_addr = Address(tree_state, coords=[2]) # e
        mac, intrfc, peer = Packager.get_interface(to_addr=to_addr, metric=dCPL)
        assert mac == b'mac_peer_u', mac
        assert intrfc == mock_interface1
        assert peer.id == peer2_id, peer

    def test_broadcast_small(self):
        Packager.add_interface(mock_interface1)
        assert len(Packager.interfaces) == 1
        assert len(castbox) == 0
        Packager.broadcast(b'app 9659b56ae1d8', b'test')
        asyncio.run(Packager.process())
        assert len(castbox) == 1, castbox

    def test_broadcast_large(self):
        Packager.add_interface(mock_interface1)
        assert len(castbox) == 0
        app_id = b'app 9659b56ae1d8'
        blob = b''.join([(i%256).to_bytes(1, 'big') for i in range(300)])
        Packager.broadcast(app_id, blob)
        asyncio.run(Packager.process())
        asyncio.run(Packager.process())
        asyncio.run(Packager.process())
        assert len(castbox) == 2, (len(castbox), len(castbox[0].data))
        packet = Packet.unpack(castbox.popleft().data)
        sequence = Sequence(
            packet.schema,
            packet.fields['seq_id'],
            seq_size=packet.fields['seq_size']+1
        )
        sequence.add_packet(packet)
        while len(castbox):
            packet = Packet.unpack(castbox.popleft().data)
            sequence.add_packet(packet)
        assert len(sequence.get_missing()) == 0, sequence.get_missing()
        package = Package.from_sequence(sequence)
        assert package.app_id == app_id, (app_id, package.app_id)
        assert package.blob == blob

    def test_send_local_small(self):
        Packager.add_interface(mock_interface1)
        assert len(Packager.interfaces) == 1
        assert len(outbox) == 0
        Packager.add_peer(b'123', [(b'macpeer0', mock_interface1)])
        assert Packager.send(b'app 9659b56ae1d8', b'test', b'123')
        asyncio.run(Packager.process())
        assert len(outbox) == 1, outbox
        p = Packet.unpack(outbox.popleft().data)
        assert p.id == 0

    def test_send_local_large(self):
        Packager.add_interface(mock_interface1)
        assert len(Packager.interfaces) == 1
        assert len(outbox) == 0
        app_id = b'app 9659b56ae1d8'
        blob = b''.join([(i%256).to_bytes(1, 'big') for i in range(300)])
        node_id = b'123'
        Packager.add_peer(node_id, [(b'macpeer0', mock_interface1)])
        assert Packager.send(app_id, blob, node_id)
        asyncio.run(Packager.process())
        asyncio.run(Packager.process())
        asyncio.run(Packager.process())
        assert len(outbox) == 2, (len(outbox), len(outbox[0].data))
        packet = Packet.unpack(outbox.popleft().data)
        sequence = Sequence(
            packet.schema,
            packet.fields['seq_id'],
            seq_size=packet.fields['seq_size']+1
        )
        sequence.add_packet(packet)
        while len(outbox):
            packet = Packet.unpack(outbox.popleft().data)
            sequence.add_packet(packet)
        assert len(sequence.get_missing()) == 0, sequence.get_missing()
        package = Package.from_sequence(sequence)
        assert package.app_id == app_id, (app_id, package.app_id)
        assert package.blob == blob

    def test_send_route_small(self):
        Packager.add_interface(mock_interface1)
        assert len(Packager.interfaces) == 1
        assert len(outbox) == 0
        app_id = b'app 9659b56ae1d8'
        blob = b'test'
        peer_id = b'123'
        peer_addr = Address(0, b'123' + b'\x00' * 13)
        node_id = b'321'
        node_addr = Address(0, b'321' + b'\x00' * 13)
        Packager.set_addr(Address(0, b'node0' + b'\x00' * 11))
        Packager.add_peer(peer_id, [(b'macpeer0', mock_interface1)])
        Packager.add_route(peer_id, peer_addr)
        Packager.add_route(node_id, node_addr)
        assert Packager.send(app_id, blob, node_id)
        asyncio.run(Packager.process())
        assert len(outbox) == 1, outbox

    def test_send_route_large(self):
        Packager.add_interface(mock_interface1)
        assert len(Packager.interfaces) == 1
        assert len(outbox) == 0
        app_id = b'app 9659b56ae1d8'
        blob = b''.join([(i%256).to_bytes(1, 'big') for i in range(300)])
        peer_id = b'123'
        peer_addr = Address(0, b'123' + b'\x00' * 13)
        node_id = b'321'
        node_addr = Address(0, b'321' + b'\x00' * 13)
        Packager.set_addr(Address(0, b'node0' + b'\x00' * 11))
        Packager.add_peer(peer_id, [(b'macpeer0', mock_interface1)])
        Packager.add_route(peer_id, peer_addr)
        Packager.add_route(node_id, node_addr)
        assert Packager.send(app_id, blob, node_id)
        asyncio.run(Packager.process())
        asyncio.run(Packager.process())
        asyncio.run(Packager.process())
        assert len(outbox) == 2, (len(outbox), len(outbox[0].data))
        packet = Packet.unpack(outbox.popleft().data)
        sequence = Sequence(
            packet.schema,
            packet.fields['seq_id'],
            seq_size=packet.fields['seq_size']+1
        )
        sequence.add_packet(packet)
        while len(outbox):
            packet = Packet.unpack(outbox.popleft().data)
            sequence.add_packet(packet)
        assert len(sequence.get_missing()) == 0, sequence.get_missing()
        package = Package.from_sequence(sequence)
        assert package.app_id == app_id, (app_id, package.app_id)
        assert package.blob == blob

    def test_get_interface_and_send_packet(self):
        Packager.add_interface(mock_interface1)
        Packager.add_interface(mock_interface2)
        assert len(Packager.interfaces) == 2
        Packager.add_peer(b'123', [(b'macpeer0', mock_interface1)])
        intrfc = Packager.get_interface(b'123')
        assert type(intrfc) is tuple
        assert len(intrfc) == 3
        assert intrfc[0] == b'macpeer0'
        assert intrfc[1] == mock_interface1
        assert type(intrfc[2]) is Peer

        packet = Packet(
            get_schema(SCHEMA_IDS[0]),
            Flags(0),
            {
                'body': b'test',
                'packet_id': 0,
            }
        )
        assert len(outbox) == 0
        # prevent mock_interface2 from receiving the datagram
        Packager.remove_interface(mock_interface2)
        assert Packager.send_packet(packet, b'123')
        asyncio.run(Packager.process())
        assert len(outbox) == 1, outbox

    def test_send_when_not_Peer_can_tx_queues_datagram_sends_RNS(self):
        # add application, network interface, and peer
        Packager.add_application(test_app)
        Packager.add_interface(mock_interface1)
        Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])
        peer = list(Packager.peers.items())[0][1]
        # disable direct transmission
        peer.last_rx = int(time()-1) * 1000

        # try to send a Package, but it should queue the packet and send RNS
        assert len(Packager.new_events) == 0, len(Packager.new_events)
        assert len(peer.queue) == 0
        assert len(mock_interface1.outbox) == 0
        assert Packager.send(test_app.id, b'test', b'peer0')
        assert len(mock_interface1.outbox) == 1
        dgram = mock_interface1.outbox.popleft()
        packet = Packet.unpack(dgram.data)
        assert packet.flags.rns, (packet.flags, packet.body)
        assert len(peer.queue) == 1

        # event to resend RNS should be queued with retry of MODEM_INTERSECT_RTX_TIMES-1
        # send retry event should also be queued
        assert len(Packager.new_events) == 2, len(Packager.new_events)
        asyncio.run(Packager.process())
        assert len(Packager.new_events) == 0
        eid = b'rnspeer0' + mock_interface1.id
        assert eid in Packager.schedule
        event = Packager.schedule[eid]
        assert event.kwargs['retries'] == MODEM_INTERSECT_RTX_TIMES-1, \
            event

        # wait MODEM_INTERSECT_INTERVAL and process again; it should resend the RNS
        sleep(MODEM_INTERSECT_INTERVAL/1000)
        asyncio.run(Packager.process())
        assert len(mock_interface1.outbox) == 1
        dgram = mock_interface1.outbox.popleft()
        packet = Packet.unpack(dgram.data)
        assert packet.flags.rns, (packet.flags, packet.body)

        # event to resend RNS should be queued with retry of MODEM_INTERSECT_RTX_TIMES-2
        assert len(Packager.new_events) == 1
        asyncio.run(Packager.process())
        assert len(Packager.new_events) == 0
        eid = b'rnspeer0' + mock_interface1.id
        assert eid in Packager.schedule
        event = Packager.schedule[eid]
        assert event.kwargs['retries'] == MODEM_INTERSECT_RTX_TIMES-2, \
            event

        # simulate sending NIA
        flags = Flags(0)
        flags.nia = True
        dgram = Datagram(
            Packet(
                mock_interface1.default_schema,
                flags,
                {
                    'packet_id': 0,
                    'body': b'',
                }
            ).pack(),
            mock_interface1.id,
            b'mac0'
        )
        inbox.append(dgram)
        # receiving via process should set can_tx to True and send the packet
        assert eid in Packager.schedule
        asyncio.run(Packager.process())
        assert peer.can_tx
        assert len(mock_interface1.outbox) == 1
        asyncio.run(Packager.process())
        assert eid not in Packager.schedule # RNS schedule dropped
        assert len(Packager.new_events) == 0
        assert len(mock_interface1.outbox) == 0
        assert len(outbox) == 1
        dgram = outbox.popleft()
        packet = Packet.unpack(dgram.data)
        assert not packet.flags.rns, (packet.flags, packet.body)
        assert len(packet.body) == 36 and packet.body[-4:] == b'test', \
            (len(packet.body), packet.body)

    def test_receive_wrong_version_drops_packet(self):
        # add application, network interface, and peer
        received = []
        hook = lambda *args, **__: received.append(args)
        assert 'receive' not in test_app._hooks
        test_app.add_hook('receive', hook)
        Packager.add_application(test_app)
        Packager.add_interface(mock_interface1)
        Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])
        blob = Package.from_blob(test_app.id, b'hello world').pack()

        # receive a packet with the correct version
        packet = Packet(
            get_schema(SCHEMA_IDS[0]),
            Flags(0),
            {
                'body': blob,
                'packet_id': 0,
            }
        )
        inbox.append(Datagram(packet.pack(), mock_interface1.id, b'mac0'))
        asyncio.run(Packager.process())
        assert len(inbox) == 0, len(inbox)
        assert len(received) == 1, received
        assert received[0][1] == b'hello world', received[0][1]
        received.clear()

        # receive a packet with the wrong version
        packet = Packet(
            get_schema(SCHEMA_IDS[0]),
            Flags(0),
            {
                'body': blob,
                'packet_id': 0,
            }
        )
        packet.schema.version += 1
        inbox.append(Datagram(packet.pack(), mock_interface1.id, b'mac0'))
        asyncio.run(Packager.process())
        assert len(inbox) == 0, len(inbox)
        assert len(received) == 0, received
        del test_app._hooks['receive']

    def test_receive_can_relay_packets_with_to_addr_but_without_ttl(self):
        schemas = [
            s for s in get_schemas(SCHEMA_IDS)
            if schema_has(s, 'to_addr') and schema_lacks(s, 'ttl')
        ]
        schema = schemas[0]
        Packager.add_interface(mock_interface1)

        # copy network configuration from VOUTE paper example
        # example network structure from the VOUTE paper for routing s -> e:
        # s [1] <-> r [] <-> e [2] <-> [2, 1] <-> v [2, 1, 1] <-> u [2, 1, 1, 1]
        # s <-> u
        tree_state = 69
        local_addr = Address(tree_state, coords=[1])
        Packager.node_id = b'0' * 32
        Packager.set_addr(local_addr)

        # r
        peer1 = Peer(
            b'1' * 32,
            [(b'mac_peer_r', mock_interface1)]
        )
        peer1_addr = Address(tree_state, coords=[])
        Packager.add_peer(peer1.id, peer1.interfaces)
        Packager.add_route(peer1.id, peer1_addr)

        # u
        peer2 = Peer(
            b'2' * 32,
            [(b'mac_peer_u', mock_interface1)]
        )
        peer2_addr = Address(tree_state, coords=[2, 1, 1, 1])
        Packager.add_peer(peer2.id, peer2.interfaces)
        Packager.add_route(peer2.id, peer2_addr)

        # send from u to r
        blob = Package.from_blob(test_app.id, b'hello world').pack()
        from_addr = peer2_addr
        to_addr = peer1_addr
        packet = Packet(
            schema,
            Flags(0),
            {
                'packet_id': 0,
                'tree_state': tree_state,
                'to_addr': to_addr.address,
                'from_addr': from_addr.address,
                'body': blob,
            }
        )
        assert len(mock_interface1.outbox) == 0
        inbox.append(Datagram(packet.pack(), mock_interface1.id, peer2.interfaces[0][0]))
        asyncio.run(Packager.process())
        assert len(mock_interface1.outbox) == 1
        dgram = mock_interface1.outbox.popleft()
        # delivers to r
        assert dgram.addr == peer1.interfaces[0][0], (dgram, Packet.unpack(dgram.data))

        # attempt to send from u to e; must send an error back to u
        packet.fields['to_addr'] = Address(tree_state, coords=[2]).address
        assert len(mock_interface1.outbox) == 0
        inbox.append(Datagram(packet.pack(), mock_interface1.id, peer2.interfaces[0][0]))
        asyncio.run(Packager.process())
        assert len(mock_interface1.outbox) == 1, len(mock_interface1.outbox)
        dgram = mock_interface1.outbox.popleft()
        assert Packet.unpack(dgram.data).flags.error
        assert dgram.addr == peer2.interfaces[0][0], (dgram, Packet.unpack(dgram.data))

    def test_receive_routes_properly_e2e(self):
        # add application and network interface
        Packager.add_interface(mock_interface1)

        # copy network configuration from VOUTE paper example
        # example network structure from the VOUTE paper for routing s -> e:
        # s [1] <-> r [] <-> e [2] <-> [2, 1] <-> v [2, 1, 1] <-> u [2, 1, 1, 1]
        # s <-> u
        tree_state = 0
        local_addr = Address(tree_state, coords=[1])
        Packager.node_id = b'0' * 32
        Packager.set_addr(local_addr)

        # r
        peer1 = Peer(
            b'1' * 32,
            [(b'mac_peer_r', mock_interface1)]
        )
        peer1_addr = Address(tree_state, coords=[])
        Packager.add_peer(peer1.id, peer1.interfaces)
        Packager.add_route(peer1.id, peer1_addr)

        # u
        peer2 = Peer(
            b'2' * 32,
            [(b'mac_peer_u', mock_interface1)]
        )
        peer2_addr = Address(tree_state, coords=[2, 1, 1, 1])
        Packager.add_peer(peer2.id, peer2.interfaces)
        Packager.add_route(peer2.id, peer2_addr)

        # child node routing through the local node
        peer3 = Peer(
            b'3' * 32,
            [(b'mac_child_1', mock_interface1)]
        )
        peer3_addr = Address(tree_state, coords=[1, 1])
        Packager.add_peer(peer3.id, peer3.interfaces)
        Packager.add_route(peer3.id, peer3_addr)

        # send to e
        to_addr = Address(tree_state, coords=[2])
        blob = Package.from_blob(test_app.id, b'hello world').pack()
        packet = Packet(
            get_schemas(SCHEMA_IDS_SUPPORT_ROUTING)[0],
            Flags(0),
            {
                'packet_id': 0,
                'ttl': 250,
                'tree_state': tree_state,
                'to_addr': to_addr.address,
                'from_addr': peer3_addr.address,
                'body': blob,
            }
        )

        # first test dTree, the default mode
        assert len(mock_interface1.outbox) == 0
        inbox.append(Datagram(packet.pack(), mock_interface1.id, peer3.interfaces[0][0]))
        asyncio.run(Packager.process())
        assert len(mock_interface1.outbox) == 1
        dgram = mock_interface1.outbox.popleft()
        # routes through r
        assert dgram.addr == peer1.interfaces[0][0]

        # now test dCPL, the second mode
        packet.flags.mode = 1
        assert len(mock_interface1.outbox) == 0
        inbox.append(Datagram(packet.pack(), mock_interface1.id, peer3.interfaces[0][0]))
        asyncio.run(Packager.process())
        assert len(mock_interface1.outbox) == 1
        dgram = mock_interface1.outbox.popleft()
        # routes through u
        assert dgram.addr == peer2.interfaces[0][0]

        # v; to test a new shortcut for dCPL
        peer4 = Peer(
            b'4' * 32,
            [(b'mac_peer_u', mock_interface1)]
        )
        peer4_addr = Address(tree_state, coords=[2, 1, 1, 1])
        Packager.add_peer(peer4.id, peer4.interfaces)
        Packager.add_route(peer4.id, peer4_addr)

        # test dCPL again after adding shortcut
        assert len(mock_interface1.outbox) == 0
        inbox.append(Datagram(packet.pack(), mock_interface1.id, peer3.interfaces[0][0]))
        asyncio.run(Packager.process())
        assert len(mock_interface1.outbox) == 1
        dgram = mock_interface1.outbox.popleft()
        # routes through v now
        assert dgram.addr == peer4.interfaces[0][0]

        # route to r
        packet.fields['to_addr'] = peer1_addr.address
        assert len(mock_interface1.outbox) == 0
        inbox.append(Datagram(packet.pack(), mock_interface1.id, peer3.interfaces[0][0]))
        asyncio.run(Packager.process())
        assert len(mock_interface1.outbox) == 1
        dgram = mock_interface1.outbox.popleft()
        # should send directly to r
        assert dgram.addr == peer1.interfaces[0][0]

    def test_send_routes_properly_e2e(self):
        # add application and network interface
        Packager.add_interface(mock_interface1)

        # copy network configuration from test devices
        # a (118-10::) <-> r (118-::) <-> u (118-20::)
        tree_state = 118
        local_addr = Address(tree_state, coords=[1])
        Packager.node_id = b'0' * 32
        Packager.set_addr(local_addr)

        # r
        peer1 = Peer(
            b'1' * 32,
            [(b'mac_peer_r', mock_interface1)]
        )
        peer1_addr = Address(tree_state, coords=[])
        Packager.add_peer(peer1.id, peer1.interfaces)
        Packager.add_route(peer1.id, peer1_addr)

        # u
        node2 = Peer(
            b'2' * 32,
            [(b'mac_peer_u', mock_interface1)]
        )
        node2_addr = Address(tree_state, coords=[2])

        # add more nodes that should be ignored
        peer3 = Peer(
            b'3' * 32,
            [(b'mac_child_1', mock_interface1)]
        )
        peer3_addr = Address(tree_state, coords=[1, 1])
        Packager.add_peer(peer3.id, peer3.interfaces)
        Packager.add_route(peer3.id, peer3_addr)

        peer4 = Peer(
            b'4' * 32,
            [(b'mac_peer_u', mock_interface1)]
        )
        peer4_addr = Address(tree_state, coords=[3])
        Packager.add_peer(peer4.id, peer4.interfaces)
        Packager.add_route(peer4.id, peer4_addr)

        # a sends to u; test dTree first
        to_addr = node2_addr
        assert Packager.send(test_app.id, b'hello world', to_addr=to_addr)
        assert len(mock_interface1.outbox) == 1
        # should route through r
        dgram = mock_interface1.outbox.popleft()
        assert dgram.addr == peer1.interfaces[0][0], \
            (dgram.addr, peer1.interfaces[0][0])
        p = Packet.unpack(dgram.data)
        assert p.schema.id in SCHEMA_IDS_SUPPORT_ROUTING, p.schema.id
        assert p.fields['from_addr'] == local_addr.address
        assert p.fields['to_addr'] == to_addr.address

        # now test dCPL, the second mode
        assert Packager.send(test_app.id, b'hello world', to_addr=to_addr, metric=dCPL)
        assert len(mock_interface1.outbox) == 1
        dgram = mock_interface1.outbox.popleft()
        # routes through r
        assert dgram.addr == peer1.interfaces[0][0], \
            (dgram.addr, peer1.interfaces[0][0])

    def test_receive_RNS_sends_NIA(self):
        # add application, network interface, and peer
        Packager.add_application(test_app)
        Packager.add_interface(mock_interface1)
        Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])

        # simulate sending RNS from the peer
        flags = Flags(0)
        flags.rns = True
        inbox.append(Datagram(
            Packet(
                mock_interface1.default_schema,
                flags,
                {
                    'packet_id': 0,
                    'body': b'',
                }
            ).pack(),
            mock_interface1.id,
            b'mac0'
        ))
        assert len(mock_interface1.outbox) == 0
        asyncio.run(Packager.process())
        assert len(mock_interface1.outbox) == 1
        assert len(outbox) == 0
        asyncio.run(Packager.process())
        assert len(mock_interface1.outbox) == 0
        assert len(outbox) == 1
        dgram = outbox.popleft()
        assert dgram.intrfc_id == mock_interface1.id
        assert dgram.addr == b'mac0'
        p = Packet.unpack(dgram.data)
        assert p.flags.nia

    def test_receive_NIA_prevents_RNS(self):
        # add application
        ...

    def test_modem_sleep_basic(self):
        # set up a logging event that shuts down after collecting 6 timestamps
        log = []
        now = lambda: int(time()*1000)
        def callback():
            log.append(now())
            if len(log) > 5:
                return Packager.stop()
            Packager.new_events.append(Event(
                now() + 10,
                b'log',
                callback
            ))

        Packager.new_events.append(Event(
            now() + 10,
            b'log',
            callback
        ))
        asyncio.run(Packager.work(use_modem_sleep=True))
        logdiff = []
        for i in range(1, len(log)):
            logdiff.append(log[i] - log[i-1])
        sub20s = [i for i in logdiff if i < 20]
        over90s = [i for i in logdiff if i >= 90]
        assert len(sub20s) == len(logdiff) - 1
        assert len(over90s) == 1

    def test_modem_sleep_skips_after_rx_or_tx(self):
        # set up a logging event that shuts down after collecting 6 timestamps
        log = []
        now = lambda: int(time()*1000)
        peer_id = b'peer0'
        peer_mac = b'mac0'
        def callback():
            log.append(now())
            if len(log) > 5:
                return Packager.stop()
            Packager.new_events.append(Event(
                now() + 10,
                b'log',
                callback
            ))
            Packager.send(test_app.id, b'hello world', peer_id)

        Packager.add_interface(mock_interface1)
        Packager.add_peer(peer_id, [(peer_mac, mock_interface1)])
        Packager.add_application(test_app)
        Packager.new_events.append(Event(
            now() + 10,
            b'log',
            callback
        ))
        asyncio.run(Packager.work(use_modem_sleep=True))
        logdiff = []
        for i in range(1, len(log)):
            logdiff.append(log[i] - log[i-1])
        sub20s = [i for i in logdiff if i < 20]
        over90s = [i for i in logdiff if i >= 90]
        assert len(sub20s) == len(logdiff)
        assert len(over90s) == 0
        assert len(Packager.sleepskip) > 0

    def test_modem_sleep_wake_interfaces(self):
        mock_interface1.configure({'awake': False})
        assert config['awake'] is False
        mock_interface1.wake()
        assert config['awake'] is True

        Packager.add_interface(mock_interface1)
        mock_interface1.configure({'awake': False})
        mock_interface1.add_hook('wake', lambda *_, **__: Packager.stop())
        asyncio.run(Packager.work(use_modem_sleep=True))
        assert config['awake'] is True

    def test_event_handling_in_work(self):
        now = int(time())
        log = []
        def logcallback(count: int):
            log.append(int(time()*1000))
            if count > 1:
                return
            event = Event(
                (now-1)*1000,
                b'log',
                logcallback,
                count+1
            )
            Packager.queue_event(event)

        Packager.queue_event(Event(
            (now+1)*1000,
            b'test',
            Packager.stop,
        ))
        Packager.queue_event(Event(
            (now-1)*1000,
            b'log',
            logcallback,
            0
        ))
        assert len(log) == 0
        assert not Packager.running
        asyncio.run(Packager.work())
        assert not Packager.running
        assert now < int(time()) <= now + 2
        assert len(log) >= 2, len(log) # async is somewhat random
        assert len(Packager.schedule.keys()) == 0

        # test event cancellation
        def cancelcallback(eid: bytes):
            Packager.cancel_events.append(eid)

        def logcallback2(count: int):
            logcallback(count)
            cancelcallback(b'log')

        log.clear()
        now = int(time())
        Packager.queue_event(Event(
            (now+1)*1000,
            b'test',
            Packager.stop,
        ))
        Packager.queue_event(Event(
            (now-1)*1000,
            b'log',
            logcallback2,
            0
        ))
        asyncio.run(Packager.work())
        assert now < int(time()) <= now + 2
        assert len(log) == 1, log # the recurring event should have been canceled
        assert len(Packager.schedule.keys()) == 0

    def test_deliver(self):
        package = Package.from_blob(test_app.id, b'hello world')
        Packager.add_application(test_app)
        assert len(app_blobs) == 0
        Packager.deliver(package, mock_interface1, b'mac0')
        assert len(app_blobs) == 1

    def test_sequence_synchronization_e2e_success(self):
        # prepare the sequence
        blob = b''.join([(i%256).to_bytes(1, 'big') for i in range(400)])
        package = Package.from_blob(test_app.id, blob).pack()
        schema_ids = list(set(SCHEMA_IDS_SUPPORT_SEQUENCE).difference(
            SCHEMA_IDS_SUPPORT_ROUTING
        ).difference(SCHEMA_IDS_SUPPORT_CHECKSUM))
        schemas = get_schemas(schema_ids)
        schemas.sort(key=lambda s: s.max_body, reverse=True)
        schema = schemas[0]
        seq = Sequence(schema, 0, data_size=len(package))
        seq.set_data(package)
        assert seq.seq_size == 2

        # add application, network interface, and peer
        Packager.add_application(test_app)
        Packager.add_interface(mock_interface1)
        Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])

        # start sequence transmission with first packet
        flags = Flags(0)
        inbox.append(Datagram(
            seq.get_packet(0, flags, {}).pack(),
            mock_interface1.id,
            b'mac0',
        ))

        assert len(Packager.new_events) == 0
        assert len(Packager.schedule.keys()) == 0
        assert len(Packager.in_seqs.keys()) == 0
        assert len(mock_interface1.outbox) == 0

        # should queue the sync_sequence event and send an ack
        asyncio.run(Packager.process())
        assert len(Packager.new_events) == 1
        assert len(Packager.schedule.keys()) == 0
        assert len(Packager.in_seqs.keys()) == 1
        assert len(mock_interface1.outbox) == 1, len(mock_interface1.outbox)
        assert len(outbox) == 0

        # mock_interface1 should send the ack datagram, and the event should be scheduled
        asyncio.run(Packager.process())
        assert len(mock_interface1.outbox) == 0
        assert len(outbox) == 1
        assert len(Packager.new_events) == 0
        assert len(Packager.schedule.keys()) == 1
        outbox.clear()

        # spoof timestamp to advance the event
        eid = list(Packager.schedule.keys())[0]
        event = Packager.schedule[eid]
        event.ts = int(time()-1)*1000
        assert event.handler == Packager.sync_sequence, event.handler

        # should now execute cls.sync_sequence
        assert Packager.in_seqs[0].retry == 3, Packager.in_seqs[0].retry
        assert len(mock_interface1.outbox) == 0
        assert len(outbox) == 0
        asyncio.run(Packager.process())
        # rtx should be queued for sending in the interface
        assert len(mock_interface1.outbox) == 1
        assert len(outbox) == 0
        assert mock_interface1.outbox[0].addr == b'mac0'
        assert Packager.in_seqs[0].retry == 2, Packager.in_seqs[0].retry

        # mock_interface1 should now send the rtx datagram
        asyncio.run(Packager.process())
        assert len(mock_interface1.outbox) == 0
        assert len(outbox) == 1
        packet = Packet.unpack(outbox.popleft().data)
        assert packet.flags.rtx
        assert packet.id == 1
        assert packet.fields['seq_id'] == 0
        assert packet.fields['seq_size'] == 1

        # retransmitting missing Packet should finish the Sequence and deliver the Package
        inbox.append(Datagram(
            seq.get_packet(packet.id, flags, {}).pack(),
            mock_interface1.id,
            b'mac0',
        ))
        assert len(app_blobs) == 0
        assert len(Packager.in_seqs.keys()) == 1
        asyncio.run(Packager.process())
        assert len(app_blobs) == 1
        assert app_blobs[0] == blob
        assert len(Packager.in_seqs.keys()) == 0

    def test_sequence_synchronization_e2e_failure(self):
        # sequence construction attempt should be dropped if the origin is unresponsive
        # prepare the sequence
        blob = b''.join([(i%256).to_bytes(1, 'big') for i in range(400)])
        package = Package.from_blob(test_app.id, blob).pack()
        schema_ids = list(set(SCHEMA_IDS_SUPPORT_SEQUENCE).difference(
            SCHEMA_IDS_SUPPORT_ROUTING
        ).difference(SCHEMA_IDS_SUPPORT_CHECKSUM))
        schemas = get_schemas(schema_ids)
        schemas.sort(key=lambda s: s.max_body, reverse=True)
        schema = schemas[0]
        seq = Sequence(schema, 0, data_size=len(package))
        seq.set_data(package)
        assert seq.seq_size == 2

        # add application, network interface, and peer
        Packager.add_application(test_app)
        Packager.add_interface(mock_interface1)
        Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])

        # start sequence transmission with first packet
        flags = Flags(0)
        inbox.append(Datagram(
            seq.get_packet(0, flags, {}).pack(),
            mock_interface1.id,
            b'mac0',
        ))

        # should queue the sync_sequence event and send an ack
        asyncio.run(Packager.process())
        assert len(Packager.new_events) == 1
        assert len(Packager.in_seqs.keys()) == 1
        assert len(mock_interface1.outbox) == 1

        # mock_interface1 should send the ack datagram, and the event should be scheduled
        asyncio.run(Packager.process())
        assert len(outbox) == 1
        assert len(Packager.schedule.keys()) == 1
        outbox.clear()

        # spoof timestamp to advance the event
        eid = list(Packager.schedule.keys())[0]
        event = Packager.schedule[eid]
        event.ts = int(time()-1)*1000
        assert event.handler == Packager.sync_sequence, event.handler

        # should now execute cls.sync_sequence
        assert Packager.in_seqs[0].retry == 3, Packager.in_seqs[0].retry
        asyncio.run(Packager.process())
        # rtx should be queued for sending in the interface
        assert len(mock_interface1.outbox) == 1
        assert Packager.in_seqs[0].retry == 2, Packager.in_seqs[0].retry
        assert len(Packager.new_events) == 1

        # mock_interface1 should now send the rtx datagram
        asyncio.run(Packager.process())
        assert len(Packager.new_events) == 0
        assert len(outbox) == 1
        packet = Packet.unpack(outbox.popleft().data)
        assert packet.flags.rtx

        # simulate unresponsive node by spoofing timestamp
        eid = list(Packager.schedule.keys())[0]
        event = Packager.schedule[eid]
        event.ts = int(time()-1)*1000
        assert event.handler == Packager.sync_sequence, event.handler

        # should execute cls.sync_sequence again
        assert Packager.in_seqs[0].retry == 2, Packager.in_seqs[0].retry
        asyncio.run(Packager.process())
        asyncio.run(Packager.process())
        assert Packager.in_seqs[0].retry == 1, Packager.in_seqs[0].retry
        # rtx datagram should be sent
        assert len(outbox) == 1
        outbox.clear()

        # simulate unresponsive node by spoofing timestamp
        eid = list(Packager.schedule.keys())[0]
        event = Packager.schedule[eid]
        event.ts = int(time()-1)*1000
        assert event.handler == Packager.sync_sequence, event.handler

        # should execute cls.sync_sequence again
        assert Packager.in_seqs[0].retry == 1, Packager.in_seqs[0].retry
        asyncio.run(Packager.process())
        asyncio.run(Packager.process())
        assert Packager.in_seqs[0].retry == 0, Packager.in_seqs[0].retry
        # rtx datagram should be sent
        assert len(outbox) == 1
        outbox.clear()

        # simulate unresponsive node by spoofing timestamp
        eid = list(Packager.schedule.keys())[0]
        event = Packager.schedule[eid]
        event.ts = int(time()-1)*1000
        assert event.handler == Packager.sync_sequence, event.handler

        # InSequence should be dropped
        assert len(Packager.in_seqs.keys()) == 1
        asyncio.run(Packager.process())
        assert len(Packager.in_seqs.keys()) == 0

    def test_receive_routed_packet_delivers_package(self):
        # add application, network interface, and peer
        Packager.add_application(test_app)
        Packager.add_interface(mock_interface1)
        peer_id = b'1' * 32
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])

        # set addr
        local_addr = Address(118, coords=[1])
        Packager.set_addr(local_addr)

        # add route
        Packager.add_route(peer_id, Address(118, coords=[2, 1]))

        # create a packet containing a package for the app
        package = Package.from_blob(test_app.id, b'hello world')
        schemas = set(SCHEMA_IDS_SUPPORT_ROUTING)
        schemas.difference_update(SCHEMA_IDS_SUPPORT_SEQUENCE)
        schemas.difference_update(SCHEMA_IDS_SUPPORT_CHECKSUM)
        schemas = get_schemas(list(schemas))
        schemas.sort(key=lambda s: s.max_body, reverse=True)
        schema = schemas[0]
        packet = Packet(
            schema,
            Flags(0),
            {
                'tree_state': local_addr.tree_state,
                'to_addr': local_addr.address,
                'from_addr': Address(118, coords=[]).address,
                'body': package.pack(),
                'ttl': 250,
                'packet_id': 0,
            }
        )
        packet.flags.ask = True

        # receiving the packet should deliver the package
        assert len(app_blobs) == 0
        Packager.receive(packet, mock_interface1, b'mac0')
        assert len(app_blobs) == 1
        assert app_blobs[0] == package.blob
        app_blobs.pop()

        # receiving as datagram should also deliver the package
        assert len(app_blobs) == 0
        inbox.append(Datagram(packet.pack(), mock_interface1.id, b'mac0'))
        asyncio.run(Packager.process())
        assert len(app_blobs) == 1
        assert app_blobs[0] == package.blob


if __name__ == '__main__':
    unittest.main()
