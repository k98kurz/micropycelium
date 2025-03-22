import asyncio
from context import *
from hashlib import sha256
from os import urandom
import unittest


app_blobs = []

test_app = Application(
    'test',
    'test',
    0,
    lambda _P, blob, _i, _m: app_blobs.append(blob),
    {
        'hello': lambda _: 'world',
    }
)

class TestGossipApplication(unittest.TestCase):
    def setUp(self) -> None:
        Packager.reset()
        mock_interface1.castbox.clear()
        mock_interface1.outbox.clear()
        castbox.clear()
        outbox.clear()
        inbox.clear()
        Gossip.invoke('get_seen').clear()
        Gossip.invoke('get_cache').clear()
        Gossip.invoke('get_subscriptions').clear()
        app_blobs.clear()
        return super().setUp()

    def tearDown(self) -> None:
        Packager.reset()
        mock_interface1.castbox.clear()
        mock_interface1.outbox.clear()
        castbox.clear()
        outbox.clear()
        inbox.clear()
        Gossip.invoke('get_seen').clear()
        Gossip.invoke('get_cache').clear()
        Gossip.invoke('get_subscriptions').clear()
        app_blobs.clear()
        return super().tearDown()

    def test_publish_gossip_adds_to_cache_and_schedules_broadcast(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        topic_id = sha256(b'topic').digest()[:16]
        data = b'data'
        gm = GossipMessage(GossipOp.PUBLISH, topic_id, data)
        message_id = sha256(Gossip.invoke('serialize', gm)).digest()[:16]

        assert len(mock_interface1.castbox) == 0
        assert message_id not in Gossip.invoke('get_seen'), Gossip.invoke('get_seen')
        assert Gossip.invoke('get_cache').get(message_id) is None
        Gossip.invoke('publish', topic_id, data)
        assert len(mock_interface1.castbox) == 1
        asyncio.run(Packager.process())
        assert len(mock_interface1.castbox) == 0
        assert len(castbox) == 1
        assert message_id in Gossip.invoke('get_seen')
        assert Gossip.invoke('get_cache').get(message_id) is not None

    def test_subscribe_and_unsubscribe(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        topic_id = sha256(b'topic').digest()[:16]
        Gossip.invoke('subscribe', topic_id, test_app.id)
        assert len(Gossip.invoke('get_subscriptions')) == 1
        Gossip.invoke('unsubscribe', topic_id, test_app.id)
        assert len(Gossip.invoke('get_subscriptions')) == 0

    def test_deliver_gossip_rebroadcasts_small_published_messages(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        topic_id = sha256(b'topic').digest()[:16]
        data = b'data'
        gm = GossipMessage(GossipOp.PUBLISH, topic_id, data)
        assert len(mock_interface1.castbox) == 0
        Gossip.invoke('deliver_gossip', gm)
        assert len(mock_interface1.castbox) == 1
        packet = Packet.unpack(mock_interface1.castbox.popleft().data)
        p = Package.unpack(packet.body)
        gm = Gossip.invoke('deserialize', p.blob)
        assert gm.op == GossipOp.PUBLISH, gm.op
        assert gm.topic_id == topic_id
        assert gm.data == data

    def test_deliver_gossip_message_does_not_rebroadcast(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        topic_id = sha256(b'topic').digest()[:16]
        data = b'data'
        gm = GossipMessage(GossipOp.RESPOND, topic_id, data)
        assert len(mock_interface1.castbox) == 0
        Gossip.invoke('deliver_gossip', gm)
        assert len(mock_interface1.castbox) == 0

    def test_deliver_gossip_broadcasts_notification_for_large_messages(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        topic_id = sha256(b'topic').digest()[:16]
        data = b'data' * 100
        gm = GossipMessage(GossipOp.PUBLISH, topic_id, data)
        message_id = sha256(Gossip.invoke('serialize', gm)).digest()[:16]
        Gossip.invoke('deliver_gossip', gm)
        assert len(mock_interface1.castbox) == 1
        packet = Packet.unpack(mock_interface1.castbox.popleft().data)
        p = Package.unpack(packet.body)
        gm = Gossip.invoke('deserialize', p.blob)
        assert gm.op == GossipOp.NOTIFY, gm.op
        assert gm.topic_id == topic_id
        assert gm.data == message_id

    def test_deliver_gossip_forwards_to_subscribed_apps(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        Packager.add_application(test_app)
        topic_id = sha256(b'topic').digest()[:16]
        data =  b'data'
        gm = GossipMessage(GossipOp.RESPOND, topic_id, data)

        Gossip.invoke('subscribe', topic_id, test_app.id)
        assert len(Gossip.invoke('get_subscriptions')) == 1
        assert len(app_blobs) == 0
        Gossip.invoke('deliver_gossip', gm)
        assert len(app_blobs) == 1

    def test_receive_seen_message_skips_it(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        Packager.add_application(test_app)
        Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])

        topic_id = sha256(b'topic').digest()[:16]
        gm = GossipMessage(GossipOp.RESPOND, topic_id, b'test data')
        message_id = sha256(Gossip.invoke('serialize', gm)).digest()[:16]
        Gossip.invoke('get_seen').append(message_id)
        blob = Gossip.invoke('serialize', gm)

        assert len(mock_interface1.outbox) == 0
        assert len(mock_interface1.castbox) == 0
        Gossip.receive(blob, mock_interface1, b'mac0')
        assert len(mock_interface1.outbox) == 0
        assert len(mock_interface1.castbox) == 0

    def test_receive_notification_results_in_request_for_message(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        Packager.add_application(test_app)
        Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])

        topic_id = sha256(b'topic').digest()[:16]
        og_gm = GossipMessage(GossipOp.RESPOND, topic_id, b'test data')
        message_id = sha256(Gossip.invoke('serialize', og_gm)).digest()[:16]
        gm = GossipMessage(GossipOp.NOTIFY, topic_id, message_id)
        blob = Gossip.invoke('serialize', gm)

        assert len(mock_interface1.outbox) == 0
        Gossip.receive(blob, mock_interface1, b'mac0')
        assert len(mock_interface1.outbox) == 1
        packet = Packet.unpack(mock_interface1.outbox.popleft().data)
        p = Package.unpack(packet.body)
        gm = Gossip.invoke('deserialize', p.blob)
        assert gm.op == GossipOp.REQUEST, gm.op
        assert gm.topic_id == message_id
        assert gm.data == Packager.node_id

    def test_receive_notification_skips_seen_message(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        Packager.add_application(test_app)
        Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])

        topic_id = sha256(b'topic').digest()[:16]
        og_gm = GossipMessage(GossipOp.RESPOND, topic_id, b'test data')
        message_id = sha256(Gossip.invoke('serialize', og_gm)).digest()[:16]
        Gossip.invoke('get_cache').add(message_id, og_gm)
        gm = GossipMessage(GossipOp.NOTIFY, topic_id, message_id)
        blob = Gossip.invoke('serialize', gm)

        assert len(mock_interface1.outbox) == 0
        Gossip.receive(blob, mock_interface1, b'mac0')
        assert len(mock_interface1.outbox) == 0

    def test_receive_request_message_sends_message(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        Packager.add_application(test_app)
        Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])

        topic_id = sha256(b'topic').digest()[:16]
        og_gm = GossipMessage(GossipOp.RESPOND, topic_id, b'test data')
        message_id = sha256(Gossip.invoke('serialize', og_gm)).digest()[:16]
        Gossip.invoke('get_cache').add(message_id, og_gm)
        gm = GossipMessage(GossipOp.REQUEST, message_id, b'some node id')
        blob = Gossip.invoke('serialize', gm)

        assert len(mock_interface1.outbox) == 0
        Gossip.receive(blob, mock_interface1, b'mac0')
        assert len(mock_interface1.outbox) == 1
        packet = Packet.unpack(mock_interface1.outbox.popleft().data)
        p = Package.unpack(packet.body)
        gm = Gossip.invoke('deserialize', p.blob)
        assert gm == og_gm

    def test_receive_request_message_ids_sends_message_ids(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        Packager.add_application(test_app)
        Packager.add_peer(b'peer0', [(b'mac0', mock_interface1)])

        topic_id = sha256(b'topic').digest()[:16]
        og_gms = [
            GossipMessage(GossipOp.RESPOND, topic_id, b'data'+i.to_bytes(1, 'big'))
            for i in range(3)
        ]
        message_ids = [
            sha256(Gossip.invoke('serialize', gm)).digest()[:16]
            for gm in og_gms
        ]
        for i in range(len(message_ids)):
            Gossip.invoke('get_cache').add(message_ids[i], og_gms[i])

        gm = GossipMessage(GossipOp.REQUEST_IDS, topic_id, b'some node id')
        blob = Gossip.invoke('serialize', gm)

        assert len(mock_interface1.outbox) == 0
        Gossip.receive(blob, mock_interface1, b'mac0')
        assert len(mock_interface1.outbox) == 1
        packet = Packet.unpack(mock_interface1.outbox.popleft().data)
        p = Package.unpack(packet.body)
        gm = Gossip.invoke('deserialize', p.blob)
        assert gm.op == GossipOp.RESPOND_IDS, gm.op
        assert gm.topic_id == topic_id
        assert gm.data == b''.join(message_ids)

    def test_receive_message_ids_requests_unseen_messages(self):
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        Packager.add_application(test_app)
        peer_id = urandom(32)
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])

        topic_id = sha256(b'topic').digest()[:16]
        og_gms = [
            GossipMessage(GossipOp.RESPOND, topic_id, b'data'+i.to_bytes(1, 'big'))
            for i in range(3)
        ]
        message_ids = [
            sha256(Gossip.invoke('serialize', gm)).digest()[:16]
            for gm in og_gms
        ]
        # add one to the cache
        Gossip.invoke('get_seen').append(message_ids[0])
        gm = GossipMessage(GossipOp.RESPOND_IDS, topic_id, b''.join(message_ids))
        blob = Gossip.invoke('serialize', gm)

        assert len(mock_interface1.outbox) == 0
        Gossip.receive(blob, mock_interface1, b'mac0')
        assert len(mock_interface1.outbox) == 2, len(mock_interface1.outbox)

    def test_start_and_stop_and_add_peer_hook(self):
        Packager.add_application(Gossip)
        Packager.add_interface(mock_interface1)
        topic_id = sha256(b'topic').digest()[:16]
        Gossip.invoke('subscribe', topic_id, test_app.id)
        assert len(Packager._hooks.get('add_peer', [])) == 0
        Gossip.invoke('start')
        assert len(Packager._hooks.get('add_peer', [])) == 1
        assert len(mock_interface1.outbox) == 0
        assert len(Packager.new_events) == 1
        peer_id = urandom(32)
        Packager.add_peer(peer_id, [(b'mac0', mock_interface1)])
        assert len(Packager.new_events) == 2
        assert len(Packager.schedule) == 0
        asyncio.run(Packager.process())
        assert len(Packager.new_events) == 1 # retry send REQUEST_IDS
        packet_id = Packager.new_events[0].args[0]
        packet: Packet = Packager.packet_cache.get(packet_id)
        package: Package = Package.unpack(packet.body)
        gm = Gossip.invoke('deserialize', package.blob)
        assert gm.op == GossipOp.REQUEST_IDS
        assert len(Packager.schedule) == 1, \
            (Packager.schedule, list(Packager.schedule.keys()))
        assert len(mock_interface1.outbox) == 1, \
            (list(mock_interface1.outbox), list(mock_interface1.castbox),
             list(mock_interface1.inbox))
        Gossip.invoke('stop')
        assert len(Packager._hooks.get('add_peer', [])) == 0


if __name__ == '__main__':
    unittest.main()
