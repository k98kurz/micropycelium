import asyncio
from context import *
import unittest


class TestBeaconApplication(unittest.TestCase):
    def setUp(self) -> None:
        Packager.reset()
        mock_interface1.castbox.clear()
        castbox.clear()
        Beacon.invoke('get_seen').clear()
        Beacon.invoke('get_sent').clear()
        return super().setUp()

    def tearDown(self) -> None:
        Packager.reset()
        mock_interface1.castbox.clear()
        castbox.clear()
        Beacon.invoke('get_seen').clear()
        Beacon.invoke('get_sent').clear()
        return super().tearDown()

    def test_invoke_broadcast(self):
        Packager.add_interface(mock_interface1)
        assert len(Packager.peers) == 0
        assert len(mock_interface1.castbox) == 0
        Packager.add_application(Beacon)
        assert len(Beacon.invoke('get_sent')) == 0
        Beacon.invoke('broadcast')
        assert len(Beacon.invoke('get_sent')) == 1
        assert len(mock_interface1.castbox) == 1
        assert len(castbox) == 0
        asyncio.run(Packager.process())
        assert len(mock_interface1.castbox) == 0
        assert len(castbox) == 1

    def test_receive_adds_peer_and_sends_response(self):
        Packager.add_interface(InterAppInterface)
        assert len(Packager.peers) == 0
        assert len(InterAppInterface.outbox) == 0
        Packager.add_application(Beacon)
        bmsgs = [
            Package.from_blob(
                Beacon.id,
                Beacon.invoke('serialize', bm),
            )
            for bm in Beacon.invoke('get_bmsgs', b'\x00')
        ]
        original_id = Packager.node_id
        Packager.node_id = b'changed for testing'
        assert len(InterAppInterface.outbox) == 0
        asyncio.run(Packager.process())
        assert len(Beacon.invoke('get_seen')) == 0
        for bm in bmsgs:
            Packager.deliver(bm, InterAppInterface, b'mac0')
        assert len(Beacon.invoke('get_seen')) > 0
        asyncio.run(Packager.process())
        assert len(Packager.peers) == 1
        assert len(iai_box) == 1
        asyncio.run(Packager.process())
        assert len(iai_box) == 0
        Packager.node_id = original_id

    def test_start_broadcasts_and_schedules_event(self):
        Packager.add_interface(InterAppInterface)
        assert len(InterAppInterface.castbox) == 0
        assert len(Packager.new_events) == 0
        Packager.add_application(Beacon)
        # should queue a broadcast on the interface and queue new event
        Beacon.invoke('start')
        assert len(InterAppInterface.castbox) == 1
        assert len(Packager.schedule.keys()) == 0
        assert len(Packager.new_events) == 1
        # should send the broadcast then schedule the event
        asyncio.run(Packager.process())
        assert len(InterAppInterface.castbox) == 0
        assert len(Packager.new_events) == 0
        assert len(Packager.schedule.keys()) == 1
        assert list(Packager.schedule.keys())[0] == Beacon.id


if __name__ == '__main__':
    unittest.main()
