from context import *
from hashlib import sha256
import asyncio
import unittest


class TestDebugApp(unittest.TestCase):
    def setUp(self) -> None:
        Packager.reset()
        Packager.add_interface(mock_interface1)
        Packager.add_application(Gossip)
        Packager.add_application(DebugApp)
        DebugApp.invoke('start')
        DebugApp.params['admin_pass_hash'] = sha256(b'test').digest()[:16]
        mock_interface1.castbox.clear()
        mock_interface1.outbox.clear()
        mock_interface1.inbox.clear()
        castbox.clear()
        inbox.clear()
        outbox.clear()
        Gossip.invoke('get_seen').clear()
        return super().setUp()

    def tearDown(self) -> None:
        Packager.reset()
        DebugApp.invoke('stop')
        mock_interface1.castbox.clear()
        mock_interface1.outbox.clear()
        mock_interface1.inbox.clear()
        castbox.clear()
        inbox.clear()
        outbox.clear()
        Gossip.invoke('get_seen').clear()
        return super().tearDown()

    def test_REQUIRE_BAN_e2e(self):
        out = []
        DebugApp.add_hook('output', lambda *args: out.append(args))
        DebugApp.invoke(
            'require', DebugOp.REQUIRE_BAN, Packager.node_id, b'test',
            Packager.node_id
        )
        assert len(out) == 2, out
        assert out[0][1] == 'DebugApp: REQUIRE_BAN received'
        assert type(out[1][1]) is dict, out[1][1]
        assert out[1][1]['op'] == 'REQUIRE_BAN', out[1][1]
        assert out[1][1]['node_id'] == Packager.node_id.hex(), out[1][1]

    def test_REQUIRE_UNBAN_e2e(self):
        out = []
        DebugApp.add_hook('output', lambda *args: out.append(args))
        DebugApp.invoke(
            'require', DebugOp.REQUIRE_UNBAN, Packager.node_id, b'test',
            Packager.node_id
        )
        assert len(out) == 2, out
        assert out[0][1] == 'DebugApp: REQUIRE_UNBAN received'
        assert type(out[1][1]) is dict, out[1][1]
        assert out[1][1]['op'] == 'REQUIRE_UNBAN', out[1][1]
        assert out[1][1]['node_id'] == Packager.node_id.hex(), out[1][1]

    def test_REQUIRE_REFLECT_e2e(self):
        # internal debug request
        dm = DebugMessage(
            DebugOp.REQUEST_NODE_INFO,
            int(time()),
            123,
            Packager.node_id,
            b''
        )
        out = []
        DebugApp.add_hook('output', lambda *args: out.append(args))
        DebugApp.invoke(
            'require', DebugOp.REQUIRE_REFLECT, Packager.node_id, b'test',
            DebugApp.invoke('serialize', dm)
        )
        assert len(out) == 2, out
        assert out[0][1] == 'DebugApp: REQUIRE_REFLECT received'
        assert type(out[1][1]) is dict, out[1][1]
        assert out[1][1]['op'] == 'RESPOND_NODE_INFO', out[1][1]

    def test_REQUIRE_RESET_e2e(self):
        out = []
        DebugApp.add_hook('output', lambda *args: out.append(args))
        DebugApp.invoke(
            'require', DebugOp.REQUIRE_RESET, Packager.node_id, b'test',
            Packager.node_id
        )
        assert len(out) == 2, out
        assert 'DebugApp: REQUIRE_RESET received' in out[0][1], out[0][1]
        assert type(out[1][1]) is dict, out[1][1]
        assert out[1][1]['op'] == 'REQUIRE_RESET', out[1][1]


if __name__ == '__main__':
    unittest.main()
