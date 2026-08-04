import unittest
from types import SimpleNamespace

from xray_fluent.application.node_runtime_service import get_node_by_id
from xray_fluent.models import Node


class _CountingNodes(list):
    def __init__(self, values):
        super().__init__(values)
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


class NodeLookupTests(unittest.TestCase):
    @staticmethod
    def _controller(nodes):
        return SimpleNamespace(
            state=SimpleNamespace(nodes=nodes),
            _node_lookup_source_id=0,
            _node_lookup_size=-1,
            _node_by_id={},
        )

    def test_repeated_lookup_does_not_rescan_the_server_list(self) -> None:
        nodes = _CountingNodes(Node(id=f"node-{index}") for index in range(10_000))
        controller = self._controller(nodes)

        self.assertEqual(get_node_by_id(controller, "node-9999").id, "node-9999")
        first_lookup_iterations = nodes.iterations
        self.assertEqual(get_node_by_id(controller, "node-5000").id, "node-5000")

        self.assertEqual(first_lookup_iterations, 1)
        self.assertEqual(nodes.iterations, first_lookup_iterations)

    def test_cache_rebuilds_after_in_place_append_or_list_replacement(self) -> None:
        nodes = _CountingNodes([Node(id="node-1")])
        controller = self._controller(nodes)
        self.assertIsNone(get_node_by_id(controller, "node-2"))

        nodes.append(Node(id="node-2"))
        self.assertEqual(get_node_by_id(controller, "node-2").id, "node-2")

        controller.state.nodes = _CountingNodes([Node(id="node-3")])
        self.assertEqual(get_node_by_id(controller, "node-3").id, "node-3")
        self.assertIsNone(get_node_by_id(controller, "node-1"))


if __name__ == "__main__":
    unittest.main()
