# pyOCD debugger
# Copyright (c) 2019 Arm Limited
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pytest

from pyocd.utility.graph import GraphNode

class BaseNode(GraphNode):
    def __init__(self, value):
        super(BaseNode, self).__init__()
        self.value = value
    
    def __repr__(self):
        return "<{}@{:#010x} {}".format(self.__class__.__name__, id(self), self.value)

class NodeA(BaseNode):
    pass

class NodeB(BaseNode):
    pass

@pytest.fixture(scope='function')
def a():
    return NodeA(23)

@pytest.fixture(scope='function')
def b():
    return NodeB(1)

@pytest.fixture(scope='function')
def c():
    return NodeB(2)

@pytest.fixture(scope='function')
def graph(a, b, c):
    p = GraphNode()
    p.add_child(a)
    a.add_child(b)
    p.add_child(c)
    return p

class TestGraph:
    def test_new(self):
        n = GraphNode()
        assert len(n.children) == 0
        assert n.parent is None

    def test_add_child(self):
        p = GraphNode()
        a = GraphNode()
        p.add_child(a)
        assert p.children == [a]
        assert p.parent is None
        assert a.parent is p
        assert a.children == []

    def test_multiple_child(self):
        p = GraphNode()
        a = GraphNode()
        b = GraphNode()
        c = GraphNode()
        p.add_child(a)
        p.add_child(b)
        p.add_child(c)
        assert p.children == [a, b, c]
        assert p.parent is None
        assert a.parent is p
        assert b.parent is p
        assert c.parent is p
        assert a.children == []
        assert b.children == []
        assert c.children == []
    
    def test_multilevel(self, graph, a, b, c):
        assert len(graph.children) == 2
        assert graph.children == [a, c]
        assert len(a.children) == 1
        assert a.children == [b]
        assert graph.parent is None
        assert a.parent is graph
        assert b.parent is a
        assert c.parent is graph
        assert b.children == []
        assert c.children == []
    
    def test_find_breadth(self, graph, a, b, c):
        assert graph.find_children(lambda n: n.value == 1) == [b]
        assert graph.find_children(lambda n: n.value == 1 or n.value == 2) == [c, b]
    
    def test_find_depth(self, graph, a, b, c):
        assert graph.find_children(lambda n: n.value == 1, breadth_first=False) == [b]
        assert graph.find_children(lambda n: n.value == 1 or n.value == 2, breadth_first=False) == [b, c]
    
    def test_first(self, graph, a, b, c):
        assert graph.get_first_child_of_type(NodeA) == a
        assert graph.get_first_child_of_type(NodeB) == c
        assert a.get_first_child_of_type(NodeB) == b
        
