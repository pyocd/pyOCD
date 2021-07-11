# pyOCD debugger
# Copyright (c) 2019 Arm Limited
# Copyright (c) 2021 Chris Reed
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

class GraphNode(object):
    """! @brief Simple graph node.
    
    All nodes have a parent, which is None for a root node, and zero or more children.
    
    Supports indexing and iteration over children.
    """

    def __init__(self):
        """! @brief Constructor."""
        super(GraphNode, self).__init__()
        self._parent = None
        self._children = []
    
    @property
    def parent(self):
        """! @brief This node's parent in the object graph."""
        return self._parent
    
    @property
    def children(self):
        """! @brief Child nodes in the object graph."""
        return self._children
    
    @property
    def is_leaf(self):
        """! @brief Returns true if the node has no children."""
        return len(self.children) == 0
    
    def add_child(self, node):
        """! @brief Link a child node onto this object."""
        node._parent = self
        self._children.append(node)
    
    def find_root(self):
        """! @brief Returns the root node of the object graph."""
        root = self
        while root.parent is not None:
            root = root.parent
        return root
    
    def find_children(self, predicate, breadth_first=True):
        """! @brief Recursively search for children that match a given predicate.
        @param self
        @param predicate A callable accepting a single argument for the node to examine. If the
            predicate returns True, then that node is added to the result list and no further
            searches on that node's children are performed. A False predicate result causes the
            node's children to be searched.
        @param breadth_first Whether to search breadth first. Pass False to search depth first.
        @returns List of matching child nodes, or an empty list if no matches were found.
        """
        def _search(node, klass):
            results = []
            childrenToExamine = []
            for child in node.children:
                if predicate(child):
                    results.append(child)
                elif not breadth_first:
                    results.extend(_search(child, klass))
                elif breadth_first:
                    childrenToExamine.append(child)
                
            if breadth_first:
                for child in childrenToExamine:
                    results.extend(_search(child, klass))
            return results
        
        return _search(self, predicate)
    
    def get_first_child_of_type(self, klass):
        """! @brief Breadth-first search for a child of the given class.
        @param self
        @param klass The class type to search for. The first child at any depth that is an instance
            of this class or a subclass thereof will be returned. Matching children at more shallow
            nodes will take precedence over deeper nodes.
        @returns Either a node object or None.
        """
        matches = self.find_children(lambda c: isinstance(c, klass))
        if len(matches):
            return matches[0]
        else:
            return None
    
    def __getitem__(self, key):
        """! @brief Returns the indexed child.
        
        Slicing is supported.
        """
        return self._children[key]
    
    def __iter__(self):
        """! @brief Iterate over the node's children."""
        return iter(self.children)
    
    def _dump_desc(self):
        """! @brief Similar to __repr__ by used for dump_to_str()."""
        return str(self)
    
    def dump_to_str(self):
        """! @brief Returns a string describing the object graph."""
    
        def _dump(node, level):
            result = ("  " * level) + "- " + node._dump_desc() + "\n"
            for child in node.children:
                result += _dump(child, level + 1)
            return result
    
        return _dump(self, 0)
    
    def dump(self):
        """! @brief Pretty print the object graph to stdout."""
        print(self.dump_to_str())
