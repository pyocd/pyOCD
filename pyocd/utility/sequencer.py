# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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

import logging
from collections import OrderedDict
from collections.abc import Callable

LOG = logging.getLogger(__name__)

class CallSequence(object):
    """! @brief Call sequence manager.
    
    Contains an ordered sequence of tasks. Each task has a name and associated
    callable. The CallSequence class itself is callable, so instances can be nested
    as tasks within other CallSequences.
    
    When tasks within a sequence are called, they may optionally return a new CallSequence
    instance. If this happens, the new sequence is executed right away, before continuing
    with the next task in the original sequence.
    
    A CallSequence can be iterated over. It will return tuples of (task-name, callable).
    """

    def __init__(self, *args):
        """! @brief Constructor.
        
        The constructor accepts an arbitrary number of parameters describing an ordered
        set of tasks. Each parameter must be a 2-tuple with the first element being the
        task's name and the second element a callable that implements the task. If you
        need to pass parameters to the callable, use a lambda.
        """
        self._validate_tasks(args)
        self._calls = OrderedDict(args)
    
    def _validate_tasks(self, tasks):
        for i in tasks:
            assert len(i) == 2
            assert type(i[0]) is str
            assert isinstance(i[1], Callable)
    
    @property
    def sequence(self):
        """! @brief Returns an OrderedDict of the call sequence.
        
        Task names are keys.
        """
        return self._calls
    
    @sequence.setter
    def sequence(self, seq):
        """! @brief Replace the entire call sequence.
        
        Accepts either an OrderedDict or a list of 2-tuples like the constructor.
        """
        if isinstance(seq, OrderedDict):
            self._calls = seq
        elif type(seq) is list and len(seq) and type(seq[0]) is tuple:
            self._calls = OrderedDict(seq)
    
    @property
    def count(self):
        """! @brief Returns the number of tasks in the sequence."""
        return len(self._calls)
    
    def clear(self):
        """! @brief Remove all tasks from the sequence."""
        self._calls = OrderedDict()
    
    def copy(self):
        """! @brief Duplicate the sequence."""
        new_seq = CallSequence()
        new_seq._calls = self._calls.copy()
        return new_seq
    
    def remove_task(self, name):
        """! @brief Remove a task with the given name.
        @exception KeyError Raised if no task with the specified name exists.
        """
        del self._calls[name]
        return self
    
    def has_task(self, name):
        """! @brief Returns a boolean indicating presence of the named task in the sequence."""
        return name in self._calls
    
    def get_task(self, name):
        """! @brief Return the callable for the named task.
        @exception KeyError Raised if no task with the specified name exists.
        """
        return self._calls[name]
    
    def replace_task(self, name, replacement):
        """! @brief Change the callable associated with a task."""
        assert isinstance(replacement, Callable)
        if name not in self._calls:
            raise KeyError(name)
        else:
            # OrderedDict preserves the order when changing the value of a key
            # that is already in the dict.
            self._calls[name] = replacement
        return self
    
    def wrap_task(self, name, wrapper):
        """! @brief Wrap an existing task with a new callable.
        
        The wrapper is expected to take a single parameter, the return value from the
        original task. This allows for easy filtering of a new call sequence returned by
        the original task.
        """
        if name not in self._calls:
            raise KeyError(name)

        # Get original callable.
        orig = self._calls[name]
        
        # OrderedDict preserves the order when changing the value of a key
        # that is already in the dict.
        self._calls[name] = lambda : wrapper(orig())
        return self
    
    def append(self, *args):
        """! @brief Append a new task or tasks to the sequence.
        
        Like the constructor, this method takes any number of arguments. Each must be a
        2-tuple task description.
        """
        self._validate_tasks(args)

        # Insert iterable.
        self._calls.update(args)
        return self

    def insert_before(self, beforeTaskName, *args):
        """! @brief Insert a task or tasks before a named task.
        
        @param beforeTaskName The name of an existing task. The new tasks will be inserted
          prior to this task.
        
        After the task name parameter, any number of task description 2-tuples may be
        passed.
        
        @exception KeyError Raised if the named task does not exist in the sequence.
        """
        self._validate_tasks(args)
        
        if not self.has_task(beforeTaskName):
            raise KeyError(beforeTaskName)

        seq = list(self._calls.items())
        for i, v in enumerate(seq):
            if v[0] == beforeTaskName:
                for c in args:
                    # List insert() inserts before the given index.
                    seq.insert(i, c)
                    i += 1
                break
        self._calls = OrderedDict(seq)
        return self

    def insert_after(self, afterTaskName, *args):
        """! @brief Insert a task or tasks after a named task.
        
        @param afterTaskName The name of an existing task. The new tasks will be inserted
          after this task.
        
        After the task name parameter, any number of task description 2-tuples may be
        passed.
        
        @exception KeyError Raised if the named task does not exist in the sequence.
        """
        self._validate_tasks(args)
        
        if not self.has_task(afterTaskName):
            raise KeyError(afterTaskName)

        seq = list(self._calls.items())
        for i, v in enumerate(seq):
            if v[0] == afterTaskName:
                for c in args:
                    # List insert() inserts before the given index.
                    seq.insert(i + 1, c)
                    i += 1
                break
        self._calls = OrderedDict(seq)
        return self

    def invoke(self):
        """! @brief Execute each task in order.
        
        A task may return a CallSequence, in which case the new sequence is immediately
        executed.
        """
        for name, call in self._calls.items():
            LOG.debug("Running task %s", name)
            resultSequence = call()
            
            # Invoke returned call sequence.
            if resultSequence is not None and isinstance(resultSequence, CallSequence):
#                 LOG.debug("Invoking returned call sequence: %s", resultSequence)
                resultSequence.invoke()
    
    def __call__(self, *args, **kwargs):
        """! @brief Another way to execute the tasks.
        
        Supports nested CallSequences.
        """
        self.invoke()
    
    def __iter__(self):
        """! @brief Iterate over the sequence."""
        return iter(self._calls.items())
    
    def __repr__(self):
        s = "<%s@%x: " % (self.__class__.__name__, id(self))
        for name, task in self._calls.items():
            s += "\n%s: %s" % (name, task)
        s += ">"
        return s
