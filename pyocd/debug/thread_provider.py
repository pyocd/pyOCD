# pyOCD debugger
# Copyright (c) 2016 Arm Limited
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

## @brief Base class representing a thread on the target.
class TargetThread(object):
    def __init__(self):
        pass

    @property
    def unique_id(self):
        raise NotImplementedError()

    @property
    def name(self):
        raise NotImplementedError()

    @property
    def description(self):
        raise NotImplementedError()

    @property
    def context(self):
        raise NotImplementedError()

    # Used by PSPThreadContext to obtain a previous stored EXC_RETURN.FType from
    # an OS task control block, if it is uncertain about the EXC_RETURN for
    # the current exception. OS can return None if not available, else True
    # meaning "standard" or False meaning "extended".
    def get_exc_return_ftype(self):
        raise NotImplementedError()

## @brief Base class for RTOS support plugins.
class ThreadProvider(object):
    def __init__(self, target, parent=None):
        self._target = target
        self._parent = parent
        self._target_context = self._target.get_target_context()
        self._last_run_token = -1
        self._read_from_target = False
        self._vector_catch_show_origin = target.session.options.get('vector_catch_show_origin', True)

    def _lookup_symbols(self, symbolList, symbolProvider):
        syms = {}
        for name in symbolList:
            addr = symbolProvider.get_symbol_value(name)
            logging.debug("Value for symbol %s = %s", name, hex(addr) if addr is not None else "<none>")
            if addr is None:
                return None
            syms[name] = addr
        return syms

    ##
    # @retval True The provider was successfully initialzed.
    # @retval False The provider could not be initialized successfully.
    def init(self, symbolProvider):
        raise NotImplementedError()

    def _build_thread_list(self):
        raise NotImplementedError()

    def _is_thread_list_dirty(self):
        token = self._target.run_token
        if token == self._last_run_token:
            # Target hasn't run since we last updated threads, so there is nothing to do.
            return False
        self._last_run_token = token
        return True

    def set_parent(self, provider):
        self._parent = provider

    def update_threads(self):
        if self._parent is not None:
            self._parent.update_threads()
        if self._is_thread_list_dirty() and self.read_from_target:
            self._build_thread_list()

    @property
    def threads(self):
        raise NotImplementedError()

    def get_threads(self):
        return list(self.threads.values())

    def get_thread(self, threadId):
        return self.threads.get(threadId, None)

    def invalidate(self):
        raise NotImplementedError()

    @property
    def read_from_target(self):
        return self._read_from_target

    @read_from_target.setter
    def read_from_target(self, value):
        if self._parent is not None:
            self._parent.read_from_target = value
        if value != self._read_from_target:
            self.invalidate()
        self._read_from_target = value

    @property
    def is_enabled(self):
        raise NotImplementedError()

    @property
    def current_thread(self):
        self.update_threads()
        id = self.get_current_thread_id()
        try:
            return self.threads[id]
        except KeyError:
            logging.debug("key error getting current thread id=%s; self.threads = %s",
                ("%x" % id) if (id is not None) else id, repr(self.threads))
            return None

    def is_valid_thread_id(self, threadId):
        self.update_threads()
        return threadId in self.threads

    def get_current_stack_pointer_id(self):
        return self._parent.get_current_stack_pointer_id()

    def get_current_thread_id(self):
        # First figure out the current stack ID - used to choose which provider in the chain
        # to use.
        stack = self.get_current_stack_pointer_id()
        # If we're at vector catch we have a choice of showing originating or current stack. 
        if self._vector_catch_show_origin and self._target_context.core.is_vector_catch():
             stack = self._target_context.core.get_vector_catch_originating_stack_pointer_id()
        # Now loop through the providers until someone gives us a thread ID. We require that
        # if any handler returns None for a given stack, it must have retained threads
        # for that stack in its list from its parents, and that the root provider
        # must always be able to return a thread for any stack id.
        provider = self
        while provider is not None:
            if provider.is_enabled:
                thread = provider.get_current_thread_id_for_stack(stack)
            else:
                thread = None
            if thread is not None:
                return thread
            provider = provider._parent
        return None

    # From a particular provider's point of view, so the current OS thread
    # corresponding to the specified stack, even if not currently on that stack.
    # So an RTOS would normally always return its OS ID whenever stack_id
    # indicated the Process stack, otherwise None, which makes us check the
    # next provider.
    def get_current_thread_id_for_stack(self, stack_id):
        raise NotImplementedError()


## @brief Class representing a simple thread.
class RootThread(TargetThread):
    UNIQUE_ID = 1

    def __init__(self, targetContext, provider, name=None):
        super(RootThread, self).__init__()
        self._target_context = targetContext
        self._provider = provider

    @property
    def priority(self):
        return 0

    @property
    def unique_id(self):
        return self.UNIQUE_ID

    @property
    def name(self):
        return None

    @property
    def description(self):
        return None

    @property
    def context(self):
        return self._target_context

    def __str__(self):
        return "<RootThread@0x%08x>" % (id(self))

    def __repr__(self):
        return str(self)


## @brief Root Thread provider - no core knowledge
class RootThreadProvider(ThreadProvider):

    # Unlike RTOS providers, we do everything in __init__ - our needs are few
    def __init__(self, target):
        super(RootThreadProvider, self).__init__(target)
        self._threads = { RootThread.UNIQUE_ID: RootThread(self._target_context, self) }

    def invalidate(self):
        pass

    def _build_thread_list(self):
        pass

    @property
    def threads(self):
        return self._threads

    @property
    def read_from_target(self):
        return True

    @read_from_target.setter
    def read_from_target(self, value):
        pass

    @property
    def is_enabled(self):
        return True

    def get_current_stack_pointer_id(self):
        return None

    def get_current_thread_id_for_stack(self, stack_id):
        return RootThread.UNIQUE_ID
