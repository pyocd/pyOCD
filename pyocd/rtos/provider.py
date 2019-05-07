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

LOG = logging.getLogger(__name__)

class TargetThread(object):
    """! @brief Base class representing a thread on the target."""

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
    def is_current(self):
        raise NotImplementedError()

    @property
    def context(self):
        raise NotImplementedError()

class ThreadProvider(object):
    """! @brief Base class for RTOS support plugins."""

    def __init__(self, target):
        self._target = target
        self._target_context = self._target.get_target_context()
        self._last_run_token = -1
        self._read_from_target = False

    def _lookup_symbols(self, symbolList, symbolProvider):
        syms = {}
        for name in symbolList:
            addr = symbolProvider.get_symbol_value(name)
            LOG.debug("Value for symbol %s = %s", name, hex(addr) if addr is not None else "<none>")
            if addr is None:
                return None
            syms[name] = addr
        return syms

    def init(self, symbolProvider):
        """!
        @retval True The provider was successfully initialzed.
        @retval False The provider could not be initialized successfully.
        """
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

    def update_threads(self):
        if self._is_thread_list_dirty() and self._read_from_target:
            self._build_thread_list()

    def get_threads(self):
        raise NotImplementedError()

    def get_thread(self, threadId):
        raise NotImplementedError()

    def invalidate(self):
        raise NotImplementedError()

    @property
    def read_from_target(self):
        return self._read_from_target

    @read_from_target.setter
    def read_from_target(self, value):
        if value != self._read_from_target:
            self.invalidate()
        self._read_from_target = value

    @property
    def is_enabled(self):
        raise NotImplementedError()

    @property
    def current_thread(self):
        raise NotImplementedError()

    def is_valid_thread_id(self, threadId):
        raise NotImplementedError()

    def get_current_thread_id(self):
        """! From GDB's point of view, where Handler Mode is a thread"""
        raise NotImplementedError()

    def get_actual_current_thread_id(self):
        """! From OS's point of view, so the current OS thread even in Handler Mode"""
        raise NotImplementedError()
