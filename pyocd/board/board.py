# pyOCD debugger
# Copyright (c) 2006-2013,2018 Arm Limited
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

import logging
from typing import (Any, Optional, TYPE_CHECKING)

from ..core import exceptions
from ..target import TARGET
from ..target.pack import pack_target
from ..utility.graph import GraphNode

if TYPE_CHECKING:
    from ..core.session import Session

LOG = logging.getLogger(__name__)

class Board(GraphNode):
    """@brief Represents the board containing the target and associated components.

    The board is the root of the runtime object graph.
    """
    def __init__(self,
            session: "Session",
            target: Optional[str] = None,
            ) -> None:
        """@brief Constructor

        This method is responsible for selecting the SoCTarget subclass for the SoC, implementing the target
        type support. There are several possible sources for the target type name, with differing levels of
        priority.

        1. `target` parameter
        2. `target_override` session option
        3. `soft_target` parameter
        4. Last resort `cortex_m` target type. If this type is used, a warning is printed (unless the
            `warning.cortex_m_default` option is disabled).

        @param self
        @param session The session instance that owns us.
        @param target Target type name to use. If this parameter is set, it overrides all other sources of the
            target type.
        """
        super().__init__()

        # Use the session option if no target type was given to us.
        if target is None:
            target = session.options.get('target_override')

        # As a last resort, default the target to 'cortex_m'.
        if target is None:
            target = 'cortex_m'

            # Log a helpful warning when defaulting to the generic cortex_m target.
            if session.options.get('warning.cortex_m_default'):
                LOG.warning("Generic 'cortex_m' target type is selected by default; is this "
                            "intentional? You will be able to debug most devices, but not program "
                            " flash. To set the target type use the '--target' argument or "
                            "'target_override' option. Use 'pyocd list --targets' to see available "
                            "targets types.")

        assert target is not None

        # Convert dashes to underscores in the target type, and convert to lower case.
        target = target.replace('-', '_').lower()

        # Write the effective target type back to options if it's different.
        if target != session.options.get('target_override'):
            session.options['target_override'] = target

        self._session = session
        self._target_type = target
        self._test_binary = session.options.get('test_binary')
        self._delegate = None
        self._inited = False

        # Create targets from provided CMSIS pack.
        if session.options['pack'] is not None:
            pack_target.PackTargets.populate_targets_from_pack(session.options['pack'])

        # Create targets from the cmsis-pack-manager cache.
        if self._target_type not in TARGET:
            pack_target.ManagedPacks.populate_target(target)

        # Create Target instance.
        try:
            self.target = TARGET[self._target_type](session)
        except KeyError as exc:
            raise exceptions.TargetSupportError(
                f"Target type {self._target_type} not recognized. Use 'pyocd list --targets' to see currently "
                "available target types. "
                "See <https://github.com/pyocd/pyOCD/blob/master/docs/target_support.md> "
                "for how to install additional target support.") from exc

        # Tell the user what target type is selected.
        LOG.info("Target type is %s", self._target_type)

        self.add_child(self.target)

    def init(self) -> None:
        """@brief Initialize the board."""
        # If we don't have a delegate set yet, see if there is a session delegate.
        if (self.delegate is None) and (self.session.delegate is not None):
            self.delegate = self.session.delegate

        # Delegate pre-init hook.
        if (self.delegate is not None) and hasattr(self.delegate, 'will_connect'):
            self.delegate.will_connect(board=self)

        # Init the target.
        self.target.init()
        self._inited = True

        # Delegate post-init hook.
        if (self.delegate is not None) and hasattr(self.delegate, 'did_connect'):
            self.delegate.did_connect(board=self)

    def uninit(self) -> None:
        """@brief Uninitialize the board."""
        if self._inited:
            LOG.debug("uninit board %s", self)
            try:
                resume = self.session.options.get('resume_on_disconnect')
                self.target.disconnect(resume)
                self._inited = False
            except exceptions.Error as err:
                LOG.error("link exception during target disconnect: %s", err, exc_info=self._session.log_tracebacks)

    @property
    def session(self) -> "Session":
        """@brief The session that owns this board instance."""
        return self._session

    @property
    def delegate(self) -> Any:
        """@brief Delegate object that will be inherited by the SoCTarget."""
        return self._delegate

    @delegate.setter
    def delegate(self, the_delegate: Any) -> None:
        """@brief Set the delegate object that will be inherited by the SoCTarget."""
        self._delegate = the_delegate

    @property
    def unique_id(self) -> str:
        """@brief The probe's unique ID.

        Deprecated. Use the probe's `unique_id` property instead.
        """
        assert self.session.probe
        return self.session.probe.unique_id

    @property
    def target_type(self) -> str:
        """@brief Target type name."""
        return self._target_type

    @property
    def test_binary(self) -> Optional[str]:
        return self._test_binary

    @property
    def name(self) -> str:
        return "generic"

    @property
    def description(self) -> str:
        assert self.session.probe
        return "Generic board via " + self.session.probe.vendor_name + " " \
                + self.session.probe.product_name + " [" + self.target_type + "]"
