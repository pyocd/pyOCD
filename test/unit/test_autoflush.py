# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

from .conftest import mock

from pyocd.core.exceptions import TransferError
from pyocd.utility.autoflush import Autoflush

@pytest.fixture(scope='function')
def mock_obj():
    return mock.Mock()

class TestAutoflush:
    def test_flushed(self, mock_obj):
        with Autoflush(mock_obj):
            pass
        assert mock_obj.flush.called

    def test_transfer_err_not_flushed(self, mock_obj):
        with pytest.raises(TransferError):
            with Autoflush(mock_obj):
                raise TransferError("bad joojoo")
        assert mock_obj.flush.not_called

