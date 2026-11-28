# pyOCD debugger
# Copyright (c) 2026 Solarboaters
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

import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("kind", ["config", "logging"])
def test_yaml_encoding(tmp_path, kind, encoding):
    text = "# café\nfrequency: 123456\n" if kind == "config" else (
        "# café\nversion: 1\ndisable_existing_loggers: false\n"
        "loggers:\n  encoding_test:\n    level: ERROR\n")
    data = text.encode(encoding)
    if encoding == "utf-16-le":
        data = b"\xff\xfe" + data
    elif encoding == "utf-16-be":
        data = b"\xfe\xff" + data
    path = tmp_path / "settings.yaml"
    path.write_bytes(data)
    if kind == "config":
        code = "s = Session(None, config_file=sys.argv[1]); assert s.options['frequency'] == 123456"
    else:
        code = ("s = Session(None, no_config=True, logging=sys.argv[1]); "
                "assert logging.getLogger('encoding_test').level == logging.ERROR")
    _run_in_c_locale(path, code)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "latin-1"])
def test_user_script_encoding(tmp_path, encoding):
    cookie = "# coding: latin-1\n" if encoding == "latin-1" else ""
    path = tmp_path / "pyocd_user.py"
    path.write_bytes((cookie + "# café\noptions['frequency'] = 654321\n").encode(encoding))
    _run_in_c_locale(path,
        "s = Session(None, no_config=True, user_script=sys.argv[1]); "
        "s._load_user_script(); assert s.options['frequency'] == 654321")


def _run_in_c_locale(path, code):
    env = dict(os.environ, LC_ALL="C", PYTHONUTF8="0", PYTHONCOERCECLOCALE="0")
    result = subprocess.run([sys.executable, "-c",
        "import sys, logging; from pyocd.core.session import Session; " + code, str(path)],
        env=env, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
