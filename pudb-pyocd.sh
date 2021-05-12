#!/bin/sh

# This script allows pyOCD debug directly in Unix shell.
# 
# You can insert breakpoint with `import pudb; pudb.set_trace()`.
#
# Copyright (c) 2021 Tomasz "CeDeROM" CEDRO
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

pip install -U pudb > /dev/null
pudb3 -m pyocd $@
