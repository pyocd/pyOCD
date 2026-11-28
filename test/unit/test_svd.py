# pyOCD debugger
# Copyright (c) 2023 Chris Reed
# Copyright (c) 2026 Andrew Jessop
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

import io
import zipfile
from xml.etree import ElementTree as ET

import pytest

from pyocd.debug.svd.parser import SVDParser
from pyocd.debug.svd.loader import (
    SVDFile,
    SVDLoader,
)

class TestIntervalSvdAccess:
    def builtin_svd(self, name: str) -> SVDLoader:
        def completion(dev):
            pass
        loader = SVDLoader(SVDFile.from_builtin(name), completion)
        loader.run()
        return loader

    def test_load(self):
        loader = self.builtin_svd('Musca_B1.svd')
        assert loader.device
        assert [p for p in loader.device.peripherals if p.name == 'UART0']



SVD_XML = """<?xml version="1.0" encoding="utf-8"?>
<device><name>Example</name><version>1.0</version>
<description> A register description </description>
<addressUnitBits>8</addressUnitBits><width>32</width>
<peripherals><peripheral><name>UART</name><baseAddress>0x40000000</baseAddress>
<registers><register><name>DATA</name><addressOffset>0x4</addressOffset>
<size>32</size></register></registers></peripheral></peripherals></device>
"""


@pytest.mark.parametrize("prefix", ["", "  ", "\t\r\n "])
@pytest.mark.parametrize("source_kind", ["path", "binary", "text", "zip"])
def test_svd_xml_declaration_whitespace(tmp_path, prefix, source_kind):
    """Vendor packs can have whitespace before their XML declaration (#1887)."""
    content = (prefix + SVD_XML).encode("utf-8")
    if source_kind == "path":
        source = tmp_path / "device.svd"
        source.write_bytes(content)
    elif source_kind == "binary":
        source = io.BytesIO(content)
    elif source_kind == "text":
        source = io.StringIO(prefix + SVD_XML)
    else:
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as pack:
            pack.writestr("device.svd", content)
        pack = zipfile.ZipFile(archive)
        source = pack.open("device.svd")
    try:
        svd = SVDFile(source)
        svd.load()
        assert svd.device.name == "Example"
        assert svd.device.description == " A register description "
        uart, = svd.device.peripherals
        assert uart.base_address == 0x40000000
        data, = uart.registers
        assert data.name == "DATA"
        assert data.address_offset == 4
        assert data.size == 32
        if source_kind != "path":
            assert not source.closed
    finally:
        if source_kind != "path":
            source.close()
        if source_kind == "zip":
            pack.close()


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-16-be"])
def test_svd_xml_encoding(encoding):
    xml = SVD_XML.replace('encoding="utf-8"', 'encoding="utf-16"') if encoding.startswith("utf-16") else SVD_XML
    device = SVDParser.for_xml_file(io.BytesIO(xml.encode(encoding))).get_device()
    assert device.name == "Example"


@pytest.mark.parametrize("xml", ["", "  <?xml version=\"1.0\"?><device>",
                                 "<!--comment--><?xml version=\"1.0\"?><device/>"])
def test_svd_invalid_xml_still_fails(xml):
    with pytest.raises(ET.ParseError):
        SVDParser.for_xml_file(io.BytesIO(xml.encode("utf-8")))
