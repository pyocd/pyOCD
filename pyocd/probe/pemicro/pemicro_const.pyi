# Copyright 2020 NXP
# This is stub for pemicro_const.py, to provide typing informations
#
# SPDX-License-Identifier:
# BSD-3-Clause

#""
from typing import Any
from enum import IntEnum


class PEMicroPortType(IntEnum):...

class PEMicroSpecialFeatures(IntEnum):...

class PEMicroSpecialFeaturesSwdStatus(IntEnum):...

class PEMicroMemoryAccessResults(IntEnum):...

class PEMicroMemoryAccessSize(IntEnum):...

class PEMicroArmRegisters(IntEnum):...

class PEMicroInterfaces(IntEnum):
    @classmethod
    def get_str(cls, interface: Any) -> str:...
