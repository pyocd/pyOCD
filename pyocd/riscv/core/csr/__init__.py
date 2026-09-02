# pyOCD debugger
# Copyright (c) 2026 Ryan QIAN
# SPDX-License-Identifier: Apache-2.0

"""CSR register support package for RISC-V targets."""

from .loader import load_csr_configs

__all__ = ["load_csr_configs"]
