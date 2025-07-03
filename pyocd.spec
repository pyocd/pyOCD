# --- Imports ---
import os
import sys
from PyInstaller.utils.hooks import get_package_paths, collect_entry_point, collect_dynamic_libs

# --- Configuration ---
SITE_PACKAGES = os.getenv('SITE_PACKAGES', '')
APP_NAME = 'pyocd'
DEBUG = False

# --- Entry Points ---
datas_probe, hiddenimports_probe = collect_entry_point('pyocd.probe')
datas_rtos, hiddenimports_rtos = collect_entry_point('pyocd.rtos')

# --- Data Files ---
datas = [
    (get_package_paths('pyocd')[1], 'pyocd'),
    (get_package_paths('pylink')[1], 'pylink'),
    ('pyocd/debug/sequences/sequences.lark', 'pyocd/debug/sequences'),
    ('pyocd/debug/svd/svd_data.zip', 'pyocd/debug/svd')
]
datas.append((get_package_paths('cmsis_pack_manager')[1], 'cmsis_pack_manager'))

# --- Analysis Configuration ---
a = Analysis(
    ['pyocd.py'],
    pathex=[],
    binaries=collect_dynamic_libs('cmsis_pack_manager') + collect_dynamic_libs('libusb_package'),
    datas=datas + datas_probe + datas_rtos,
    hiddenimports=hiddenimports_probe + hiddenimports_rtos,
    excludes=['tkinter'],
    runtime_hooks=[],
    cipher=None,
    noarchive=False
)

# --- Build Components ---
pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    [],  # Empty list for directory build
    exclude_binaries=True,
    name=APP_NAME,
    debug=DEBUG,
    strip=False,
    upx=True,
    console=True
)

# --- Output Collection ---
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name=APP_NAME
)
