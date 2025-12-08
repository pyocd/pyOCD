from __future__ import annotations

import zipfile
from pathlib import Path

from setuptools.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist


def _ensure_svd_zip() -> None:
    script_dir = Path(__file__).resolve().parent
    svd_dir_path = script_dir / "debug" / "svd"
    svd_data_dir_path = svd_dir_path / "data"
    svd_zip_path = svd_dir_path / "svd_data.zip"

    if svd_data_dir_path.exists():
        with zipfile.ZipFile(svd_zip_path, "w", zipfile.ZIP_DEFLATED) as svd_zip:
            for svd_file in sorted(svd_data_dir_path.iterdir()):
                if svd_file.is_file():
                    svd_zip.write(svd_file, svd_file.name)
    elif not svd_zip_path.exists():
        raise RuntimeError(
            "neither the source SVD data directory nor built svd_data.zip exist",
        )


class build_py(_build_py):
    def run(self) -> None:
        _ensure_svd_zip()
        super().run()


class sdist(_sdist):
    def run(self) -> None:
        _ensure_svd_zip()
        super().run()
