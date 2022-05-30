#!/usr/bin/env bash
# Fill the version with the current commit number to simplify local debug

FULL_SCRIPT_PATH="$(pwd)/${0}"
PROJECT_DIR="${FULL_SCRIPT_PATH%/*}"
cd "${PROJECT_DIR}"

echo "version = '$(git describe --long --always)'" > pyocd/_version.py

# Now you can run the following command inside of $PROJECT_DIR
# python3.8 -m pyocd --version
