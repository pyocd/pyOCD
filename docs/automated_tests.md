Automated Tests
===============

Both unit tests and functional tests are used to verify pyOCD.

The primary difference between unit tests and functional tests is that unit tests will work without
a debug probe connected. Some unit tests do take advantage of a connected probe to expand testing,
but those tests will be skipped if no probe is present. In contrast, all functional tests require
at least one probe to be connected.


## Unit tests

The unit tests are located in the `pyocd/tests/` directory of the repo. They must be executed using
pytest, as they rely on the advanced capabilities of this tool.

To run the unit tests, simply invoke `pytest` in the root directory of the repo. Read the pytest
usage to see the many options it provides.

To get code coverage results, do the following:

```
$ pytest --cov-report=html --cov=pyocd
$ firefox htmlcov/index.html
```

## Functional tests

A series of quite comprehensive functional tests are provided in the `test/` directory. The primary
script for running these tests is `automated_test.py`. It will execute all functional tests in
sequence for all connected debug probes, then produce a summary and JUnit-style XML report. This
script is used to execute our CI test plan, and we frequently use it on our personal development
systems to test prior to creating pull requests.

Functional tests:

- `basic_test.py`: a simple test that checks a range of basic functionality, from flash programming to accessing memory and core registers.
- `blank_test.py`: tests ability to connect to devices with with blank flash. (Not run by `automated_test.py`.)
- `connect_test.py`: tests all combinations of the halt on connect and disconnect resume options.
- `cortex_test.py`: validates CPU control operations and memory accesses.
- `debug_context_test.py`: tests some `DebugContext` classes.
- `flash_test.py`: comprehensive test of flash programming.
- `flash_loader_test.py`: test the classes in the `pyocd.flash.loader` module.
- `gdb_server_json_test.py`: validates the JSON output from pyocd-gdbserver used by tools like the GNU MCU Eclipse pyOCD plugin.
- `gdb_test.py`: tests the gdbserver by running a script in a gdb process. Note that on Windows,
    the 32-bit Python 2.7 must be installed for the Python-enabled gdb to work properly and for
    this test to pass.
- `parallel_test.py`: checks for issues with accessing debug probes from multiple processes and threads simultaneously. (Not run by `automated_test.py`.)
- `speed_test.py`: performance test for memory reads and writes.


