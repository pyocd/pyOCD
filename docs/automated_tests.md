---
title: Automated tests
---

Both unit tests and functional tests are used to verify pyOCD.

The primary difference between unit tests and functional tests is that unit tests will work without
a debug probe connected. Some unit tests do take advantage of a connected probe to expand testing,
but those tests will be skipped if no probe is present. In contrast, all functional tests require
at least one probe to be connected.


## Unit tests

The unit tests are located in the `tests/unit` directory of the repo. They must be executed using
pytest, as they rely on the advanced capabilities of this tool.

To run the unit tests, simply invoke `pytest` in the root directory of the repo. Read the pytest
usage to see the many options it provides.

To get code coverage results, do the following:

```
$ pytest --cov-report=html --cov=pyocd
$ open htmlcov/index.html
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
- `commander_test.py`: tests the `pyocd commander` functionality.
- `commands_test.py`: tests commands supported by commander and gdb monitor commands.
- `concurrency_test.py`: verify multiple threads can simultaneously access a debug probe, specifically for memory
    transfers.
- `connect_test.py`: tests all combinations of the halt on connect and disconnect resume options.
- `cortex_test.py`: validates CPU control operations and memory accesses.
- `debug_context_test.py`: tests some `DebugContext` classes.
- `flash_loader_test.py`: test the classes in the `pyocd.flash.loader` module.
- `flash_test.py`: comprehensive test of flash programming.
- `import_all.py`: imports all pyocd modules. (Not run by `automated_test.py`.)
- `gdb_test.py`: tests the gdbserver by running a script in a gdb process. Note that on Windows,
    the 32-bit Python 2.7 must be installed for the Python-enabled gdb to work properly and for
    this test to pass.
- `json_lists_test.py`: validates the JSON output from `pyocd json`.
- `parallel_test.py`: checks for issues with accessing debug probes from multiple processes and threads simultaneously. (Not run by `automated_test.py`.)
- `probeserver_test.py`: verify remote probe server and client.
- `speed_test.py`: performance test for memory reads and writes.
- `user_script_test.py`: verify loading of user scripts.

## Azure Pipelines

PyOCD uses Azure Pipelines to run the CI tests for commits and pull requests. The pipeline runs the functional tests on
a set of test machines, called self-hosted test agents in Azure Pipelines parlance. There is one each of Mac, Linux, and
Windows test agents.

The complete results from pipeline runs are [publicly
accessible](https://dev.azure.com/pyocd/pyocd/_build?definitionId=1&_a=summary).

For pull requests, a pyOCD team member or collaborator must manually initiate the pipeline run by entering a special
comment of the form "/azp run" or "/AzurePipelines run".


## Testing with tox

pyOCD includes a configuration file for tox that enables easy testing of multiple Python versions.
The tox tool is included in `test` install extra, so it will already be present in a standard
pyOCD developer virtual environment.

To run the functional tests via tox, just execute `tox` from the root of the pyOCD
repo. It will create new virtual environments for each Python version and run `automated_test.py`.

Currently only the functions tests are included in the tox configuration.
