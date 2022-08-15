---
title: Automated tests
---

Both unit tests and functional tests are used to verify pyOCD.

The primary difference between unit tests and functional tests is that unit tests will work without
a debug probe connected. Some unit tests do take advantage of a connected probe to expand testing,
but those tests will be skipped if no probe is present. In contrast, all functional tests require
at least one probe to be connected.


## Test Setup

For test setup it is good practice to create a virtualenv in the repos root subdirectory.  Otherwise expect weird
behavior during tests.

```bash
$ python -mvenv --upgrade-deps .venv
$ source .venv/bin/activate
$ pip install -e .[test]
$ pytest
```

To make the tests pick the correct setup, a [`pyocd.yaml` configuration file](configuration.md) has to be used.
For functional testing the file should contain a reference to a `test_binary` from `test/data/binaries`.

Example config file:

```yaml
probes:
  E6614103E7176A23: # Probe's unique ID.
    target_override:  nrf52
    test_binary:      l1_nrf52840-dk.bin
    frequency:        6000000
```


## Unit tests

The unit tests are located in the `tests/unit` directory of the repo. They must be executed using
pytest, as they rely on the advanced capabilities of this tool.

To run the unit tests, simply invoke `pytest` in the root directory of the repo. Read the pytest
help to see the many options it provides.

To get code coverage results, do the following:

```
$ pytest --cov-report=html --cov=pyocd
$ open htmlcov/index.html
```

Note: The `semihosting.py` unit test requires a target connection and test binary. It is currently the only unit that uses a target. When no targets are available the test cases will be skipped.


## Functional tests

A series of fairly comprehensive functional tests are provided in the `test/` directory.

The primary script for running these tests is `automated_test.py`. It will execute all functional tests in
sequence for all connected debug probes, then produce a summary and JUnit-style XML report. This
script is used to execute our CI test plan, and we frequently use it on our personal development
systems to test prior to creating pull requests.

The `automated_test.py` script has several command line arguments that can be used to control which test suites are run and on which debug probes. Use `--list-tests` to see available test suite names. Comma-separated lists of these names can be passed to the `-x` / `--exclude-tests` or `-i` / `--include-tests` arguments to exclude and include tests, respectively. Only one of these two arguments can be used at a time.

The `-b` / `--board` argument is used to select a debug probe on which tests will be run. By default, tests will run on all available debug probes. Adding any `--board` arguments restricts tests to run on only the specified set of debug probes.

### List of functional tests

Test scripts with an "n/a" for the test name are not run by `automated_test.py` (or in CI) and have to be run directly with Python.

<table>

<tr><th width="20%">Test name</th><th width="20%">File</th><th>Description</th></tr>

<tr><td>Basic Test</td><td><tt>basic_test.py</tt></td><td>
Simple test that checks a range of basic functionality, from flash programming to accessing memory and core registers.
</td></tr>

<tr><td>n/a</td><td><tt>blank_test.py</tt></td><td>
Tests ability to connect to devices with with blank flash.
</td></tr>

<tr><td>Commander Test</td><td><tt>commander_test.py</tt></td><td>
Tests the <tt>pyocd commander</tt> functionality.
</td></tr>

<tr><td>Commands Test</td><td><tt>commands_test.py</tt></td><td>
Tests commands supported by commander and gdb monitor commands.
</td></tr>

<tr><td>Concurrency Test</td><td><tt>concurrency_test.py</tt></td><td>
Verify multiple threads can simultaneously access a debug probe, specifically for memory transfers.
</td></tr>

<tr><td>Connect Test</td><td><tt>connect_test.py</tt></td><td>
Tests all combinations of the halt on connect and disconnect resume options.
</td></tr>

<tr><td>Cortex Test</td><td><tt>cortex_test.py</tt></td><td>
Validates CPU control operations and memory accesses.
</td></tr>

<tr><td>Debug Context Test</td><td><tt>debug_context_test.py</tt></td><td>
Tests some <tt>DebugContext</tt> classes.
</td></tr>

<tr><td>Flash Loader Test</td><td><tt>flash_loader_test.py</tt></td><td>
Test the classes in the <tt>pyocd.flash.loader</tt> module.
</td></tr>

<tr><td>Flash Test</td><td><tt>flash_test.py</tt></td><td>
Comprehensive test of flash programming.
</td></tr>

<tr><td>n/a</td><td><tt>import_all_.py</tt></td><td>
Imports all pyocd modules. Run by the GitHub "basic test" workflow.
</td></tr>

<tr><td>Gdb Test</td><td><tt>gdb_test.py</tt></td><td>
Tests the gdbserver by running the <tt>gdb_test_script.py</tt> script in a gdb process.
Note that on Windows, the 32-bit Python 2.7 must be installed for the Python-enabled <tt>arm-none-eabi-gdb</tt> to work properly and for this test to pass.
</td></tr>

<tr><td>Json Lists Test</td><td><tt>json_lists_test.py</tt></td><td>
Validates the JSON output from <tt>pyocd json</tt>.
</td></tr>

<tr><td>n/a</td><td><tt>parallel_test.py</tt></td><td>
Checks for issues with accessing debug probes from multiple processes and threads simultaneously.
</td></tr>

<tr><td>Probeserver Test</td><td><tt>probeserver_test.py</tt></td><td>
Verify remote probe server and client.
</td></tr>

<tr><td>Speed Test</td><td><tt>speed_test.py</tt></td><td>
Performance test for memory reads and writes.
</td></tr>

<tr><td>User Script Test</td><td><tt>user_script_test.py</tt></td><td>
Verify loading of user scripts.
</td></tr>

</table>


## Test binaries

The functional tests and some unit tests (currently only `test/unit/semihosting.py`) require a test firmware binary in order to run. This firmware can be extremely simple. The only requirement is that it have a valid vector table and be executable when loaded to the base of the boot memory. Ideally an LED is blinked so there is an easily-identifiable visual signal that the firmware is running.

Built-in targets almost all include a test binary in the pyOCD repository under `test/data/binaries/`. If the board has a board ID, e.g., those listed in `pyocd/board/board_ids.py`, the test binary is automatically identified.

If the target is not built-in (DFP) or does not have a board ID then, the `test_binary` session option must be set to the path of a test firmware binary file relative to the `test/data/binaries` directory. This can be conveniently added as probe-specific options in a `pyocd.yaml` config file placed under `test/`.


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

Currently only the functional tests are included in the tox configuration.
