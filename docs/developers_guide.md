pyOCD Developers' Guide
=======================

## Setup

PyOCD developers are strongly recommended to setup a working environment using either
[virtualenv](https://virtualenv.pypa.io/en/latest/) or the built-in `venv` module (only use of virtualenv is shown
below, but the two are equivalent). After cloning the code, you can setup a virtualenv and install the pyOCD
dependencies for the current platform by following the detailed steps below.

Install the necessary tools listed below. Skip any step where a compatible tool already exists.

* [Install Python](https://www.python.org/downloads/) version 3.6.0 or above. Add to PATH.
    *  Note that on Windows, the 32-bit Python 2.7 must be installed for the Python-enabled `arm-none-eabi-gdb-py` to
        work properly and for the `test/gdb_test.py` functional test to pass.
* [Install Git](https://git-scm.com/downloads). Add to PATH.
* [Install virtualenv](https://virtualenv.pypa.io/en/latest/) in your global Python installation, eg: `pip install virtualenv`. Not needed if using the built-in `venv` module.
* [Install GNU Arm Embedded toolchain](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm).
    This provides `arm-none-eabi-gdb` used for testing the gdbserver. Add to PATH.

## Steps

**Step 1.** Get the sources and create a virtual environment

```
$ git clone https://github.com/pyocd/pyOCD
$ cd pyOCD
$ virtualenv venv
```

**Step 2.** Activate virtual environment

Activate your virtualenv and install the pyOCD dependencies for the current platform by doing
the following.

Linux or Mac:
```
$ source venv/bin/activate
$ pip install -r dev-requirements.txt
```

Windows:
```
$ venv\Scripts\activate
$ pip install -r dev-requirements.txt
```

**Step 3.** Develop

See the [porting guide](adding_new_targets.md) for how to add new devices. Of course, we welcome
all improvements and changes. See the [contributor statement](../CONTRIBUTING.md) for some guidelines.

Normally you should work from the `develop` branch. See the [branch policy](#branch-configuration-policy) below for
more information about branches.

**Step 4.** Test

To run the unit tests, you can execute the following.

```
$ pytest
```

To get code coverage results, do the following:

```
$ pytest --cov-report=html --cov=pyocd
$ open htmlcov/index.html
```

The automated test suite also needs to be run:

```
$ cd test
$ python ./automated_test.py
```

**Step 5.** Pull request

Once you are satisfied with your changes and all automated tests pass, please create a
[new pull request](https://github.com/pyocd/pyOCD/pull/new/develop) against the `develop` branch on GitHub to share your work.

Pull requests should be made after a changeset is [rebased onto `develop`](https://www.atlassian.com/git/tutorials/merging-vs-rebasing/workflow-walkthrough).


## Branch configuration policy

There are two primary branches:

- `main`: Stable branch reflecting the most recent release.
- `develop`: Active development branch for the next version. Merged into `main` at release time.

There may be other development branches present to host long term development of major new features and backwards incompatible changes, such as API changes.

Changes should generally be made against the `develop` branch.
