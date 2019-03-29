pyOCD Developers' Guide
=======================

PyOCD developers are recommended to setup a working environment using
[virtualenv](https://virtualenv.pypa.io/en/latest/). After cloning
the code, you can setup a virtualenv and install the pyOCD
dependencies for the current platform by following the detailed steps below.

## Setup

Install the necessary tools listed below. Skip any step where a compatible tool already exists.

* [Install Python](https://www.python.org/downloads/). It is recommended that you install both
    Python 3.7.0 or above and Python 2.7.15 or above, in order to test under both versions. Add to
    PATH.
    *  Note that on Windows, the 32-bit Python 2.7 must be installed for the Python-enabled gdb to
        work properly and for the `test/gdb_test.py` functional test to pass.
* [Install Git](https://git-scm.com/downloads). Add to PATH.
* [Install virtualenv](https://virtualenv.pypa.io/en/latest/) in your global Python installation, eg: `pip install virtualenv`.
* [Install GNU Arm Embedded toolchain](https://developer.arm.com/tools-and-software/open-source-software/gnu-toolchain/gnu-rm).
    This provides `arm-none-eabi-gdb` used for testing the gdbserver. Add to PATH.

## Steps

**Step 1.** Get the sources and create a virtual environment

```
$ git clone https://github.com/mbedmicro/pyOCD
$ cd pyOCD
$ virtualenv venv
```

You may wish to create two virtual environments, for both Python 2.7 and 3.x.

```
$ python2 -mvirtualenv venv2
$ python3 -mvirtualenv venv3
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
[new pull request](https://github.com/mbedmicro/pyOCD/pull/new/master) on GitHub to share your work.

Pull requests should be made once a changeset is [rebased onto Master](https://www.atlassian.com/git/tutorials/merging-vs-rebasing/workflow-walkthrough).

