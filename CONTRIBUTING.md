Contributing
============

We appreciate your contributions! Because this is an open source project, we want to keep it as easy
as possible to contribute changes. However, we need contributors to follow a few guidelines.


## Coding style

Contributed source code must follow [PEP8](https://www.python.org/dev/peps/pep-0008/) style
conventions.

Other formatting requirements:
- 4 space indents, no tabs are allowed.
- No trailing whitespace.
- All source files must end with a newline (an empty line at the end).
- Lines should generally not be longer than 120 characters, though this is not a hard rule.


## Process

Please create a pull request in GitHub with your contribution. Before creating the pull request,
please ensure that all tests pass. We also run the tests on a wide range of boards for every pull
request using our CI setup. Changes must pass on all tested boards before the the pull request can
be merged.

The [developers' guide](docs/developers_guide.md) describes how to create your development
environment. The [automated tests guide](docs/automated_tests.md) provides information about the
available types of tests and describes how to run the tests.


## More

For more information about contributing, see the Mbed OS [contributor
documentation](http://os.mbed.com/contributing). Although this documentation is written primarily
with Mbed OS in mind, much of it applies directly to pyOCD, as well.
