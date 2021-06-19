Contributing
============

We appreciate your contributions! Because this is an open source project, we want to keep it as easy
as possible to contribute changes. However, we need contributors to follow a few guidelines.

By contributing to pyOCD you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).


## Coding style

Contributed source code must follow [PEP8](https://www.python.org/dev/peps/pep-0008/) style
conventions.

Significant new code must use type annotations. However, until the bulk of pyOCD code is converted to have type
annotations, static type checking isn't actual performed by CI. Also, it is perfectly ok to fix bugs without annotating
the errant module.

Other formatting requirements:
- 4 space indents, no tabs are allowed.
- No trailing whitespace.
- All source files must end with a newline (an empty line at the end).
- Lines should generally not be longer than 120 characters, though this is not a hard rule. Overall readability
  is more important.


## Process

Before you submit your changes, please ensure that:

- The code meets style requirements listed above.
- You have added your copyright below existing copyrights in the files you modified. New files should have only
  your copyright. See the License section below for more.
- Changes have been tested locally to the extent possible. (Obviously, we don't expect you to have as many
  test boards as we do.)

Please [create a new pull request](https://github.com/pyocd/pyOCD/pull/new/develop) on GitHub with your contribution.
The new pull request should target the `develop` branch. Before creating the pull request, please ensure that all tests
pass. We also run the tests on a wide range of boards for every pull request using our CI setup. Changes must pass all
required pull request checks before they can be accepted.

The [developers' guide](docs/developers_guide.md) describes how to create your development
environment. The [automated tests guide](docs/automated_tests.md) provides information about the
available types of tests and describes how to run the tests.


## License

By creating a pull request on GitHub asking to merge your content into pyOCD, you agree to the [Developer Certificate of
Origin](https://developercertificate.org), stating that you have the right to grant license to your contribution under
the Apache 2.0 license.

Copyright on contributions is retained by their author(s). Please add the author(s) copyright below existing copyrights
in the license header at the top of the contributed source file(s). If you are doing the work for your employer, you
should use your employer's copyright. If a file is newly added by you, it must contain the standard license header with
your copyright. Please note that we do not list changes in each source file by copyright owner, as this becomes a burden
to maintain.

PyOCD follows the "inbound = outbound" licensing policy. This is [the default](https://docs.github.com/en/github/site-policy/github-terms-of-service#6-contributions-under-repository-license) for the GitHub Terms of Service.

Contributing source code that is already licensed using a license other than Apache 2.0 is possible, but each
case must be considered individually. If you are the owner of the source code, then you have the right to
relicense to Apache 2.0. The most important thing is that the license is compatible with Apache 2.0. Examples
are MIT, the BSD licenses, and similar. GPL-licensed code is expressly disallowed to be contributed, as the
GPL is not compatible with Apache 2.0 (or any of the Apache-compatible licenses).


