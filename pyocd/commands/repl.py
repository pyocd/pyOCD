# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
# Copyright (c) 2021 Chris Reed
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import traceback
import atexit

# Attempt to import readline.
try:
    import readline
except ImportError:
    pass

from ..core import (session, exceptions)

LOG = logging.getLogger(__name__)

class ToolExitException(Exception):
    """! @brief Special exception indicating the tool should exit.
    
    This exception is only raised by the `exit` command.
    """
    pass

class PyocdRepl(object):
    """! @brief Read-Eval-Print-Loop for pyOCD commander."""
    
    PROMPT = 'pyocd> '
    
    PYOCD_HISTORY_ENV_VAR = 'PYOCD_HISTORY'
    PYOCD_HISTORY_LENGTH_ENV_VAR = 'PYOCD_HISTORY_LENGTH'
    DEFAULT_HISTORY_FILE = ".pyocd_history"

    def __init__(self, command_context):
        self.context = command_context
        
        # Enable readline history.
        self._history_path = os.environ.get(self.PYOCD_HISTORY_ENV_VAR,
                os.path.join(os.path.expanduser("~"), self.DEFAULT_HISTORY_FILE))
        
        # Read command history and set history length.
        try:
            readline.read_history_file(self._history_path)
            
            history_len = int(os.environ.get(self.PYOCD_HISTORY_LENGTH_ENV_VAR,
                    session.Session.get_current().options.get('commander.history_length')))
            readline.set_history_length(history_len)
        except (NameError, IOError) as err:
            pass

        # Install exit handler to write out the command history.
        try:
            atexit.register(readline.write_history_file, self._history_path)
        except (NameError, IOError) as err:
            pass

    def run(self):
        """! @brief Runs the REPL loop until EOF is encountered."""
        try:
            while True:
                try:
                    line = input(self.PROMPT)
                    self.run_one_command(line)
                except KeyboardInterrupt:
                    print()
        except EOFError:
            # Print a newline when we get a Ctrl-D on a Posix system.
            # Windows exits with a Ctrl-Z+Return, so there is no need for this.
            if os.name != "nt":
                print()
        except ToolExitException:
            pass
    
    def run_one_command(self, line):
        """! @brief Execute a single command line and handle exceptions."""
        try:
            line = line.strip()
            if line:
                self.context.process_command_line(line)
        except KeyboardInterrupt:
            print()
        except ValueError:
            print("Error: invalid argument")
            if session.Session.get_current().log_tracebacks:
                traceback.print_exc()
        except exceptions.TransferError as e:
            print("Transfer failed:", e)
            if session.Session.get_current().log_tracebacks:
                traceback.print_exc()
        except exceptions.CommandError as e:
            print("Error:", e)
        except ToolExitException:
            # Catch and reraise this exception so it isn't caught by the catchall below.
            raise
        except Exception as e:
            # Catch most other exceptions so they don't cause the REPL to exit.
            print("Error:", e)
            if session.Session.get_current().log_tracebacks:
                traceback.print_exc()
