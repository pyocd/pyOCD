# pyOCD debugger
# Copyright (c) 2018-2019 Arm Limited
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

from time import sleep
import colorama
import prettytable

from .session import Session
from ..probe.aggregator import DebugProbeAggregator

# Init colorama here since this is currently the only module that uses it.
colorama.init()

class ConnectHelper(object):
    """! @brief Helper class for streamlining the probe discovery and session creation process.
    
    This class provides several static methods that wrap the DebugProbeAggregator methods
    with a simple command-line user interface, or provide a single method that performs
    a common access pattern.
    """
    
    @staticmethod
    def get_sessions_for_all_connected_probes(blocking=True, unique_id=None, options=None, **kwargs):
        """! @brief Return a list of Session objects for all connected debug probes.
        
        This method is useful for listing detailed information about connected probes, especially
        those that have associated boards, as the Session object will have a Board instance.
        
        The returned list of sessions is sorted by the combination of the debug probe's
        description and unique ID.
        
        @param blocking Specifies whether to wait for a probe to be connected if there are no
              available probes.
        @param unique_id String to match against probes' unique IDs using a contains match. If the
              default of None is passed, then all available probes are matched.
        @param options Dictionary of session options.
        @param kwargs Session options passed as keyword arguments.
        
        @return A list of Session objects. The returned Session objects are not yet active, in that
              open() has not yet been called. If _blocking_ is True, the list will contain at least
              one session. If _blocking_ is False and there are no probes connected then an empty list
              will be returned.
        """
        probes = ConnectHelper.get_all_connected_probes(blocking=blocking, unique_id=unique_id)
        sessions = [Session(probe, options=options, **kwargs) for probe in probes]
        return sessions

    @staticmethod
    def get_all_connected_probes(blocking=True, unique_id=None, print_wait_message=True):
        """! @brief Return a list of DebugProbe objects for all connected debug probes.
        
        The returned list of debug probes is always sorted by the combination of the probe's
        description and unique ID.
        
        @param blocking Specifies whether to wait for a probe to be connected if there are no
              available probes. A message will be printed
        @param unique_id String to match against probes' unique IDs using a contains match. If the
              default of None is passed, then all available probes are matched.
        @param print_wait_message Whether to print a message to the command line when waiting for a
              probe to be connected and _blocking_ is True.
        
        @return A list of DebugProbe instances. If _blocking_ is True, the list will contain at least
              one probe. If _blocking_ is False and there are no probes connected then an empty list
              will be returned.
        """
        printedMessage = False
        while True:
            allProbes = DebugProbeAggregator.get_all_connected_probes(unique_id=unique_id)
            sortedProbes = sorted(allProbes, key=lambda probe:probe.description + probe.unique_id)

            if not blocking:
                break
            elif len(sortedProbes):
                break
            else:
                if print_wait_message and not printedMessage:
                    if unique_id is None:
                        msg = "Waiting for a debug probe to be connected..."
                    else:
                        msg = "Waiting for a debug probe matching unique ID '%s' to be connected..." % unique_id
                    print(colorama.Fore.YELLOW + msg + colorama.Style.RESET_ALL)
                    printedMessage = True
                sleep(0.01)
            assert len(sortedProbes) == 0

        return sortedProbes

    @staticmethod
    def list_connected_probes():
        """! @brief List the connected debug probes.   
        
        Prints a list of all connected probes to stdout. If no probes are connected, a message
        saying as much is printed instead.
        """
        allProbes = ConnectHelper.get_all_connected_probes(blocking=False)
        if len(allProbes):
            ConnectHelper._print_probe_list(allProbes)
        else:
            print(colorama.Fore.RED + "No available debug probes are connected" + colorama.Style.RESET_ALL)
        print(colorama.Style.RESET_ALL, end='')

    @staticmethod
    def choose_probe(blocking=True, return_first=False, unique_id=None):
        """! @brief Return a debug probe possibly chosen by the user.
        
        This method provides an easy to use command line interface for selecting one of the
        connected debug probes. It has parameters that control filtering of probes by unique ID and
        automatic selection of the first discovered probe.
        
        If, after application of the _unique_id_ and _return_first_ parameters, there are still
        multiple debug probes to choose from, the user is presented with a simple command-line UI
        to select a probe (or abort the selection process).
        
        @param blocking Specifies whether to wait for a probe to be connected if there are no
              available probes.
        @param return_first If more than one probe is connected, a _return_first_ of True will select
              the first discovered probe rather than present a selection choice to the user.
        @param unique_id String to match against probes' unique IDs using a contains match. If the
              default of None is passed, then all available probes are matched.
        
        @return Either None or a DebugProbe instance.
        """
        # Get all matching probes, sorted by name.
        allProbes = ConnectHelper.get_all_connected_probes(blocking=blocking, unique_id=unique_id)

        # Print some help if the user specified a unique ID, but more than one probe matches.
        if (unique_id is not None) and (len(allProbes) > 1) and not return_first:
            print(colorama.Fore.RED + "More than one debug probe matches unique ID '%s':" % unique_id + colorama.Style.RESET_ALL)
            unique_id = unique_id.lower()
            for probe in allProbes:
                head, sep, tail = probe.unique_id.lower().rpartition(unique_id)
                highlightedId = head + colorama.Fore.RED + sep + colorama.Style.RESET_ALL + tail
                print("%s | %s" % (
                    probe.description,
                    highlightedId))
            return None

        # Return if no boards are connected.
        if allProbes is None or len(allProbes) == 0:
            if unique_id is None:
                print(colorama.Fore.RED + "No connected debug probes" + colorama.Style.RESET_ALL)
            else:
                print(colorama.Fore.RED + "No connected debug probe matches unique ID '%s'" %
                    unique_id + colorama.Style.RESET_ALL)
            return None # No boards to close so it is safe to return

        # Select first board
        if return_first:
            return allProbes[0]

        # Ask user to select boards if there is more than 1 left
        if len(allProbes) > 1:
            ConnectHelper._print_probe_list(allProbes)
            while True:
                print(colorama.Style.RESET_ALL)
                print("Enter the number of the debug probe or 'q' to quit", end='')
                line = input("> ")
                valid = False
                if line.strip().lower() == 'q':
                    return None
                try:
                    ch = int(line)
                    valid = 0 <= ch < len(allProbes)
                except ValueError:
                    pass
                if not valid:
                    print(colorama.Fore.YELLOW + "Invalid choice: %s\n" % line)
                    Session._print_probe_list(allProbes)
                else:
                    break
            allProbes = allProbes[ch:ch + 1]

        assert len(allProbes) == 1
        return allProbes[0]

    @staticmethod
    def session_with_chosen_probe(blocking=True, return_first=False, unique_id=None,
                    auto_open=True, options=None, **kwargs):
        """! @brief Create a session with a probe possibly chosen by the user.
        
        This method provides an easy to use command line interface for selecting one of the
        connected debug probes, then creating and opening a Session instance. It has several
        parameters that control filtering of probes by unique ID and automatic selection of the
        first discovered probe. In addition, you can pass session options to the Session either with
        the _options_ parameter or directly as keyword arguments.
        
        If, after application of the _unique_id_ and _return_first_ parameter, there are still
        multiple debug probes to choose from, the user is presented with a simple command-line UI
        to select a probe (or abort the selection process).
        
        Most commonly, this method will be used directly in a **with** statement:
        @code
        with ConnectHelper.session_with_chosen_probe() as session:
            # the session is open and ready for use
        @endcode

        You can also call this method to get a session, then use the resulting session in a **with**
        statement. This makes it easy to further modify the session prior to opening it.
        @code
        session = ConnectHelper.session_with_chosen_probe()
        # modify session here before it is opened
        with session:
            # the session is open and ready for use
        @endcode
        
        @param blocking Specifies whether to wait for a probe to be connected if there are no
              available probes.
        @param return_first If more than one probe is connected, a _return_first_ of True will select
              the first discovered probe rather than present a selection choice to the user.
        @param unique_id String to match against probes' unique IDs using a contains match. If the
              default of None is passed, then all available probes are matched.
        @param auto_open Sets whether the returned Session object will be opened when used as a
              context manager.
        @param options Dictionary of session options.
        @param kwargs Session options passed as keyword arguments.
        
        @return Either None or a Session instance.
        """
        # Choose a probe.
        probe = ConnectHelper.choose_probe(
                    blocking=blocking,
                    return_first=return_first,
                    unique_id=unique_id,
                    )
        if probe is None:
            return None
        else:
            return Session(probe, auto_open=auto_open, options=options, **kwargs)

    @staticmethod
    def _print_probe_list(probes):
        pt = prettytable.PrettyTable(["#", "Probe", "Unique ID"])
        pt.align = 'l'
        pt.header = True
        pt.border = True
        pt.hrules = prettytable.HEADER
        pt.vrules = prettytable.NONE

        for index, probe in enumerate(probes):
            pt.add_row([
                colorama.Fore.YELLOW + str(index),
                colorama.Fore.GREEN + probe.description,
                colorama.Fore.CYAN + probe.unique_id,
                ])
        print(pt)
        print(colorama.Style.RESET_ALL, end='')
