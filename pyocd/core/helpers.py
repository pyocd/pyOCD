# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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

from __future__ import print_function
from .session import Session
from ..probe.aggregator import DebugProbeAggregator
from time import sleep
import colorama
import six

# Init colorama here since this is currently the only module that uses it.
colorama.init()

## @brief Helper class for streamlining the probe discovery and session creation process.
#
# This class provides several static methods that wrap the DebugProbeAggregator methods
# with a simple command-line user interface, or provide a single method that performs
# a common access pattern.
class ConnectHelper(object):

    ## @brief Return a list of Session objects for all connected debug probes.
    #
    # This method is useful for listing detailed information about connected probes, especially
    # those that have associated boards, as the Session object will have a Board instance.
    #
    # The returned list of sessions is sorted by the combination of the debug probe's
    # description and unique ID.
    #
    # @param blocking Specifies whether to wait for a probe to be connected if there are no
    #       available probes.
    # @param unique_id String to match against probes' unique IDs using a contains match. If the
    #       default of None is passed, then all available probes are matched.
    # @param options Dictionary of user options.
    # @param kwargs User options passed as keyword arguments.
    #
    # @return A list of Session objects. The returned Session objects are not yet active, in that
    #       open() has not yet been called. If _blocking_ is True, the list will contain at least
    #       one session. If _blocking_ is False and there are no probes connected then an empty list
    #       will be returned.
    @staticmethod
    def get_sessions_for_all_connected_probes(blocking=True, unique_id=None, options=None, **kwargs):
        probes = ConnectHelper.get_all_connected_probes(blocking=blocking, unique_id=unique_id)
        sessions = [Session(probe, options=options, **kwargs) for probe in probes]
        return sessions

    ## @brief Return a list of DebugProbe objects for all connected debug probes.
    #
    # The returned list of debug probes is always sorted by the combination of the probe's
    # description and unique ID.
    #
    # @param blocking Specifies whether to wait for a probe to be connected if there are no
    #       available probes. A message will be printed
    # @param unique_id String to match against probes' unique IDs using a contains match. If the
    #       default of None is passed, then all available probes are matched.
    # @param print_wait_message Whether to print a message to the command line when waiting for a
    #       probe to be connected and _blocking_ is True.
    #
    # @return A list of DebugProbe instances. If _blocking_ is True, the list will contain at least
    #       one probe. If _blocking_ is False and there are no probes connected then an empty list
    #       will be returned.
    @staticmethod
    def get_all_connected_probes(blocking=True, unique_id=None, print_wait_message=True):
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
                    print(colorama.Fore.YELLOW + "Waiting for a debug probe to be connected..." + colorama.Style.RESET_ALL)
                    printedMessage = True
                sleep(0.01)
            assert len(sortedProbes) == 0

        return sortedProbes

    ## @brief List the connected debug probes.   
    #
    # @return List of zero or more DebugProbe objects that are currently connected, sorted by the
    #       combination of the probe's description and unique ID.
    @staticmethod
    def list_connected_probes():
        allProbes = ConnectHelper.get_all_connected_probes(blocking=False)
        if len(allProbes):
            ConnectHelper._print_probe_list(allProbes)
        else:
            print(colorama.Fore.RED + "No available debug probes are connected" + colorama.Style.RESET_ALL)

    ## @brief Create a session with a probe possibly chosen by the user.
    #
    # This method provides an easy to use command line interface for selecting one of the
    # connected debug probes, then creating and opening a Session instance. It has several
    # parameters that control filtering of probes by unique ID, automatic selection of the first
    # discovered probe, and whether to automaticallty open the created Session. In addition, you
    # can pass user options to the Session either with the _options_ parameter or directly as
    # keyword arguments.
    #
    # If, after application of the _unique_id_ and _return_first_ parameter, there are still
    # multiple debug probes to choose from, the user is presented with a simple command-line UI
    # to select a probe (or abort the selection process).
    #
    # @param blocking Specifies whether to wait for a probe to be connected if there are no
    #       available probes.
    # @param return_first If more than one probe is connected, a _return_first_ of True will select
    #       the first discovered probe rather than present a selection choice to the user.
    # @param unique_id String to match against probes' unique IDs using a contains match. If the
    #       default of None is passed, then all available probes are matched.
    # @param board_id Deprecated alias of _unique_id_.
    # @param open_session Indicates whether the returned Session object should be opened for the
    #       caller. If opening causes an exception, the Session will be automatically closed.
    # @param init_board Deprecated alias of _open_session_.
    # @param options Dictionary of user options.
    # @param kwargs User options passed as keyword arguments.
    #
    # @return Either None or a Session instance. If _open_session_ is True then the session will
    #       have already been opened, the board and target initialized, and is ready to be used.
    @staticmethod
    def session_with_chosen_probe(blocking=True, return_first=False,
                    unique_id=None, board_id=None, # board_id param is deprecated
                    open_session=True, init_board=None, # init_board param is deprecated
                    options=None, **kwargs):
        # Get all matching probes, sorted by name.
        board_id = unique_id or board_id
        allProbes = ConnectHelper.get_all_connected_probes(blocking=blocking, unique_id=board_id)

        # Print some help if the user specified a unique ID, but more than one probe matches.
        if (board_id is not None) and (len(allProbes) > 1) and not return_first:
            print(colorama.Fore.RED + "More than one debug probe matches unique ID '%s':" % board_id + colorama.Style.RESET_ALL)
            board_id = board_id.lower()
            for probe in allProbes:
                head, sep, tail = probe.unique_id.lower().rpartition(board_id)
                highlightedId = head + colorama.Fore.RED + sep + colorama.Style.RESET_ALL + tail
                print("%s | %s" % (
                    probe.description,
                    highlightedId))
            return None

        # Return if no boards are connected.
        if allProbes is None or len(allProbes) == 0:
            if board_id is None:
                print("No connected debug probes")
            else:
                print("A debug probe matching unique ID '%s' is not connected, or no connected probe matches" % board_id)
            return None # No boards to close so it is safe to return

        # Select first board
        if return_first:
            allProbes = allProbes[0:1]

        # Ask user to select boards if there is more than 1 left
        if len(allProbes) > 1:
            ConnectHelper._print_probe_list(allProbes)
            print(colorama.Fore.RED + " q => Quit")
            while True:
                print(colorama.Style.RESET_ALL)
                print("Enter the number of the debug probe to connect:")
                line = six.moves.input("> ")
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
                    print(colorama.Fore.RED + " q => Exit" + colorama.Style.RESET_ALL)
                else:
                    break
            allProbes = allProbes[ch:ch + 1]

        # Let deprecated init_board override open_session if it was specified.
        if init_board is not None:
            open_session = init_board
        
        assert len(allProbes) == 1
        session = Session(allProbes[0], options=options, **kwargs)
        if open_session:
            try:
                session.open()
            except:
                session.close()
                raise
        return session

    @staticmethod
    def _print_probe_list(probes):
        print(colorama.Fore.BLUE + "## => Board Name | Unique ID")
        print("-- -- ----------------------")
        for index, probe in enumerate(probes):
            print(colorama.Fore.GREEN + "%2d => %s | " % (index, probe.description) +
                colorama.Fore.CYAN + probe.unique_id + colorama.Style.RESET_ALL)
        print(colorama.Style.RESET_ALL, end='')
