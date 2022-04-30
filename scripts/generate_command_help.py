#!/usr/bin/env python3

# Copyright (c) 2020 Arm Limited
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

import sys

if sys.version_info[:2] < (3, 9):
    print(f"This script requires Python 3.9 or later")
    sys.exit(1)

from pyocd.commands.base import (
    ALL_COMMANDS,
    CommandBase,
    ValueBase,
    )

# These modules must be imported in order to load the commands into the ALL_COMMANDS table.
import pyocd.commands.commands
import pyocd.commands.values

ACCESS_DESC = {
        'r': "read-only",
        "w": "write-only",
        "rw": "read-write",
    }

GROUP_DOCS = {
        'bringup': "These commands are meant to be used when starting up Commander in no-init mode. They are primarily useful for low-level debugging of debug infrastructure on a new chip.",
        'symbols': "These commands require an ELF to be set.",
    }

def gen_command(info):
    names = info['names']
    usage = info['usage']
    help = info['help']
    extra_help = info.get('extra_help')
    print("""<tr><td>""")
    name_docs = []
    for name in names:
        name_docs.append(f"""<a href="#{names[0]}"><tt>{name}</tt></a>""")
    print(",\n".join(name_docs))
    print("""</td><td>""")
    if usage:
        print(usage)
    print("""</td><td>""")
    print(help)
    print("""</td></tr>""")
    print()

def gen_value(info):
    names = info['names']
    access = info['access']
    help = info['help']
    extra_help = info.get('extra_help')
    print("""<tr><td>""")
    name_docs = []
    for name in names:
        name_docs.append(f"""<a href="#{names[0]}"><tt>{name}</tt></a>""")
    print(",\n".join(name_docs))
    print("""</td><td>""")
    print(ACCESS_DESC[access])
    print("""</td><td>""")
    print(help)
    print("""</td></tr>""")
    print()

def build_categories(commands):
    categories = {}
    for cmdlist in commands.values():
        for cmd in cmdlist:
            categories.setdefault(cmd.INFO['category'], []).append(cmd)
    return categories

def get_all_values(commands: dict[str, list[ValueBase]]) -> list[ValueBase]:
    """Converts dict of group name to list of commands"""
    return [
        c
        for group_commands in commands.values()
        for c in group_commands
        ]

def gen_cmd_groups(commands):
    categories = build_categories(commands)

    for group in sorted(categories.keys()):
        # Filter out the base classes that have empty 'names'.
        filtered_cmds = [c for c in categories[group] if c.INFO['names']]
        group_cmds = sorted(filtered_cmds, key=lambda c: c.INFO['names'][0])

        # Skip empty groups.
        if not group_cmds:
            continue

        print(f"""<tr><td colspan="3"><b>{group.capitalize()}</b></td></tr>
""")

        for cmd in group_cmds:
            gen_command(cmd.INFO)

def gen_value_groups(commands: list[ValueBase]) -> None:
    # Filter out the base classes that have empty 'names'.
    filtered_cmds = [c for c in commands if c.INFO['names']]
    group_cmds = sorted(filtered_cmds, key=lambda c: c.INFO['names'][0])

#         print(f"""<tr><td colspan="3"><b>{group.capitalize()}</b></td></tr>""")

    for cmd in group_cmds:
        gen_value(cmd.INFO)

def format_group_name(group: str) -> str:
    return group.replace('_', ' ').capitalize()

def gen_command_docs(commands):
    nl = "\\"
    categories = build_categories(commands)
    for group in sorted(categories.keys()):
        # Filter out the base classes that have empty 'names'.
        filtered_cmds = [c for c in categories[group] if c.INFO['names']]
        group_cmds = sorted(filtered_cmds, key=lambda c: c.INFO['names'][0])

        # Skip empty groups.
        if not group_cmds:
            continue

        group_docs = GROUP_DOCS.get(group, '')
        print(f"""
### {format_group_name(group)}""")
        if group_docs:
            print(group_docs)

        for cmd in group_cmds:
            info = cmd.INFO
            print(f"""
##### `{info['names'][0]}`
""")
            if len(info['names']) > 1:
                print(f"""**Aliases**: {', '.join("`%s`" % n for n in info['names'][1:])} """ + nl)

            help = info['help']
            if 'extra_help' in info:
                help += " " + info['extra_help']
            print(f"""**Usage**: {info['names'][0]} {info['usage']} {nl}
{help}
""")

def gen_value_docs(commands: list[ValueBase]) -> None:
    nl = "\\"
    # Filter out the base classes that have empty 'names'.
    filtered_cmds = [c for c in commands if c.INFO['names']]
    group_cmds = sorted(filtered_cmds, key=lambda c: c.INFO['names'][0])

    for cmd in group_cmds:
        info = cmd.INFO
        names = info['names']
        first_name = names[0]
        access = info['access']
        access_desc = ACCESS_DESC[access]
        help = info['help']
        if 'extra_help' in info:
            help += " " + info['extra_help']

        print(f"""
##### `{first_name}`
""")
        if len(names) > 1:
            print(f"""**Aliases**: {', '.join("`%s`" % n for n in names[1:])} """ + nl)

        print(f"**Access**: {access_desc} {nl}")
        print(f"**Usage**: ", end='')
        if 'r' in access:
            print(f"show {first_name}", end='')
        if access == 'rw':
            print(", ", end='')
        if 'w' in access:
            print(f"set {first_name} VALUE", end='')
        print(f" {nl}")

        print(help)

def get_all_command_classes():
    klasses = set()
    for cmds in ALL_COMMANDS.values():
        klasses.update(cmds)
    return klasses

def split_into_commands_and_values():
    commands = get_all_command_classes()
    value_classes = {klass for klass in commands if issubclass(klass, ValueBase)}
    cmd_classes = commands - value_classes
    cmd_groups = {}
    value_groups = {}
    for cmd in cmd_classes:
        cmd_groups.setdefault(cmd.INFO['group'], set()).add(cmd)
    for val in value_classes:
        value_groups.setdefault(val.INFO['group'], set()).add(val)
    return cmd_groups, value_groups

def main():
    all_cmds_by_group, all_values_by_group = split_into_commands_and_values()
    all_values = get_all_values(all_values_by_group)
    print("""
All commands
------------

<table>

<tr><th>Command</th><th>Arguments</th><th>Description</th></tr>
""")
    gen_cmd_groups(all_cmds_by_group)
    print("""
</table>
""")

    print("""
All values
----------

Values represent a setting or piece of information that can be read and/or changed. They are accessed with
the [`show`](#show) and [`set`](#set) commands. The "Access" column of the table below shows whether the
command can be read, written, or both.

<table>

<tr><th>Value</th><th>Access</th><th>Description</th></tr>
""")
    gen_value_groups(all_values)
    print("""
</table>
""")

    print("""
Command details
---------------""")
    gen_command_docs(all_cmds_by_group)

    print("""

Value details
-------------""")
    gen_value_docs(all_values)

if __name__ == '__main__':
    main()


