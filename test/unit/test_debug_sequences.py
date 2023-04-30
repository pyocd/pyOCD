# pyOCD debugger
# Copyright (c) 2020 Arm Limited
# Copyright (c) 2021-2022 Chris Reed
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

from __future__ import annotations

import logging
import pytest
from unittest import mock
from lark.lexer import Token as LarkToken
from lark.tree import Tree as LarkTree

from pyocd.core import exceptions
from pyocd.debug.sequences.scope import Scope
from pyocd.debug.sequences.sequences import (
    DebugSequenceSemanticError,
    DebugSequenceExecutionContext,
    DebugSequence,
    Block,
    WhileControl,
    IfControl,
    Parser,
    SemanticChecker,
    _ConstantFolder,
)
from pyocd.core.session import Session
from pyocd.probe.debug_probe import DebugProbe

# Substitute for SequenceFunctionDelegate for testing.
class SequenceFunctionsDelegateForTesting:
    def valid_fn_no_args(self):
        pass

    def valid_fn_1_arg(self, a: int):
        pass

    def valid_fn_3_arg(self, a: int, b: int, c: int):
        pass

    def valid_fn_varg(self, a: int, *vargs):
        pass

    def fn_with_str_parm(self, foo: str):
        pass

    def sequence(self, name: str):
        pass

class SequenceDelegateForTesting:
    # This same root scope instance must be return from all .get_root_scope() calls since it is
    # checked for by id in some tests.
    _root = Scope(name="unit-test-root")

    @property
    def sequences(self):
        return set()

    @property
    def cmsis_pack_device(self):
        return mock.MagicMock()

    def get_root_scope(self, context) -> Scope:
        self._root.set('rootvar', 42)
        return self._root

    def has_sequence_with_name(self, name, pname=None):
        return name == "valid"

    def get_sequence_with_name(self, name, pname=None):
        print(f"SequenceDelegateForTesting.get_sequence_by_name: name={name} pname={pname}")
        if name == "valid":
            x = mock.Mock()
            print(f"returning {x}")
            return x
        else:
            return None

    def get_protocol(self):
        return 2

    def get_connection_type(self):
        return 1

    def get_traceout(self):
        return 0

    def get_sequence_functions(self) -> SequenceFunctionsDelegateForTesting:
        return SequenceFunctionsDelegateForTesting()


class MockProbe:
    def __init__(self):
        self.wire_protocol = DebugProbe.Protocol.SWD

@pytest.fixture(scope='function')
def session():
    s = Session(None)
    setattr(s, '_probe', MockProbe())
    return s

@pytest.fixture(scope='function')
def delegate():
    return SequenceDelegateForTesting()

@pytest.fixture(scope='function')
def scope():
    s = Scope(name="fixture")
    s.set("a", 0)
    s.set("b", 128)
    return s

@pytest.fixture(scope='function')
def context(session, delegate):
    c = DebugSequenceExecutionContext(session, delegate, pname=None)
    return c

@pytest.fixture(scope='function')
def block_context(context):
    # Return a context set up to be able to run a Block.
    #
    # First create a sequence node with no children. Use the private _create_scope() method to get
    # the new sequence scope with the delegate's root scope at parent. Then push the sequence node
    # and scope onto the context stack. We can't just execute the sequence to do all that because
    # it will pop the context before returning, leaving us without the proper context for running
    # a block.
    seq = DebugSequence('test_sequence')
    scope = seq._create_scope(context)
    # Must manually enter the push context manager.
    ctxmgr = context._push(seq, scope)
    return context

class TestDebugSequenceScope:
    def test_name(self):
        s = Scope(name='test')
        assert s.name == 'test'

    def test_get_1(self, scope):
        assert scope.get('a') == 0
        assert scope.get('b') == 128
        assert len(scope) == 2

    def test_get_invalid(self, scope):
        with pytest.raises(KeyError):
            scope.get('missing')
        with pytest.raises(KeyError):
            scope.get('')

    def test_set_1(self, scope):
        scope.set('a', 10)
        assert scope.get('a') == 10
        assert scope.get('b') == 128

    def test_set_ro(self, scope):
        scope.set('x', 32, readonly=True)
        assert scope.is_read_only('x')
        assert scope.get('x') == 32
        with pytest.raises(RuntimeError):
            scope.set('x', 50)

    def test_freeze(self, scope):
        scope.set('y', 16)
        scope.freeze()
        with pytest.raises(RuntimeError):
            scope.set('a', 1)
        assert len(scope) == 3
        assert scope.is_read_only('b')

    def test_parent_1(self, scope):
        sub = Scope(parent=scope, name='subscope')
        assert sub.parent is scope
        assert sub.get('a') == 0
        assert sub.get('b') == 128
        assert sub.is_defined('b')

    def test_parent_2(self, scope):
        sub = Scope(parent=scope, name='subscope')
        sub.set('x', 1)
        assert sub.parent is scope
        assert sub.get('a') == 0
        assert sub.get('x') == 1
        assert sub.is_defined('b')
        assert not scope.is_defined('x')

    def test_parent_3(self, scope):
        sub = Scope(parent=scope, name='subscope')
        sub.set('a', 1)
        assert sub.parent is scope
        assert sub.get('a') == 1
        assert scope.get('a') == 1 # Make sure it was set in parent scope.
        assert sub.is_defined('a')
        assert 'a' not in sub._variables
        assert scope.is_defined('a')

    def test_parent_4(self, scope):
        sub = Scope(parent=scope, name='subscope')
        scope.set('y', 12, readonly=True)
        with pytest.raises(RuntimeError):
            sub.set('y', 1)
        assert sub.get('y') == 12
        assert scope.get('y') == 12

    def test_copy(self, scope):
        other = Scope(name='other')
        other.copy_variables(from_scope=scope, variables=['a', 'b'])
        assert other.is_defined('a') \
            and other.is_defined('b')
        assert other.get('a') == scope.get('a')
        assert other.get('b') == scope.get('b')

    def test_copy_undefined(self, scope):
        other = Scope(name='other')
        other.copy_variables(from_scope=scope, variables=['a', 'missing'])
        assert other.is_defined('a') \
            and not other.is_defined('b') \
            and not other.is_defined('missing')
        assert other.get('a') == scope.get('a')


class TestDebugSequenceParser:
    def test_semicolons(self):
        # first with semicolon
        ast = Parser().parse("12;")
        print("ast=", ast)
        assert ast.children[0].children[0] == 12

        # now without semicolon
        ast = Parser().parse("12")
        print("ast=", ast)
        assert ast.children[0].children[0] == 12

    def test_fncall_no_args(self):
        ast = Parser().parse("myfunc();")
        print("ast=", ast)
        fncall = ast.children[0].children[0] # start.expr_stmt...
        assert fncall.data == 'fncall'
        assert len(fncall.children) == 1 # IDENT only
        assert fncall.children[0] == LarkToken('IDENT', 'myfunc')

    def test_fncall_3_arg(self):
        ast = Parser().parse("myfunc(1, 2, 3);")
        print("ast=", ast)
        fncall = ast.children[0].children[0] # start.expr_stmt...
        assert fncall.data == 'fncall'
        assert len(fncall.children) == 4 # IDENT, arg1, arg2, arg3
        assert fncall.children[0] == LarkToken('IDENT', 'myfunc')
        assert fncall.children[1] == 1
        assert fncall.children[2] == 2
        assert fncall.children[3] == 3

    def test_bad_input(self):
        with pytest.raises(exceptions.Error):
            Parser().parse("bad input ••• wooo")

    def test_unary_op_assign(self):
        # Statement from Infineon.PSoC6_DFP
        ast = Parser().parse("__Result = -1; // DAP is unavailable")
        print("ast=", ast)

    def test_assign_minus_negative(self):
        ast = Parser().parse("a = 1 - -1;")
        print("ast=", ast)
        e = ast.children[0].children[2] # start.assign_stmt.binary_expr
        assert e.children[0] == 1
        assert e.children[1] == LarkToken('MINUS', '-')
        assert e.children[2].data == 'unary_expr'
        assert e.children[2].children[0] == LarkToken('MINUS', '-')
        assert e.children[2].children[1] == 1

    def test_assign_minus_positive(self):
        ast = Parser().parse("a = 1 - +1;")
        print("ast=", ast)
        e = ast.children[0].children[2] # start.assign_stmt.binary_expr
        assert e.children[0] == 1
        assert e.children[1] == LarkToken('MINUS', '-')
        assert e.children[2].data == 'unary_expr'
        assert e.children[2].children[0] == LarkToken('PLUS', '+')
        assert e.children[2].children[1] == 1

class TestDebugSequenceBlockExecute:
    def test_semicolons(self, block_context):
        block_context.current_scope.set("a", 0)

        # First with semicolon.
        s = Block("a == 0;")
        s.execute(block_context)
        assert block_context.current_scope.get("a") == 0

        # Now without semicolon.
        s = Block("a == 0")
        s.execute(block_context)
        assert block_context.current_scope.get("a") == 0

    def test_set_var(self, block_context):
        s = Block("__var x = 100;")
        s.execute(block_context)
        assert block_context.current_scope.get("x") == 100

    def test_var_no_expr(self, block_context):
        s = Block("__var x;")
        s.execute(block_context)
        assert block_context.current_scope.get("x") == 0

    def test_var_no_expr_separate_set(self, block_context):
        s = Block("__var x; x = 123;")
        s.execute(block_context)
        assert block_context.current_scope.get("x") == 123

    @pytest.mark.parametrize(("expr", "result"), [
            ("-1", 0xffffffffffffffff),
            ("-2", 0xfffffffffffffffe),
            ("!1", 0),
            ("!0", 1),
            ("+1", 1),
            ("~0xffff", 0xffffffffffff0000),
        ])
    def test_int_unary_ops(self, block_context, expr, result):
        s = Block("__var x = %s;" % expr)
        s.execute(block_context)
        assert block_context.current_scope.get("x") == result

    @pytest.mark.parametrize(("expr", "result"), [
            ("1 + 1", 2),
            ("2 - 1", 1),
            ("2 * 4", 8),
            ("4 / 2", 2),
            ("5 % 4", 1),
            ("1 << 12", 4096),
            ("0x80 >> 4", 0x8),
            ("0b1000 | 0x2", 0b1010),
            ("0b1100 & 0b0100", 0b0100),
        ])
    def test_int_expr(self, block_context, expr, result):
        s = Block("__var x = %s;" % expr)
        s.execute(block_context)
        assert block_context.current_scope.get("x") == result

    @pytest.mark.parametrize(("expr", "result"), [
            ("1 == 1", 1),
            ("1 == 0", 0),
            ("0 == 1", 0),
            ("1 != 1", 0),
            ("1 != 0", 1),
            ("0 != 1", 1),
            ("20 > 10", 1),
            ("20 > 20", 0),
            ("20 > 100", 0),
            ("5 >= 2", 1),
            ("5 >= 5", 1),
            ("5 >= 100", 0),
            ("10 < 20", 1),
            ("10 < 10", 0),
            ("10 < 4", 0),
            ("10 <= 20", 1),
            ("10 <= 10", 1),
            ("10 <= 5", 0),
        ])
    def test_bool_cmp_expr(self, block_context, expr, result):
        s = Block("__var x = %s;" % expr)
        s.execute(block_context)
        assert block_context.current_scope.get("x") == result

    # Aside from the obvious, verify that && and || are evaluated as in C rather than Python.
    # That is, they must produce a 1 or 0 and not the value of either operand.
    @pytest.mark.parametrize(("expr", "result"), [
            ("1 && 1", 1),
            ("1 && 0", 0),
            ("0 && 1", 0),
            ("0 && 0", 0),
            ("1 || 1", 1),
            ("1 || 0", 1),
            ("0 || 1", 1),
            ("0 || 0", 0),
            ("5 && 1000", 1),
            ("432 && 0", 0),
            ("0 && 2", 0),
            ("0 && 0", 0),
            ("348 || 4536", 1),
            ("5 || 0", 1),
            ("0 || 199", 1),
            ("0 || 0", 0),
        ])
    def test_bool_and_or_expr(self, block_context, expr, result):
        s = Block("__var x = %s;" % expr)
        s.execute(block_context)
        assert block_context.current_scope.get("x") == result

    @pytest.mark.parametrize(("expr", "result"), [
            ("1 + 2 * 5", 11),
            ("7 * 12 + 5", 89),
            ("1 + 5 - 3", 3),
            ("(1 + 2) * 5", 15),
            ("1 + (2 * 5)", 11),
            ("2 + 16 / 2", 10),
            ("1 + 17 % 3", 3),
            ("2 * 3 * 4", 24),
            ("0 || 1 && 1", 1),
            ("0 && 1 || 0", 0),
            ("1 == 6 > 5", 1),
            ("1 != 6 < 12", 0),
            ("1 << 4 > 1 << 2", 1),
            ("1 << (4 > 1) << 2", 8),
            ("!1 == 0", 1),
        ])
    def test_precedence(self, block_context, expr, result):
        s = Block("__var x = %s;" % expr)
        logging.info("Block: %s", s._ast.pretty())
        s.execute(block_context)
        actual = block_context.current_scope.get("x")
        assert actual == result

    @pytest.mark.parametrize(("expr", "result"), [
            ("(7 * (1 << 3) + 1) >> 1", 28),
        ])
    def test_longer_expr(self, block_context, expr, result):
        s = Block("__var x = %s;" % expr)
        logging.info("Block: %s", s._ast.pretty())
        s.execute(block_context)
        actual = block_context.current_scope.get("x")
        assert actual == result

    def test_unary_op_assign(self, block_context):
        # Statement from Infineon.PSoC6_DFP
        s = Block("__Result = -1; // DAP is unavailable")
        logging.info(f"Block: {s._ast.pretty()}")
        s.execute(block_context)
        actual = block_context.current_scope.get("__Result")
        assert actual == 0xffffffffffffffff

    @pytest.mark.parametrize(("expr", "result"), [
            ("1 ? (1 + 1) : (1 - 1)", 2),
            ("0 ? 10: 20", 20),
            ("1 << 5 ? 17 * (2 + 1) : 0", 51),
        ])
    def test_ternary_expr(self, block_context, expr, result):
        s = Block(f"__var x = {expr};")
        logging.info("Block: %s", s._ast.pretty())
        s.execute(block_context)
        actual = block_context.current_scope.get("x")
        assert actual == result

    @pytest.mark.parametrize(("expr", "result"), [
            ("x += 1", 2),
            ("x -= 1", 0),
            ("x *= 10", 10),
            ("x /= 1", 1),
            ("x %= 1", 0),
            ("x &= 3", 1),
            ("x |= 0x40", 0x41),
            ("x ^= 3", 2),
            ("x <<= 5", 1 << 5),
            ("x >>= 0", 1),
        ])
    def test_compound_assign(self, block_context, expr, result):
        s = Block("__var x = 1; %s;" % expr)
        s.execute(block_context)
        assert block_context.current_scope.get("x") == result

class TestConstantFolder:
    def _get_folded_ast(self, expr):
        ast = Parser.parse(expr)
        logging.info("Unoptimized AST:\n%s", ast.pretty())
        ast_opt = _ConstantFolder().transform(ast)
        logging.info("Optimized AST:\n%s", ast_opt.pretty())
        return ast_opt

    def _do_fold_test(self, expr, expected):
        ast_opt = self._get_folded_ast(expr)
        assert isinstance(ast_opt, LarkTree)
        assert ast_opt.data == 'start'
        assert ast_opt.children[0].data == 'expr_stmt'
        assert ast_opt.children[0].children[0] == expected

    @pytest.mark.parametrize(("op", "expected"), [
            # return left
            ("+",   "x"),
            ("-",   "x"),
            ("|",   "x"),
            ("^",   "x"),
            ("<<",  "x"),
            (">>",  "x"),
            ("||",  "x"),
            # return 0
            ("*",   0),
            ("/",   0),
            ("%",   0),
            ("&",   0),
            ("&&",  0),
        ])
    def test_fold_left_0(self, op, expected):
        self._do_fold_test(f"x {op} 0", expected)

    @pytest.mark.parametrize(("op", "expected"), [
            # return right
            ("+",   "x"),
            ("-",   "x"),
            ("|",   "x"),
            ("^",   "x"),
            ("||",  "x"),
            # return 0
            ("*",   0),
            ("/",   0),
            ("%",   0),
            ("&",   0),
            ("<<",  0),
            (">>",  0),
            ("&&",  0),
        ])
    def test_fold_right_0(self, op, expected):
        self._do_fold_test(f"0 {op} x", expected)

    @pytest.mark.parametrize(("op", "expected"), [
            # return left
            ("*",   "x"),
            ("/",   "x"),
            # return 1
            ("||",  1),
            # return 0
            ("%",   0),
        ])
    def test_fold_left_1(self, op, expected):
        self._do_fold_test(f"x {op} 1", expected)

    # Really more of a parser test.
    def test_unary_parens(self):
        self._do_fold_test(f"! (1)", 0)

    # Really more of a parser test.
    def test_unary_unfolded(self):
        ast_opt = self._get_folded_ast("! x")

        assert isinstance(ast_opt, LarkTree)
        assert ast_opt.data == 'start'
        assert ast_opt.children[0].data == 'expr_stmt'
        assert ast_opt.children[0].children[0].data == 'unary_expr'

    @pytest.mark.parametrize(("expr", "expected"), [
            ("-1",   0xffffffffffffffff),
            ("-0",   0),
        ])
    def test_unary_fold(self, expr, expected):
        self._do_fold_test(expr, expected)

    @pytest.mark.parametrize(("expr", "expected"), [
            ("1 ? 10 : 20",     10),
            ("0 ? 1 : 2",       2),
            ("0 ? 1 : 2 + 2",   4),
            ("1 + 1 ? 99 : 77", 99),
        ])
    def test_ternary_fold(self, expr, expected):
        self._do_fold_test(expr, expected)

class TestSemanticChecker:

    @pytest.mark.parametrize("expr", [
            "funkymonkey();",                   # fncall: invalid function name
            "valid_fn_1_arg(2134, x << 4);",    # fncall: too many args
            "valid_fn_1_arg(\"a-string\");",    # fncall: string arg for int param
            "valid_fn_3_arg(1, 2);",            # fncall: too few args
            "fn_with_str_parm(123);",           # fncall: int arg for string param
            "valid_fn_varg();",                 # vararg fn: too few args
            '"just a string in this expr";',    # expr consisting of only a string
            "__var a = \"string value\";",      # decl: attempt to assign string to variable
            "b = \"string value\";",            # assign: attempt to assign string to variable
            "Sequence();",                      # fn-specific check: no args
            "Sequence(1000);",                  # fn-specific check: int arg for str arg
        ])
    def test_sem_checker_raises(self, expr, context, scope):
        ast = Parser.parse(expr)
        logging.info("ast:\n%s", ast.pretty())
        c = SemanticChecker(ast, scope, context)
        with pytest.raises(DebugSequenceSemanticError):
            c.check()

    @pytest.mark.parametrize("expr", [
            "valid_fn_no_args();",
            "valid_fn_1_arg(2134);",
            "valid_fn_3_arg(1, 2, 3);",
            "fn_with_str_parm(\"bubblegum\");", # fncall: string arg for string param
            "valid_fn_varg(a);",                # vararg fn: exact number of positional args
            "valid_fn_varg(123, x, q + 1, \"hi there\", 99);",  # vararg fn: several var args
            "__var a = 3 + x * 2;",             # decl: valid assignment
            "b = 3 + x * 2;",                   # assign: valid assignment
            "Sequence(\"valid\");",             # fn-specific check: valid call
        ])
    def test_sem_checker_passes(self, expr, context, scope):
        ast = Parser.parse(expr)
        logging.info("ast:\n%s", ast.pretty())
        c = SemanticChecker(ast, scope, context)
        c.check()

class TestDebugSequences:
    def test_pname(self):
        seq = DebugSequence('test', pname="cm4")
        assert seq.name == 'test'
        assert seq.pname == 'cm4'

        assert DebugSequence('test').pname is None

    def test_info(self):
        assert DebugSequence('test').info == ''
        assert DebugSequence('test', info='hi there').info == 'hi there'

    def test_enable(self):
        assert DebugSequence('test').is_enabled
        assert not DebugSequence('test', is_enabled=False).is_enabled

    def test_scope_create(self, context):
        seq = DebugSequence('test')
        scope = seq._create_scope(context)
        assert scope.parent is context.delegate.get_root_scope(context)
        assert scope.get('__Result') == 0
        assert not scope.is_read_only('_Result')
        assert scope.get('__dp') == 0
        assert not scope.is_read_only('__dp')
        assert scope.get('__ap') == 0
        assert not scope.is_read_only('__ap')
        assert scope.get('__apid') == 0
        assert not scope.is_read_only('__apid')
        assert scope.get('__errorcontrol') == 0
        assert not scope.is_read_only('__errorcontrol')
        assert scope.get('__protocol') == 2
        assert scope.is_read_only('__protocol')
        assert scope.get('__connection') == 1
        assert scope.is_read_only('__connection')
        assert scope.get('__traceout') == 0
        assert scope.is_read_only('__traceout')
        assert scope.get('__FlashOp') == 0
        assert scope.is_read_only('__FlashOp')
        assert scope.get('__FlashAddr') == 0
        assert scope.is_read_only('__FlashAddr')
        assert scope.get('__FlashLen') == 0
        assert scope.is_read_only('__FlashLen')
        assert scope.get('__FlashArg') == 0
        assert scope.is_read_only('__FlashArg')

    def test_scope_create_with_calling_seq(self, block_context):
        # Modify some of the stacked scope's special vars.
        super_scope = block_context.current_scope
        super_scope.set('__dp', 1)
        super_scope.set('__ap', 2)
        super_scope.set('__apid', 3)
        super_scope.set('__errorcontrol', 1)
        super_scope.set('__Result', 333)

        # Create a sub-sequence.
        seq = DebugSequence('test')
        # _create_scope() will see the stacked sequence in the context.
        scope = seq._create_scope(block_context)

        # Certain vars are propagated to subsequences.
        assert scope.get('__dp') == 1
        assert scope.get('__ap') == 2
        assert scope.get('__apid') == 3
        assert scope.get('__errorcontrol') == 1
        # __Result should not have been propagated.
        assert scope.get('__Result') == 0

        # Modify the propagated variables.
        scope.set('__dp', 2)
        scope.set('__ap', 1)
        scope.set('__apid', 5)
        scope.set('__errorcontrol', 0)
        scope.set('__Result', 555)

        # Verify the variables weren't set in the supersequences.
        assert super_scope.get('__dp') == 1
        assert super_scope.get('__ap') == 2
        assert super_scope.get('__apid') == 3
        assert super_scope.get('__errorcontrol') == 1
        assert super_scope.get('__Result') == 333

    def test_exec_block(self, context):
        seq = DebugSequence('test')
        seq.add_child(Block("__var x = 1 + 1;"))
        seq.execute(context)

    def test_exec_if(self, context):
        seq = DebugSequence('test')
        seq.add_child(Block("__var x = 1;"))
        seq.add_child(IfControl("x"))
        seq.execute(context)

    def test_exec_while(self, context):
        seq = DebugSequence('test')
        seq.add_child(Block("__var x = 0;"))
        w = WhileControl("x < 2")
        w.add_child(Block("x += 1;"))
        seq.add_child(w)
        seq.execute(context)


