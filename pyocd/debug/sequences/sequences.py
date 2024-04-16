# pyOCD debugger
# Copyright (c) 2020 Arm Limited
# Copyright (c) 2021-2023 Chris Reed
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

from contextlib import contextmanager
import lark.lark
import lark.exceptions
import lark.visitors
import logging
import threading
from dataclasses import dataclass
from enum import Enum
from inspect import signature
from lark.lexer import Token as LarkToken
from lark.tree import Tree as LarkTree
from typing import (Any, Iterator, cast, List, Optional, Union, TYPE_CHECKING)
from typing_extensions import Self

from ...core import exceptions
from ...coresight.ap import (APv1Address, APv2Address)
from ...utility.graph import GraphNode
from ...utility.mask import bit_invert
from ...utility.timeout import Timeout
from .scope import Scope

if TYPE_CHECKING:
    # Only import Session when type checking to avoid complex import cycles.
    from ...core.session import Session
    from ...coresight.ap import APAddressBase
    from .delegates import DebugSequenceDelegate

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

NodeType = Union[LarkTree, LarkToken, int]

class DebugSequenceError(exceptions.Error):
    pass

class DebugSequenceSemanticError(DebugSequenceError):
    pass

class DebugSequenceRuntimeError(exceptions.Error):
    pass

def _is_token(tok: Any, typename: str) -> bool:
    """@brief Test whether a node is a specific type of token."""
    return isinstance(tok, LarkToken) and tok.type == typename

class _ConvertLiterals(lark.visitors.Transformer):
    """@brief Transformer to convert integer literal tokens to integers.

    Running this transformer during the parse is more efficient than handling it post-parse
    such as during optimization.
    """
    def INTLIT(self, tok: LarkToken) -> int: # pylint: disable=invalid-name
        return int(tok.value.upper().rstrip('U'), base=0)

    def STRLIT(self, tok: LarkToken) -> LarkToken:
        tok.value = tok.value.strip('"')
        return tok

class Parser:
    """@brief Debug sequence statement parser."""

    ## Shared parser object.
    _parser = lark.lark.Lark.open("sequences.lark",
                        rel_to=__file__,
                        parser="lalr",
                        maybe_placeholders=True,
                        propagate_positions=True,
                        transformer=_ConvertLiterals())

    @classmethod
    def parse(cls, data: str) -> LarkTree:
        try:
            # Parse the input.
            tree = cls._parser.parse(data)

            # Return the resulting tree.
            return tree
        except lark.exceptions.UnexpectedInput as e:
            message = str(e) + "\n\nContext: " + e.get_context(data, 40)
            raise exceptions.Error(message) from e

class DebugSequenceExecutionContext:
    """@brief Context for running debug sequences.

    Instances of this class contain state for running a call stack of sequences. There is a stack
    of sequence node and scope pairs. This stack is also used to get the current running sequence.

    Context objects can be used as context managers, which will set the context as the current
    thread's active context. The class method get_active_context() returns the currently active
    context for the current thread. There is no stack of active contexts; the assumption is that
    only one call stack of debug sequences can be run at any time on a given thread.
    """

    _thread_local_contexts = threading.local()

    @dataclass
    class _NodeScopeStackItem:
        node: DebugSequenceNode
        scope: Scope

    @classmethod
    def get_active_context(cls) -> DebugSequenceExecutionContext:
        """@brief Return the active context for the current thread.
        @exception AttributeError There is no active context for this thread.
        """
        return cls._thread_local_contexts.context

    def __init__(self, session: Session, delegate: DebugSequenceDelegate, pname: Optional[str]) -> None:
        """@brief Constructor.

        @param self
        @param session Session for the target connection.
        @param delegate Debug sequence delegate that owns the running sequences.
        @param pname Pname under which sequences are being run.
        """
        self._session = session
        self._delegate = delegate
        self._default_ap_address = APv1Address(0)
        self._pname = pname
        self._stack: List[DebugSequenceExecutionContext._NodeScopeStackItem] = []

    @property
    def session(self) -> Session:
        return self._session

    @property
    def delegate(self) -> DebugSequenceDelegate:
        return self._delegate

    @property
    def default_ap(self) -> APAddressBase:
        """@brief Return the AP address from which the __ap and __apid variables should be inited.

        The initial AP address is the one defined for the <debug> element corresponding to the active
        processor.

        This is contained in the context rather than returned by the sequence delegate because it can
        differ for each execution of a debug sequence. Compare with the delegate methods for getting
        `__protocol`, `__connection`, and `__traceout`, which should be static for an entire session.
        """
        return self._default_ap_address

    @default_ap.setter
    def default_ap(self, address: APAddressBase) -> None:
        """@brief Set the default AP adddress."""
        self._default_ap_address = address

    @property
    def pname(self) -> Optional[str]:
        """@brief Pname for which sequences are executing in this context.

        The Pname for this context is set when the context is created.
        Only debug sequences with this Pname or an empty Pname can be run in this context.
        """
        return self._pname

    @property
    def current_scope(self) -> Scope:
        """@brief Topmost scope of the scope stack.
        @exception AssertionError Raised if an attempt is made to get the current scope without a
            currently running debug sequence. If needed, this can be checked before accessing this
            property by getting the `.has_current_sequence` property.
        """
        assert self._stack, "current_scope accessed from outside a running sequence"
        return self._stack[-1].scope

    @property
    def has_current_sequence(self) -> bool:
        """@brief Whether there is a debug sequence running on this context.

        By definition, there must be a debug sequence on the stack if the stack is not empty,
        with one exception for when the debugvars block is run to create the the root scope.
        """
        return bool(self._stack)

    @property
    def current_sequence(self) -> DebugSequence:
        """@brief Currently executing debug sequence."""
        assert self._stack, "current_sequence accessed without a running debug sequence"

        # Walk the stack to find the most recent DebugSequence.
        for elem in reversed(self._stack):
            if isinstance(elem.node, DebugSequence):
                return elem.node

        # Ooh, not good..
        assert False, "invalid state: no debug sequence on active debug sequence execute context stack"

    def _push(self, node: DebugSequenceNode, scope: Scope) -> None:
        """@brief Context stack push operation.

        Separated even though it's tiny so it can be used manually for unit testing.
        """
        self._stack.append(self._NodeScopeStackItem(node, scope))

    def _pop(self) -> None:
        """@brief Context stack pop operation.

        Separated even though it's tiny so it can be used manually for unit testing.
        """
        self._stack.pop()

    @contextmanager
    def push(self, node: DebugSequenceNode, scope: Scope) -> Iterator[None]:
        """@brief Context manager to push/pop a sequence node and scope pair on the context stack.

        A node/scope pair is pushed prior to that node (and its children) being executed.

        Scopes in the stack do not automatically or necessarily have parent links between them. This
        allows for unlinked scopes from the call stack of sequences to be placed on the stack, without
        causing issues with variable access.

        Blocks are not normally pushed, since they do not define scopes. The sole exception to this is when
        the debugvars block is executed to create the root scope, but this is done by the code that
        creates the root scope and not the Block itself.

        When the context manager exits, the scope is popped.
        """
        try:
            self._push(node, scope)
            yield
        finally:
            self._pop()

    def get_variable(self, name: str) -> int:
        """@brief Return the value of a variable from the current scope."""
        assert self.current_scope is not None
        try:
            return self.current_scope.get(name)
        except KeyError as err:
            LOG.debug("debug sequence reference to undefined variable %s... %s", name, self.current_scope.dump())
            raise DebugSequenceRuntimeError(f"reference to undefined variable {name}") from err

    def __enter__(self) -> Self:
        """@brief Make this context the active one for the current thread."""
        self._thread_local_contexts.context = self
        return self

    def __exit__(self, exc_type, value, traceback) -> None:
        """@brief Clear the current thread's active context."""
        assert self._thread_local_contexts.context == self
        del self._thread_local_contexts.context

class DebugSequenceNode(GraphNode):
    """@brief Common base class for debug sequence nodes."""

    def __init__(self, info: str = "") -> None:
        super().__init__()
        self._info = info

    @property
    def info(self) -> str:
        return self._info

    def execute(self, context: DebugSequenceExecutionContext) -> Optional[Scope]:
        """@brief Execute the sequence node.

        @return If a scope was created in order to execute the sequence node, that scope is returned
            to the caller so any variables can be accessed.
        """
        raise NotImplementedError()

    def _execute_children(self, context: DebugSequenceExecutionContext) -> None:
        """@brief Execute all child nodes."""
        for node in self.children:
            cast(DebugSequenceNode, node).execute(context)

class DebugSequence(DebugSequenceNode):
    """@brief Named debug sequence.

    Variable scoping:
    - Sequences and control elements create new scopes.
    - Scope extends to child control elements.
    - Block elements do not create a new scope.
    - Variables in a parent scope can be modified.
    - Leaving a scope destroys contained variables.
    - Variables are not passed to sub-sequences.

    Special read-write variables:
    - __dp, __ap, __apid, __errorcontrol
        - Propagates to another sequence called via the Sequence() function.
        - Restored to previous values when sub-sequence returns.
    - __Result
        - Not pushed when calling another sequence.
        - 0=success

    Special read-only variables:
    - __protocol
        - [15:0] 0=error, 1=JTAG, 2=SWD, 3=cJTAG
        - [16] SWJ-DP present?
        - [17] switch through dormant state?
    - __connection
        - [7:0] connection type: 0=error/disconnected, 1=for debug, 2=for flashing
        - [15:8] reset type: 0=error, 1=hw, 2=SYSRESETREQ, 3=VECTRESET
        - [16] connect under reset?
        - [17] pre-connect reset?
    - __traceout
        - [0] SWO enabled?
        - [1] parallel trace enabled?
        - [2] trace buffer enabled?
        - [21:16] selected parallel trace port size
    - __FlashOp
        - 0=no op, 1=erase full chip, 2=erase sector, 3=program
    - __FlashAddr
    - __FlashLen
    - __FlashArg
    """

    ## Special predefined variables that are read-write and propagate to sub-sequences.
    _SPECIAL_VARS = ['__dp', '__ap', '__apid', '__errorcontrol']

    ## Predefined variables that are read-write, but do not propagate.
    _WRITABLE_PREDEFINED = ['__Result']

    def __init__(
            self,
            name: str,
            is_enabled: bool = True,
            pname: Optional[str] = None,
            info: str = ""
            ) -> None:
        super().__init__(info)
        self._name = name
        self._is_enabled = is_enabled
        self._pname = pname

    @property
    def name(self) -> str:
        return self._name

    @property
    def pname(self) -> Optional[str]:
        return self._pname

    @property
    def is_enabled(self) -> bool:
        return self._is_enabled

    def _create_scope(self, context: DebugSequenceExecutionContext) -> Scope:
        """@brief Create a new variables scope with predefined variables filled in."""
        delegate = context.delegate

        # Create the new scope using the delegate's root scope as parent.
        scope = Scope(parent=context.delegate.get_root_scope(context), name=self.name)

        # Writable result.
        scope.set('__Result', 0)

        # Propagate specials if there is a sequence that called us.
        if context.has_current_sequence:
            scope.copy_variables(context.current_scope, self._SPECIAL_VARS)
        # Otherwise just fill in the defaults.
        else:
            scope.set('__errorcontrol', 0)

            # Convert the default AP address to __ap and __apid variables. If the AP is v1 then
            # __ap is set, for v2 __apid is set. The other variable gets set to 0.
            default_ap_address = context.default_ap
            scope.set('__dp', default_ap_address.dp_index) # We still only support one DP.
            scope.set('__ap', default_ap_address.nominal_address
                                if isinstance(default_ap_address, APv1Address)
                                else 0)
            scope.set('__apid',  default_ap_address.nominal_address
                                    if isinstance(default_ap_address, APv2Address)
                                    else 0)

        # Generate __protocol value.
        protocol = delegate.get_protocol()
        scope.set('__protocol', protocol, readonly=True)

        # Generate __connection value.
        connection = delegate.get_connection_type()
        scope.set('__connection', connection, readonly=True)

        # Generate __traceout value.
        traceout = delegate.get_traceout()
        scope.set('__traceout', traceout, readonly=True)

        # Flash algorithm sequence parameters.
        scope.set('__FlashOp', 0, readonly=True)
        scope.set('__FlashAddr', 0, readonly=True)
        scope.set('__FlashLen', 0, readonly=True)
        scope.set('__FlashArg', 0, readonly=True)
        return scope

    def execute(self, context: DebugSequenceExecutionContext) -> Optional[Scope]:
        """@brief Run the sequence."""
        scope = self._create_scope(context)

        # Make this the active sequence.
        with context.push(self, scope):
            self._execute_children(context)

        return scope

    def __eq__(self, o: object) -> bool:
        return (isinstance(o, DebugSequence)
                and self.name == o.name
                and self.pname == o.pname
                and self.is_enabled == o.is_enabled)

    def __hash__(self) -> int:
        return hash((self.name, self.pname, self.is_enabled))

    def __repr__(self):
        return f"<{type(self).__name__}@{id(self):x} {self.name} enabled={self.is_enabled} pname={self.pname}>"

class Control(DebugSequenceNode):
    """@brief Base class for control nodes of debug sequences.

    Control elements create new scopes.
    """

    class ControlType(Enum):
        IF = 1
        WHILE = 2

    def __init__(self, control_type: ControlType, predicate: str, info: str = "", timeout_µs: int = 0) -> None:
        """@brief Constructor.
        @param self The control object.
        @param control_type One of the #ControlType enums that selects between if- and while-type.
        @param predicate String of the predicate expression.
        @param info Optional descriptive string.
        @param timeout_µs Integer timeout in microseconds. A value of zero means an infinite timeout.
        """
        super().__init__(info)
        self._type = control_type
        # Convert µs to seconds, and 0 to None.
        self._timeout = (timeout_µs / 1000000) if timeout_µs else None
        self._predicate = predicate
        self._ast = Parser.parse(predicate)

    def execute(self, context: DebugSequenceExecutionContext) -> Optional[Scope]:
        """@brief Run the sequence."""
        # Get our scope and interpreter objects.
        parent_scope = context.current_scope
        scope = Scope(
            parent_scope,
            name=f"{parent_scope.name}.{self._type.name}"
            )
        interp = Interpreter(self._ast, scope, context)

        # Push our new scope.
        with context.push(self, scope):
            # Start the timeout counting.
            timeout = Timeout(self._timeout)
            timeout.start()

            # Execute the predicate a first time.
            result = interp.execute()
            TRACE.debug("%s(%s): pred=%s", self._type.name, self._predicate, result)

            while result and timeout.check():
                # Execute all child nodes.
                self._execute_children(context)

                # For an if control, we're done.
                if self._type == self.ControlType.IF:
                    break
                # For a while control, re-evaluate the predicate.
                elif self._type == self.ControlType.WHILE:
                    result = interp.execute()
                    TRACE.debug("%s(%s): pred=%d", self._type.name, self._predicate, result)

        return scope

    def __repr__(self):
        return f"<{type(self).__name__}@{id(self):x} {self._ast.pretty()}>"

class WhileControl(Control):
    """@brief Looping debug sequence node."""

    def __init__(self, predicate: str, info: str = "", timeout: int = 0) -> None:
        super().__init__(self.ControlType.WHILE, predicate, info, timeout)

class IfControl(Control):
    """@brief Conditional debug sequence node."""

    def __init__(self, predicate: str, info: str = "", timeout: int = 0) -> None:
        super().__init__(self.ControlType.IF, predicate, info, timeout)

class Block(DebugSequenceNode):
    """@brief Block of debug sequence statements.

    Block elements do not create a new scope.
    """

    def __init__(self, code: str, is_atomic: bool = False, info: str = "") -> None:
        super().__init__(info)
        self._ast = Parser.parse(code)
        self._is_atomic = is_atomic

    def execute(self, context: DebugSequenceExecutionContext) -> Optional[Scope]:
        """@brief Run the sequence."""
        assert context.session.probe

        try:
            # If the block is atomic, hold the probe lock while it is executed.
            if self._is_atomic:
                context.session.probe.lock()

            interp = Interpreter(self._ast, context.current_scope, context)
            interp.execute()
        finally:
            if self._is_atomic:
                context.session.probe.unlock()

    def __repr__(self):
        atomic_str = " atomic" if self._is_atomic else ""
        return f"<{type(self).__name__}@{id(self):x}{atomic_str} {self._ast.pretty()}>"

# Using Any type for the methods of this class is a workaround for LarkToken not being
# handled or inferred correctly, since Lark doesn't have annotations.
class _ConstantFolder(lark.visitors.Transformer):
    """@brief Performs basic constant folding on expressions."""

    def _is_intlit(self, node: Any) -> bool:
        return isinstance(node, int)

    def ternary_expr(self, children: Any) -> Any:
        predicate = children[0]
        true_expr = children[1]
        false_expr = children[2]

        # Fold ternaries to either true or false branch when the predicate is an integer constant.
        if self._is_intlit(predicate):
            if predicate != 0:
                return true_expr
            elif predicate == 0:
                return false_expr

        return LarkTree('ternary_expr', children)

    def binary_expr(self, children: Any) -> Any:
        left = children[0]
        op = children[1].value
        right = children[2]

        # Fold binary expressions on literals.
        if self._is_intlit(left) and self._is_intlit(right):
            result = _BINARY_OPS[op](left, right)
            # TRACE.debug("opt: %#x %s %#x -> %#x", left, op, right, result)
            return result

        # Fold binary expressions with a left operand of zero.
        elif self._is_intlit(right) and right == 0:
            # Operators whose result will be the left operand unmodified.
            if op in ('+', '-', '|', '^', '<<', '>>', '||'):
                # TRACE.debug("opt: x %s 0 -> x", op)
                return left
            # Operators whose result will be zero.
            elif op in ('*', '/', '%', '&', '&&'):
                # TRACE.debug("opt: x %s 0 -> 0", op)
                return 0

        # Fold binary expression with a right operand of zero.
        elif self._is_intlit(left) and left == 0:
            # Operators whose result will be the right operand unmodified.
            if op in ('+', '-', '|', '^', '||'):
                # TRACE.debug("opt: 0 %s x -> x", op)
                return right
            # Operators whose result will be zero.
            elif op in ('*', '/', '%', '&', '<<', '>>', '&&'):
                # TRACE.debug("opt: 0 %s x -> 0", op)
                return 0

        # Fold binary expressions with a left operand of 1.
        elif self._is_intlit(right) and right == 1:
            # Operators whose result will be the left operand unmodified.
            if op in ('*', '/'):
                # TRACE.debug("opt: x %s 1 -> x", op)
                return left
            # Operators whose result will be one.
            elif op in ('||',):
                # TRACE.debug("opt: x %s 1 -> 1", op)
                return 1
            # Operators whose result will be zero.
            elif op in ('%',):
                # TRACE.debug("opt: x %s 1 -> 0", op)
                return 0

        return LarkTree('binary_expr', children)

    def unary_expr(self, children: Any) -> Any:
        op = children[0].value
        arg = children[1]

        # Fold unary expressions on a literal.
        if self._is_intlit(arg):
            result = _UNARY_OPS[op](arg)
            # TRACE.debug("opt: %s %#x -> %#x", op, arg, result)
            return result

        return LarkTree('unary_expr', children)

## Lambdas for evaluating binary operators.
#
# Note that divide and modulo by 0 just results in 0 rather than an exception.
_BINARY_OPS = {
    '+':    lambda l, r: l + r,
    '-':    lambda l, r: l - r,
    '*':    lambda l, r: l * r,
    '/':    lambda l, r: 0 if (r == 0) else (l // r),
    '%':    lambda l, r: 0 if (r == 0) else (l % r),
    '&':    lambda l, r: l & r,
    '|':    lambda l, r: l | r,
    '^':    lambda l, r: l ^ r,
    '<<':   lambda l, r: l << r,
    '>>':   lambda l, r: l >> r,
    '&&':   lambda l, r: int(bool(l) & bool(r)), # implement C-style AND
    '||':   lambda l, r: int(bool(l) | bool(r)), # implement C-style OR
    '==':   lambda l, r: int(l == r),
    '!=':   lambda l, r: int(l != r),
    '>':    lambda l, r: int(l > r),
    '>=':   lambda l, r: int(l >= r),
    '<':    lambda l, r: int(l < r),
    '<=':   lambda l, r: int(l <= r),
    }

## Lambdas for evaluating unary operators.
_UNARY_OPS = {
    '~':    lambda v: bit_invert(v, width=64),
    '!':    lambda v: int(not v),
    '+':    lambda v: v,
    '-':    lambda v: (-v) & 0xffffffffffffffff, # Mask to get unsigned two's complement.
    }

class SemanticChecker:
    """@brief Check the semantics of debug sequence statements."""

    class _SemanticsVisitor(lark.visitors.Visitor):
        """@brief Visitor for performing semantic checks of debug sequence statements."""

        def __init__(self, scope: Scope, context: DebugSequenceExecutionContext) -> None:
            super().__init__()
            self._scope = scope
            self._context = context
            self._fns = self._context.delegate.get_sequence_functions()
            self._declared_variables = set()

        def decl_stmt(self, tree: LarkTree) -> None:
            # Record the declared variable name.
            assert _is_token(tree.children[0], 'IDENT')
            assert isinstance(tree.children[0], LarkToken)
            name = tree.children[0].value
            self._declared_variables.add(name)

            # Disallow assigning expressions consisting of only a string.
            if _is_token(tree.children[1], 'STRLIT'):
                raise DebugSequenceSemanticError(
                        f"line {tree.meta.line}: cannot store a string to variable '{name}'")

        def assign_expr(self, tree: LarkTree) -> None:
            # Assigned variable must have been previously declared.
            # TODO disabled until declarations are fully tracked in scopes.
            assert _is_token(tree.children[0], 'IDENT')
            assert isinstance(tree.children[0], LarkToken)
            name = tree.children[0].value
#             if name not in self._declared_variables:
#                 raise DebugSequenceSemanticError(
#                         f"line {tree.meta.line}: attempt to set undeclared variable '{name}'")

            # Disallow assigning expressions consisting of only a string.
            if _is_token(tree.children[2], 'STRLIT'):
                raise DebugSequenceSemanticError(
                        f"line {tree.meta.line}: cannot store a string to variable '{name}'")

        def expr_stmt(self, tree: LarkTree) -> None:
            # Disallow statements consisting of only a string.
            if _is_token(tree.children[0], 'STRLIT'):
                raise DebugSequenceSemanticError(
                        f"line {tree.meta.line}: expression statements consisting of only a string are invalid")

        def fncall(self, tree: LarkTree) -> None:
            fn_name = tree.children[0]
            assert isinstance(fn_name, str)
            # TRACE.debug("checking %s (%s)", fn_name, tree.children[1:])

            # Case-insensitive match.
            fn_name = fn_name.lower()

            # Look up the function on the delegate.
            try:
                impl = getattr(self._fns, fn_name)
            except AttributeError:
                raise DebugSequenceSemanticError(f"line {tree.meta.line}: call to unknown function '{fn_name}'")

            # Get the function's signature.
            sig = signature(impl)

            arg_count = len(tree.children[1:])
            param_count = 0
            has_varargs = False

            # Note that the 'self' parameter should not be present due to getting the signature from the
            # bound method of the functions delegate instance.
            for param in sig.parameters.values():
                if param.kind == param.VAR_POSITIONAL:
                    # Don't need to check past a varargs parameter.
                    has_varargs = True
                    break
                else:
                    param_count += 1

                # Check arg count.
                if param_count > arg_count:
                    raise DebugSequenceSemanticError(
                            f"line {tree.meta.line}: function '{fn_name}' is passed too few arguments")

                # Check argument types.
                #
                # The type of the argument is only checked if a type annotation is present. Type annotations
                # must be stringified, eg using 'from __future__ import annotations' or Python 3.10. Only
                # explicit 'str' and 'int' annotation types are currently supported; subclasses of these
                # types are not (which is why empty annotations are allowed, as a workaround).
                arg_node = tree.children[param_count]

                # str params require a literal string arg.
                if param.annotation == 'str' and not _is_token(arg_node, 'STRLIT'):
                    raise DebugSequenceSemanticError(
                            f"line {tree.meta.line}: function '{fn_name}' parameter '{param.name}' "
                            "requires a string argument")
                # int params require either a literal int or an expression tree.
                elif param.annotation == 'int' and not \
                        (isinstance(arg_node, int) or _is_token(arg_node, 'IDENT') or isinstance(arg_node, LarkTree)):
                    raise DebugSequenceSemanticError(
                            f"line {tree.meta.line}: function '{fn_name}' parameter '{param.name}' "
                            "requires an integer argument")

            # Check for more args than parameters.
            if (param_count < arg_count) and not has_varargs:
                raise DebugSequenceSemanticError(
                        f"line {tree.meta.line}: function '{fn_name}' is passed too many arguments")

            # Function-specific checks.
            if fn_name == "Sequence":
                # From above, we know the correct number of arguments is present, and that the arg is a string.
                assert isinstance(tree.children[1], LarkToken)
                name = tree.children[1].value

                # Look for a sequence with the given name.
                if not self._context.delegate.has_sequence_with_name(name, self._context.pname):
                    raise DebugSequenceSemanticError(
                            f"line {tree.meta.line}: attempt to call undefined sequence '{name}'")

    def __init__(self, tree: LarkTree, scope: Scope, context: DebugSequenceExecutionContext) -> None:
        """@brief Constructor.

        @param self This object.
        @param tree The abstract syntax tree that will be checked.
        @param scope Scope within which the AST will execute.
        @param delegate Delegate providing debug sequence function implementations.
        """
        super().__init__()
        self._tree = tree
        self._scope = scope
        self._context = context

    def check(self) -> None:
        """@brief Performs the semantic checks and raises for any errors.
        @exception DebugSequenceSemanticError A semantic error was discovered in the provided code.
        """
        visitor = self._SemanticsVisitor(self._scope, self._context)
        visitor.visit(self._tree)

class Interpreter:
    """@brief Interpreting for debug sequence ASTs.

    This class interprets the AST from only a single block or control node. The user of this class
    is required to handle crossing block/control boundaries.

    An Interpreter instance can be used to execute the AST more than once.
    """

    class _InterpreterVisitor(lark.visitors.Interpreter):
        """@brief Visitor for interpreting sequence trees."""

        def __init__(self, scope: Scope, context: DebugSequenceExecutionContext) -> None:
            super().__init__()
            self._scope = scope
            self._context = context
            self._fns = self._context.delegate.get_sequence_functions()

        def start(self, tree: LarkTree) -> Optional[int]:
            # Interpret the tree.
            values = self.visit_children(tree)
            return values.pop() if len(values) else None

        def _log_children(self, name: str, children: List) -> None: # pragma: no cover
            LOG.info('%s: %s', name, [(("Node: %s" % c.data) if hasattr(c, 'data') else ("%s=%s" % (c.type, c.value))) for c in children])

        def decl_stmt(self, tree: LarkTree) -> None:
            values = self.visit_children(tree)

            assert _is_token(values[0], 'IDENT')
            name = values[0].value
            # Handle __var declarations with no initialiser expression. Even though this is disallowed
            # by the specification, it appears in some DFPs, including some of NXP's.
            if values[1] is None:
                value = 0

                TRACE.debug("(line %d): decl %s = 0", getattr(tree.meta, 'line', 0), name)
            else:
                value = self._get_atom(values[1])

                TRACE.debug("(line %d): decl %s = %s", getattr(tree.meta, 'line', 0), name, self._format_atom(values[1]))

            self._scope.set(name, value)

        def assign_expr(self, tree: LarkTree) -> int:
            values = self.visit_children(tree)

            name = values[0].value
            op = values[1].value
            value = self._get_atom(values[2])

            TRACE.debug("(line %d): %s %s %s", getattr(tree.meta, 'line', 0), name, op, self._format_atom(values[2]))

            # Handle compound assignment operators.
            if op != '=':
                left = self._scope.get(name)
                op = op.rstrip('=')
                value = _BINARY_OPS[op](left, value)

            self._scope.set(name, value)

            # Return the variable's value as the assignment expression's value.
            return value

        def expr_stmt(self, tree: LarkTree) -> int:
            values = self.visit_children(tree)
            expr_value = values.pop()
            TRACE.debug("(line %d): expr stmt = %s", getattr(tree.meta, 'line', 0), self._format_atom(expr_value))
            return self._get_atom(expr_value)

        def ternary_expr(self, tree: LarkTree) -> int:
            values = self.visit_children(tree)

            predicate = self._get_atom(values[0])

            if not isinstance(predicate, int):
                raise DebugSequenceSemanticError("ternary expression predicate is not an integer")

            if predicate != 0:
                result = self._get_atom(values[1])
            else:
                result = self._get_atom(values[2])

            TRACE.debug("(line %s): %s ? %s : %s -> %s",
                    getattr(tree.meta, 'line', 0),
                    self._format_atom(values[0]),
                    self._format_atom(values[1]),
                    self._format_atom(values[2]),
                    hex(result))

            return result

        def binary_expr(self, tree: LarkTree) -> int:
            values = self.visit_children(tree)

            left = self._get_atom(values[0])
            op = values[1].value
            right = self._get_atom(values[2])

            result = _BINARY_OPS[op](left, right)

            TRACE.debug("(line %s): %s %s %s -> %s", getattr(tree.meta, 'line', 0),
                    self._format_atom(values[0]), op, self._format_atom(values[2]), hex(result))
            return result

        def unary_expr(self, tree: LarkTree) -> int:
            values = self.visit_children(tree)

            op = values[0].value
            value = self._get_atom(values[1])

            result = _UNARY_OPS[op](value)

            TRACE.debug("(line %s): %s %s -> %s", getattr(tree.meta, 'line', 0), op, self._format_atom(values[1]),
                hex(result))

            return result

        def fncall(self, tree: LarkTree) -> int:
            values = self.visit_children(tree)
            fn_name = values[0]
            fn_args = [self._get_atom(a) for a in values[1:]]

            # Case-insensitive match.
            fn_name = fn_name.lower()

            TRACE.debug("(line %d): fn %s (%s) ...", getattr(tree.meta, 'line', 0), fn_name,
                ", ".join(self._format_atom(a) for a in values[1:]))

            # Should have already verified the function name.
            impl = getattr(self._fns, fn_name)
            result = impl(*fn_args)
            if result is None:
                result = 0

            TRACE.debug("(line %d): fn %s () returned %s", getattr(tree.meta, 'line', 0), fn_name, hex(result))
            return result

        def _get_atom(self, node: NodeType) -> int:
            if isinstance(node, LarkTree):
                raise DebugSequenceSemanticError(f"expected atom but found an expression tree of type {node.data}")
            elif isinstance(node, LarkToken):
                if node.type == 'IDENT':
                    try:
                        return self._scope.get(node.value)
                    except KeyError as err:
                        LOG.debug("debug sequence reference to undefined variable %s... %s",
                                node.value, self._scope.dump())
                        raise DebugSequenceSemanticError(f"reference to undefined variable {node.value}") from err
                elif node.type in ('INTLIT', 'STRLIT'):
                    return node.value
                else:
                    raise DebugSequenceSemanticError(f"unexpected literal type {node.type}")
            elif isinstance(node, int):
                return node
            else:
                raise DebugSequenceSemanticError("unexpected node type when expecting atom")

        def _format_atom(self, node: NodeType) -> str:
            """@brief Format an atom for trace logging."""
            if isinstance(node, LarkToken):
                if node.type == 'IDENT':
                    try:
                        return node.value + "{" + hex(self._scope.get(node.value)) + "}"
                    except KeyError:
                        TRACE.debug("reference to undefined variable %s... %s", node.value, self._scope.dump())
                        return node.value + "{undefined}"
                elif node.type == 'INTLIT':
                    return hex(node.value)
                elif node.type == 'STRLIT':
                    return f"'{node.value}'"
                else:
                    raise DebugSequenceSemanticError(f"unexpected literal type {node.type}")
            elif isinstance(node, int):
                return hex(node)
            else:
                return f"?<{type(node).__class__}>?"

    def __init__(self, tree: LarkTree, scope: Scope, context: DebugSequenceExecutionContext) -> None:
        """@brief Constructor.

        The provided AST is semantically checked and optimized.

        @param self This interpreter.
        @param tree The abstract syntax tree to interpret.
        @param scope Scope within which the AST will execute.
        @param delegate Delegate providing debug sequence function implementations.

        @exception DebugSequenceSemanticError A semantic error was discovered in the provided code.
        """
        super().__init__()
        self._scope = scope
        self._context = context

        # First run the semantic checker, so semantic errors are raised prior to actually
        # performing any actions.
        checker = SemanticChecker(tree, self._scope, context)
        checker.check()

        # Do some optimization.
        self._tree = _ConstantFolder().transform(tree)

    def execute(self) -> int:
        """@brief Runs the statements in the AST passed to the constructor.
        @return The value of the last statement is returned to the caller.
        """
        visitor = self._InterpreterVisitor(self._scope, self._context)
        return visitor.visit(self._tree)

