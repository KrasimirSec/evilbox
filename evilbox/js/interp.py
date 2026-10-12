"""Bounded interpreter for constant JS functions. Not a JS engine."""

from __future__ import annotations

from evilbox.decode import MAX_CODEC_OUTPUT
from evilbox.rewrite import node_text

MAX_STEPS = 200_000
MAX_DEPTH = 8


class InterpFail(Exception):
    pass


class _Ctx:
    __slots__ = ("steps", "chars", "depth", "loop")

    def __init__(self, depth: int) -> None:
        self.steps = 0
        self.chars = 0
        self.depth = depth
        self.loop = 0

    def tick(self, n: int = 1) -> None:
        self.steps += n
        if self.steps > MAX_STEPS:
            raise InterpFail

    def charge(self, val) -> None:
        py = val.py if hasattr(val, "py") else val
        if isinstance(py, str):
            self.chars += len(py)
        elif isinstance(py, list):
            self.chars += len(py)
        if self.chars > MAX_CODEC_OUTPUT:
            raise InterpFail


def interpret_js_iife(node, values: list, source: str, env) -> object | None:
    """Run a function_expression / arrow IIFE when every argument is constant."""
    from evilbox.js.passes import FoldEnv, Value, _function_param_names

    if env is None:
        return None
    fn = node.child_by_field_name("function")
    if fn is None and node.named_children:
        fn = node.named_children[0]
    while fn is not None and fn.type == "parenthesized_expression" and fn.named_children:
        fn = fn.named_children[0]
    if fn is None or fn.type not in {"function_expression", "arrow_function"}:
        return None
    if any(v.splice_raw for v in values):
        return None
    params = _function_param_names(fn, source)
    overlay: dict[str, Value] = dict(env.overlay) if env.overlay is not None else {}
    for i, name in enumerate(params):
        if i < len(values):
            overlay[name] = values[i]
        else:
            overlay[name] = Value(None)
    body = fn.child_by_field_name("body")
    if body is None:
        return None
    saved = env.overlay
    env.overlay = overlay
    ctx = _Ctx(depth=(getattr(interpret_js_iife, "_depth", 0) + 1))
    if ctx.depth > MAX_DEPTH:
        env.overlay = saved
        return None
    interpret_js_iife._depth = ctx.depth
    try:
        if body.type == "statement_block":
            result = _stmt(body, source, env, ctx)
        else:
            result = _expr(body, source, env, ctx)
        if result is None:
            return None
        note = "Interpreted a constant JS function."
        if note not in env.warnings:
            env.warnings.append(note)
        return result
    except InterpFail:
        return None
    finally:
        interpret_js_iife._depth = ctx.depth - 1
        env.overlay = saved


def _stmt(node, source: str, env, ctx: _Ctx):
    from evilbox.js.passes import Value

    ctx.tick()
    t = node.type
    if t in {"statement_block", "program"}:
        for child in node.named_children:
            got = _stmt(child, source, env, ctx)
            if got is not None:
                return got
        return None
    if t in {"empty_statement", "comment"}:
        return None
    if t in {"lexical_declaration", "variable_declaration"}:
        _decl(node, source, env, ctx)
        return None
    if t == "expression_statement":
        inner = node.named_children[0] if node.named_children else None
        if inner is not None:
            _expr(inner, source, env, ctx)
        return None
    if t == "return_statement":
        inner = node.named_children[0] if node.named_children else None
        if inner is None:
            return Value(None)
        return _expr(inner, source, env, ctx)
    if t == "if_statement":
        cond = node.child_by_field_name("condition")
        cons = node.child_by_field_name("consequence")
        alt = node.child_by_field_name("alternative")
        if cond is None or cons is None:
            raise InterpFail
        test = _expr(cond, source, env, ctx)
        from evilbox.js.passes import _js_truthy

        if _js_truthy(test.py):
            return _stmt(cons, source, env, ctx)
        if alt is not None:
            body = alt.named_children[0] if alt.type == "else_clause" and alt.named_children else alt
            return _stmt(body, source, env, ctx)
        return None
    if t == "for_statement":
        return _for(node, source, env, ctx)
    if t == "while_statement":
        return _while(node, source, env, ctx, do=False)
    if t == "do_statement":
        return _while(node, source, env, ctx, do=True)
    if t == "break_statement":
        if ctx.loop <= 0:
            raise InterpFail
        raise _Break()
    if t == "continue_statement":
        if ctx.loop <= 0:
            raise InterpFail
        raise _Continue()
    raise InterpFail


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


def _decl(node, source: str, env, ctx: _Ctx) -> None:
    from evilbox.js.passes import Value

    overlay = env.overlay
    if overlay is None:
        raise InterpFail
    for child in node.named_children:
        if child.type != "variable_declarator":
            continue
        name_node = child.child_by_field_name("name")
        value = child.child_by_field_name("value")
        if name_node is None or name_node.type != "identifier":
            raise InterpFail
        name = node_text(source, name_node)
        if value is None:
            overlay[name] = Value(None)
        else:
            overlay[name] = _expr(value, source, env, ctx)


def _for(node, source: str, env, ctx: _Ctx):
    init = node.child_by_field_name("initializer")
    cond = node.child_by_field_name("condition")
    incr = node.child_by_field_name("increment")
    body = node.child_by_field_name("body")
    if init is not None:
        if init.type in {"lexical_declaration", "variable_declaration"}:
            _decl(init, source, env, ctx)
        else:
            _expr(init, source, env, ctx)
    from evilbox.js.passes import _js_truthy, const_eval

    ctx.loop += 1
    try:
        while True:
            ctx.tick()
            if cond is not None:
                test = const_eval(cond, source, env)
                if test is None:
                    test = _expr(cond, source, env, ctx)
                if not _js_truthy(test.py):
                    return None
            if body is not None:
                try:
                    got = _stmt(body, source, env, ctx)
                except _Continue:
                    got = None
                except _Break:
                    return None
                if got is not None:
                    return got
            if incr is not None:
                _expr(incr, source, env, ctx)
            if cond is None:
                raise InterpFail
    finally:
        ctx.loop -= 1


def _while(node, source: str, env, ctx: _Ctx, *, do: bool):
    from evilbox.js.passes import _js_truthy, const_eval

    cond = node.child_by_field_name("condition")
    body = node.child_by_field_name("body")
    if cond is None or body is None:
        raise InterpFail
    ctx.loop += 1
    try:
        first = True
        while True:
            ctx.tick()
            if not (do and first):
                test = const_eval(cond, source, env)
                if test is None:
                    test = _expr(cond, source, env, ctx)
                if not _js_truthy(test.py):
                    return None
            first = False
            try:
                got = _stmt(body, source, env, ctx)
            except _Continue:
                got = None
            except _Break:
                return None
            if got is not None:
                return got
    finally:
        ctx.loop -= 1


def _expr(node, source: str, env, ctx: _Ctx):
    from evilbox.js.passes import const_eval

    t = node.type
    if t == "parenthesized_expression" and node.named_children:
        return _expr(node.named_children[0], source, env, ctx)
    if t == "sequence_expression":
        last = None
        for child in node.named_children:
            last = _expr(child, source, env, ctx)
        if last is None:
            raise InterpFail
        return last
    if t == "assignment_expression":
        return _assign(node, source, env, ctx, op="=")
    if t == "augmented_assignment_expression":
        op_node = node.child_by_field_name("operator")
        op = op_node.type if op_node is not None else ""
        if not op:
            for child in node.children:
                if not child.is_named and child.type.endswith("="):
                    op = child.type
                    break
        return _assign(node, source, env, ctx, op=op or "+=")
    if t == "update_expression":
        return _update(node, source, env, ctx)
    if t == "call_expression":
        mutated = _mutating_call(node, source, env, ctx)
        if mutated is not None:
            ctx.charge(mutated)
            return mutated
    val = const_eval(node, source, env)
    if val is None:
        raise InterpFail
    ctx.charge(val)
    return val


def _assign(node, source: str, env, ctx: _Ctx, *, op: str):
    from evilbox.js.passes import Value, _is_num

    overlay = env.overlay
    if overlay is None:
        raise InterpFail
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None or left.type != "identifier":
        raise InterpFail
    name = node_text(source, left)
    rhs = _expr(right, source, env, ctx)
    if op == "=":
        overlay[name] = rhs
        return rhs
    cur = overlay.get(name)
    if cur is None:
        raise InterpFail
    if op == "+=":
        if isinstance(cur.py, str) or isinstance(rhs.py, str):
            nxt = Value(str(cur.py) + str(rhs.py))
        elif _is_num(cur.py) and _is_num(rhs.py):
            nxt = Value(cur.py + rhs.py)
        else:
            raise InterpFail
        ctx.charge(nxt)
        overlay[name] = nxt
        return nxt
    raise InterpFail


def _update(node, source: str, env, ctx: _Ctx):
    from evilbox.js.passes import Value, _is_num

    overlay = env.overlay
    if overlay is None:
        raise InterpFail
    arg = node.named_children[0] if node.named_children else None
    if arg is None or arg.type != "identifier":
        raise InterpFail
    name = node_text(source, arg)
    cur = overlay.get(name)
    if cur is None or not _is_num(cur.py):
        raise InterpFail
    plus = any(child.type == "++" for child in node.children)
    nxt = Value(cur.py + 1 if plus else cur.py - 1)
    overlay[name] = nxt
    prefix = node.children and node.children[0].type in {"++", "--"}
    return nxt if prefix else cur


def _mutating_call(node, source: str, env, ctx: _Ctx):
    from evilbox.js.passes import Value, _call_args, _callee, const_eval

    obj, prop, recv = _callee(node, source, env)
    if recv is None or not isinstance(recv.py, list) or not prop:
        return None
    args = []
    for arg in _call_args(node):
        val = const_eval(arg, source, env)
        if val is None:
            val = _expr(arg, source, env, ctx)
        args.append(val)
    if prop == "push":
        for val in args:
            recv.py.append(val if isinstance(val, Value) else Value(val.py))
        return Value(len(recv.py))
    if prop == "shift":
        if not recv.py:
            return Value(None)
        item = recv.py.pop(0)
        return item if isinstance(item, Value) else Value(item)
    if prop == "pop":
        if not recv.py:
            return Value(None)
        item = recv.py.pop()
        return item if isinstance(item, Value) else Value(item)
    return None
