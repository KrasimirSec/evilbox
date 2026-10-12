"""Bounded interpreter for constant PHP functions and loops. Not a PHP engine."""

from __future__ import annotations

from evilbox.decode import MAX_CODEC_OUTPUT, looks_like_php_source
from evilbox.rewrite import node_text, stmt_span, walk

MAX_STEPS = 200_000
MAX_DEPTH = 8


class InterpFail(Exception):
    pass


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Ctx:
    __slots__ = ("steps", "chars", "depth", "loop", "mutated")

    def __init__(self, depth: int) -> None:
        self.steps = 0
        self.chars = 0
        self.depth = depth
        self.loop = 0
        self.mutated: set[str] = set()

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise InterpFail

    def charge(self, val) -> None:
        py = val.py if hasattr(val, "py") else val
        if isinstance(py, str):
            self.chars += len(py)
        elif isinstance(py, (bytes, list)):
            self.chars += len(py)
        if self.chars > MAX_CODEC_OUTPUT:
            raise InterpFail


def interpret_php_function(fn, values: list, source: str, env) -> object | None:
    from evilbox.php.passes import Value, _strip_php_tags

    if env is None:
        return None
    if any(getattr(v, "splice_raw", False) for v in values):
        return None
    params = _php_param_names(fn, source)
    overlay: dict[str, Value] = dict(env.overlay) if env.overlay is not None else {}
    for i, name in enumerate(params):
        overlay[name] = values[i] if i < len(values) else Value(None)
    body = fn.child_by_field_name("body")
    if body is None:
        return None
    ctx = _Ctx(depth=getattr(interpret_php_function, "_depth", 0) + 1)
    if ctx.depth > MAX_DEPTH:
        return None
    saved = env.overlay
    env.overlay = overlay
    interpret_php_function._depth = ctx.depth
    try:
        result = _stmt(body, source, env, ctx)
        if result is None:
            return None
        if result.splice_raw and isinstance(result.py, str):
            result = Value(_strip_php_tags(result.py), splice_raw=True)
        note = "Interpreted a constant PHP function."
        if note not in env.warnings:
            env.warnings.append(note)
        return result
    except InterpFail:
        return None
    finally:
        interpret_php_function._depth = ctx.depth - 1
        env.overlay = saved


def php_loop_replacements(tree, source: str, env) -> list[tuple[int, int, str]]:
    """Interpret for/while with constant inputs; splice when the next stmt evals the result."""
    from evilbox.php.passes import (
        _decoder_of_var,
        _apply_known_decoder,
        _strip_php_tags,
    )

    out: list[tuple[int, int, str]] = []
    if env.overlay is not None:
        return out
    for node in walk(tree.root_node):
        if node.type not in {"for_statement", "while_statement", "do_statement"}:
            continue
        mutated = _run_php_loop(node, source, env)
        if not mutated:
            continue
        parent = node.parent
        if parent is None:
            continue
        siblings = list(parent.named_children)
        try:
            index = siblings.index(node)
        except ValueError:
            continue
        if index + 1 >= len(siblings):
            continue
        nxt = siblings[index + 1]
        for name, val in mutated.items():
            if val is None or not isinstance(val.py, (str, bytes)):
                continue
            decoder = _decoder_of_var(nxt, source, env, name)
            payload = val.py
            if isinstance(payload, str):
                raw = payload.encode("latin-1", "replace")
            else:
                raw = payload
            decoded = _apply_known_decoder(decoder, raw) if decoder else None
            text = None
            if decoded is not None:
                try:
                    text = decoded.decode("latin-1")
                except Exception:
                    text = None
            elif isinstance(val.py, str) and looks_like_php_source(val.py):
                text = val.py
            if not text or (not looks_like_php_source(text) and "echo" not in text.lower()):
                continue
            start = node.start_byte
            _, end = stmt_span(source, nxt)
            out.append((start, end, _strip_php_tags(text)))
            env.warnings.append(
                f"Interpreted a constant PHP loop ({decoder or 'bytes'})."
            )
            break
    return out


def _run_php_loop(node, source: str, env) -> dict[str, object] | None:
    from evilbox.php.passes import Value

    names = _php_vars_in(node, source)
    overlay: dict[str, Value] = {}
    for name in names:
        reached = env.reaching(node, name)
        if reached is not None:
            overlay[name] = reached
    saved = env.overlay
    env.overlay = overlay
    ctx = _Ctx(depth=1)
    try:
        _stmt(node, source, env, ctx)
    except InterpFail:
        env.overlay = saved
        return None
    env.overlay = saved
    result = {}
    for name in ctx.mutated:
        if name in overlay:
            result[name] = overlay[name]
            env.record(node, name, overlay[name], False)
    return result


def _php_param_names(fn, source: str) -> list[str]:
    params = fn.child_by_field_name("parameters")
    if params is None:
        for child in fn.children:
            if child.type in {"formal_parameters", "parameters"}:
                params = child
                break
    if params is None:
        return []
    names: list[str] = []
    for child in params.named_children:
        if child.type == "variable_name":
            names.append(node_text(source, child).lstrip("$"))
        else:
            inner = next((c for c in child.named_children if c.type == "variable_name"), None)
            if inner is not None:
                names.append(node_text(source, inner).lstrip("$"))
    return names


def _php_vars_in(node, source: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for child in walk(node):
        if child.type != "variable_name":
            continue
        name = node_text(source, child).lstrip("$")
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _php_truthy(value) -> bool:
    if value is None or value is False:
        return False
    if value is True:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        return value not in {"", "0"}
    if isinstance(value, bytes):
        return value not in {b"", b"0"}
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _stmt(node, source: str, env, ctx: _Ctx):
    from evilbox.php.passes import Value

    ctx.tick()
    t = node.type
    if t in {"compound_statement", "program"}:
        for child in node.named_children:
            if child.type in {"php_tag", "text_interpolation", "?>"}:
                continue
            got = _stmt(child, source, env, ctx)
            if got is not None:
                return got
        return None
    if t in {"empty_statement", "comment", "php_tag"}:
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
        body = node.child_by_field_name("body")
        if cond is None:
            named = node.named_children
            cond = named[0] if named else None
            body = named[1] if len(named) > 1 else None
        if cond is None or body is None:
            raise InterpFail
        test = _expr(cond, source, env, ctx)
        if _php_truthy(test.py):
            return _stmt(body, source, env, ctx)
        alt = node.child_by_field_name("alternative")
        if alt is None:
            for child in node.named_children:
                if child.type in {"else_clause", "else_if_clause"}:
                    alt = child
                    break
        if alt is not None:
            inner = alt.named_children[-1] if alt.named_children else alt
            return _stmt(inner, source, env, ctx)
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
    if t in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
        _expr(node, source, env, ctx)
        return None
    raise InterpFail


def _for(node, source: str, env, ctx: _Ctx):
    from evilbox.php.passes import const_eval

    body = node.child_by_field_name("body")
    cond = node.child_by_field_name("condition")
    incr = node.child_by_field_name("update") or node.child_by_field_name("increment")
    init = node.child_by_field_name("initializer") or node.child_by_field_name("init")

    def _same(a, b) -> bool:
        return (
            a is not None
            and b is not None
            and a.start_byte == b.start_byte
            and a.end_byte == b.end_byte
            and a.type == b.type
        )

    if init is None:
        for child in node.named_children:
            if any(_same(child, item) for item in (body, cond, incr)):
                continue
            init = child
            break
    if init is not None:
        _expr(init, source, env, ctx)
    ctx.loop += 1
    try:
        while True:
            ctx.tick()
            if cond is not None:
                test = const_eval(cond, source, env)
                if test is None:
                    test = _expr(cond, source, env, ctx)
                if not _php_truthy(test.py):
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
    from evilbox.php.passes import const_eval

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
                if not _php_truthy(test.py):
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
    from evilbox.php.passes import Value, _is_num, const_eval

    t = node.type
    if t == "parenthesized_expression" and node.named_children:
        return _expr(node.named_children[0], source, env, ctx)
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
        return _assign(node, source, env, ctx, op=op or ".=")
    if t == "update_expression":
        return _update(node, source, env, ctx)
    val = const_eval(node, source, env)
    if val is None:
        raise InterpFail
    ctx.charge(val)
    return val


def _assign(node, source: str, env, ctx: _Ctx, *, op: str):
    from evilbox.php.passes import Value, _is_num

    overlay = env.overlay
    if overlay is None:
        raise InterpFail
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None or left.type != "variable_name":
        raise InterpFail
    name = node_text(source, left).lstrip("$")
    rhs = _expr(right, source, env, ctx)
    if op == "=":
        overlay[name] = rhs
        ctx.mutated.add(name)
        return rhs
    cur = overlay.get(name)
    if cur is None:
        raise InterpFail
    if op in {".=", "+="}:
        if isinstance(cur.py, str) or isinstance(rhs.py, str):
            left_s = cur.py if isinstance(cur.py, str) else str(cur.py)
            right_s = rhs.py if isinstance(rhs.py, str) else str(rhs.py)
            nxt = Value(left_s + right_s)
        elif _is_num(cur.py) and _is_num(rhs.py) and op == "+=":
            nxt = Value(cur.py + rhs.py)
        else:
            raise InterpFail
        ctx.charge(nxt)
        overlay[name] = nxt
        ctx.mutated.add(name)
        return nxt
    raise InterpFail


def _update(node, source: str, env, ctx: _Ctx):
    from evilbox.php.passes import Value, _is_num

    overlay = env.overlay
    if overlay is None:
        raise InterpFail
    arg = node.named_children[0] if node.named_children else None
    if arg is None or arg.type != "variable_name":
        raise InterpFail
    name = node_text(source, arg).lstrip("$")
    cur = overlay.get(name)
    if cur is None or not _is_num(cur.py):
        raise InterpFail
    plus = any(child.type == "++" for child in node.children)
    nxt = Value(int(cur.py) + (1 if plus else -1))
    overlay[name] = nxt
    ctx.mutated.add(name)
    prefix = node.children and node.children[0].type in {"++", "--"}
    return nxt if prefix else cur
