"""Static structural simplifications for javascript-obfuscator output.

These rewrites do not execute the program. They inline constant objects and
dispatcher functions, unflatten ``split("|")`` switches, and drop branches
whose test is a constant string comparison.
"""

from __future__ import annotations

import re

from evilbox.parsers import parse_js
from evilbox.rewrite import apply_replacements, has_error, node_text, stmt_span, walk

_IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_SEQ_RE = re.compile(r"^\d+(?:\|\d+)*$")
_DIGIT_RE = re.compile(r"^\d+$")
_SAFE_DOT_OBJECT = {
    "identifier",
    "member_expression",
    "subscript_expression",
    "call_expression",
    "parenthesized_expression",
    "this",
    "array",
    "string",
    "template_string",
}
_COMPARE_OPS = {"===", "==", "!==", "!="}
_PURE_SKIP = {
    "call_expression",
    "identifier",
    "assignment_expression",
    "update_expression",
    "new_expression",
}


def simplify_js_structure(source: str) -> tuple[str, list[str]]:
    """Apply structural rewrites until one pass stops changing the text."""
    warnings: list[str] = []
    for _ in range(5):
        nxt, found = _one_pass(source)
        if nxt == source:
            break
        source = nxt
        warnings.extend(found)
    deduped: list[str] = []
    for warning in warnings:
        if warning not in deduped:
            deduped.append(warning)
    return source, deduped


def _one_pass(source: str) -> tuple[str, list[str]]:
    tree = parse_js(source)
    if has_error(tree.root_node):
        return source, []
    replacements: list[tuple[int, int, str]] = []
    warnings: list[str] = []
    _collect(replacements, warnings, _inline_objects(tree, source))
    _collect(replacements, warnings, _inline_anonymous_objects(tree, source))
    _collect(replacements, warnings, _dead_string_branches(tree, source))
    _collect(replacements, warnings, _flatten_switches(tree, source))
    _collect(replacements, warnings, _cleanup_replacements(tree, source))
    _collect(replacements, warnings, _debug_protection(tree, source))
    _collect(replacements, warnings, _self_defending(tree, source))
    if not replacements:
        return source, []
    text = apply_replacements(source, replacements)
    if text == source:
        return source, []
    return text, warnings


def _collect(replacements: list, warnings: list, found: tuple[list, str] | None) -> None:
    if not found or not found[0]:
        return
    replacements.extend(found[0])
    if found[1]:
        warnings.append(found[1])


def _const(node, source):
    from evilbox.js.passes import const_eval

    if node is None:
        return None
    return const_eval(node, source, None)


def _binary_op(node):
    from evilbox.js.passes import _binary_op as op

    return op(node)


def _unwrap(node):
    while node is not None and node.type == "parenthesized_expression" and node.named_children:
        node = node.named_children[0]
    return node


def _unary_op(node) -> str | None:
    for child in node.children:
        if not child.is_named and child.type in {"!", "+", "-", "~", "typeof", "void", "delete"}:
            return child.type
    return None


def _same(a, b) -> bool:
    return a is not None and b is not None and a.start_byte == b.start_byte and a.type == b.type


def _field_children(node, field: str) -> list:
    found = []
    for index, child in enumerate(node.children):
        if node.field_name_for_child(index) == field:
            found.append(child)
    return found


def _block_stmts(node) -> list:
    if node is None or node.type not in {"statement_block", "program", "switch_body"}:
        return []
    return [child for child in node.named_children if child.type != "comment"]


def _stmt(node):
    current = node
    while current is not None and current.parent is not None and current.parent.type not in {
        "statement_block",
        "program",
    }:
        current = current.parent
    return current


def _call_args(node) -> list:
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    return list(args.named_children)


def _sole_declarator(stmt):
    if stmt is None or stmt.type not in {"variable_declaration", "lexical_declaration"}:
        return None
    decls = [child for child in stmt.named_children if child.type == "variable_declarator"]
    if len(decls) != 1:
        return None
    return decls[0]


def _is_eq(node) -> bool:
    return node.type == "assignment_expression" and any(not child.is_named and child.type == "=" for child in node.children)


def _name_counts(tree, source: str) -> dict[str, int]:
    counts: dict[str, int] = {}

    def add(node) -> None:
        if node is None or node.type != "identifier":
            return
        name = node_text(source, node)
        counts[name] = counts.get(name, 0) + 1

    for node in walk(tree.root_node):
        if node.type == "variable_declarator":
            add(node.child_by_field_name("name"))
        elif node.type in {"function_declaration", "function_expression"}:
            add(node.child_by_field_name("name"))
        elif node.type == "formal_parameters":
            for child in node.named_children:
                if child.type == "identifier":
                    add(child)
                elif child.type == "rest_pattern":
                    add(next((item for item in child.named_children if item.type == "identifier"), None))
        elif node.type == "arrow_function":
            add(node.child_by_field_name("parameter"))
        elif node.type == "catch_clause":
            add(node.child_by_field_name("parameter"))
    return counts


def _refs(tree, source: str, name: str, decl_start: int) -> list:
    found = []
    for node in walk(tree.root_node):
        if node.type == "identifier" and node.start_byte != decl_start and node_text(source, node) == name:
            found.append(node)
        elif node.type == "shorthand_property_identifier" and node_text(source, node) == name:
            found.append(node)
    return found


def _member_key(member, source: str):
    if member.type == "member_expression":
        prop = member.child_by_field_name("property")
        if prop is not None and prop.type == "property_identifier":
            return node_text(source, prop)
        return None
    if member.type != "subscript_expression":
        return None
    index = member.child_by_field_name("index")
    val = _const(index, source)
    if val is None or val.splice_raw:
        return None
    if isinstance(val.py, str):
        return val.py
    if isinstance(val.py, int) and not isinstance(val.py, bool):
        return str(val.py)
    return None


def _ref_kind(ident, source: str):
    if ident.type != "identifier":
        return ("other",)
    parent = ident.parent
    if parent is None:
        return ("other",)
    if parent.type == "assignment_expression" and _same(parent.child_by_field_name("left"), ident):
        return ("write",)
    if parent.type == "update_expression":
        return ("write",)
    if parent.type == "variable_declarator":
        value = _unwrap(parent.child_by_field_name("value"))
        if _same(value, ident) or _same(parent.child_by_field_name("value"), ident):
            return ("alias",)
    if parent.type in {"member_expression", "subscript_expression"} and _same(parent.child_by_field_name("object"), ident):
        key = _member_key(parent, source)
        if key is None or key == "__proto__":
            return ("other",)
        grand = parent.parent
        if grand is not None and grand.type == "unary_expression" and _unary_op(grand) == "delete":
            return ("other",)
        if grand is not None and _is_eq(grand) and _same(grand.child_by_field_name("left"), parent):
            return ("member-write", key, parent)
        if grand is not None and grand.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
            return ("other",)
        return ("member-read", key, parent)
    return ("other",)


def _params(fn, source: str):
    params = fn.child_by_field_name("parameters")
    if params is None or params.type != "formal_parameters":
        return None
    names: list[str] = []
    rest = None
    for child in params.named_children:
        if child.type == "identifier":
            if rest is not None:
                return None
            names.append(node_text(source, child))
        elif child.type == "rest_pattern":
            ident = next((item for item in child.named_children if item.type == "identifier"), None)
            if ident is None or rest is not None:
                return None
            rest = node_text(source, ident)
        else:
            return None
    return names, rest


def _return_expr(fn):
    body = fn.child_by_field_name("body")
    if body is None or body.type != "statement_block":
        return None
    stmts = _block_stmts(body)
    if len(stmts) != 1 or stmts[0].type != "return_statement":
        return None
    named = stmts[0].named_children
    if len(named) != 1:
        return None
    return _unwrap(named[0])


def _classify_fn(fn, source: str):
    parsed = _params(fn, source)
    if parsed is None:
        return None
    names, rest = parsed
    expr = _return_expr(fn)
    if expr is None:
        return None
    if rest is not None:
        if len(names) != 1 or expr.type != "call_expression":
            return None
        callee = expr.child_by_field_name("function")
        args = _call_args(expr)
        if (
            callee is None
            or callee.type != "identifier"
            or node_text(source, callee) != names[0]
            or len(args) != 1
            or args[0].type != "spread_element"
        ):
            return None
        inner = next((item for item in args[0].named_children if item.is_named), None)
        if inner is None or inner.type != "identifier" or node_text(source, inner) != rest:
            return None
        return ("spread", fn)
    if expr.type == "call_expression" and names:
        callee = expr.child_by_field_name("function")
        args = _call_args(expr)
        if (
            callee is not None
            and callee.type == "identifier"
            and node_text(source, callee) == names[0]
            and len(args) == len(names) - 1
            and all(
                arg.type == "identifier" and node_text(source, arg) == names[index + 1]
                for index, arg in enumerate(args)
            )
        ):
            return ("call", fn)
        return None
    if len(names) == 2 and expr.type == "binary_expression":
        op = _binary_op(expr)
        left = expr.child_by_field_name("left")
        right = expr.child_by_field_name("right")
        if (
            op
            and left is not None
            and right is not None
            and left.type == "identifier"
            and right.type == "identifier"
        ):
            left_name = node_text(source, left)
            right_name = node_text(source, right)
            if left_name in names and right_name in names and left_name != right_name:
                return ("binop", fn, op, names.index(left_name), names.index(right_name))
    return None


def _classify_value(node, source: str):
    node = _unwrap(node)
    if node is None:
        return None
    if node.type in {"string", "number", "true", "false", "null"}:
        return ("literal", node)
    if node.type == "function_expression" and node.child_by_field_name("name") is None:
        return _classify_fn(node, source)
    return None


def _prop_name(key, source: str) -> str | None:
    if key is None:
        return None
    if key.type == "property_identifier":
        name = node_text(source, key)
        return None if name == "__proto__" else name
    if key.type == "computed_property_name":
        inner = next((child for child in key.named_children), None)
        return _prop_name(inner, source)
    if key.type == "string":
        val = _const(key, source)
        if val is None or not isinstance(val.py, str) or val.py == "__proto__":
            return None
        return val.py
    if key.type == "number":
        val = _const(key, source)
        if val is None or isinstance(val.py, bool) or not isinstance(val.py, int):
            return None
        return str(val.py)
    return None


def _props_of_object(obj, source: str):
    props = {}
    for child in obj.named_children:
        if child.type != "pair":
            return None
        key = _prop_name(child.child_by_field_name("key"), source)
        classified = _classify_value(child.child_by_field_name("value"), source)
        if key is None or classified is None:
            return None
        props[key] = classified
    return props


def _pexpr(node, source: str) -> str:
    text = node_text(source, node)
    if node.type in {
        "identifier",
        "member_expression",
        "subscript_expression",
        "call_expression",
        "parenthesized_expression",
        "number",
        "string",
        "true",
        "false",
        "null",
        "template_string",
        "this",
    }:
        return text
    return f"({text})"


def _emit_forward(args, source: str) -> str:
    parts = []
    for arg in args[1:]:
        if arg.type == "spread_element":
            inner = next((item for item in arg.named_children if item.is_named), None)
            if inner is None:
                return ""
            parts.append("..." + _pexpr(inner, source))
        else:
            parts.append(_pexpr(arg, source))
    return f"{_pexpr(args[0], source)}({', '.join(parts)})"


def _emit_member(member, classified, source: str):
    call = member.parent
    is_call = (
        call is not None
        and call.type == "call_expression"
        and _same(call.child_by_field_name("function"), member)
    )
    kind = classified[0]
    if kind == "literal":
        if is_call:
            return None
        return member.start_byte, member.end_byte, node_text(source, classified[1])
    if not is_call:
        fn = classified[1]
        return member.start_byte, member.end_byte, node_text(source, fn)
    args = _call_args(call)
    if kind == "binop":
        _fn, _op_node, op, left_i, right_i = classified
        if len(args) != 2 or any(arg.type == "spread_element" for arg in args):
            return None
        text = f"({_pexpr(args[left_i], source)} {op} {_pexpr(args[right_i], source)})"
        return call.start_byte, call.end_byte, text
    if kind == "call":
        names, rest = _params(classified[1], source)
        if rest or not args or len(args) != len(names) or any(arg.type == "spread_element" for arg in args):
            return None
        return call.start_byte, call.end_byte, _emit_forward(args, source)
    if kind == "spread":
        if not args:
            return None
        return call.start_byte, call.end_byte, _emit_forward(args, source)
    return None


def _prop_assignment(stmt, name: str, source: str):
    if stmt.type != "expression_statement" or not stmt.named_children:
        return None
    expr = stmt.named_children[0]
    if not _is_eq(expr):
        return None
    left = expr.child_by_field_name("left")
    right = expr.child_by_field_name("right")
    if left is None or right is None or left.type not in {"member_expression", "subscript_expression"}:
        return None
    obj = left.child_by_field_name("object")
    if obj is None or obj.type != "identifier" or node_text(source, obj) != name:
        return None
    key = _member_key(left, source)
    if not key or key == "__proto__":
        return None
    return key, right


def _alias_of(stmt, name: str, source: str):
    decl = _sole_declarator(stmt)
    if decl is None:
        return None
    alias = decl.child_by_field_name("name")
    value = _unwrap(decl.child_by_field_name("value"))
    if alias is None or alias.type != "identifier" or value is None:
        return None
    if value.type != "identifier" or node_text(source, value) != name:
        return None
    return stmt, alias


def _inline_objects(tree, source: str):
    counts = _name_counts(tree, source)
    reps: list[tuple[int, int, str]] = []
    literal = False
    dispatcher = False
    seen: set[int] = set()
    for node in walk(tree.root_node):
        if node.type != "variable_declarator" or node.start_byte in seen:
            continue
        prepared = _prepare_object(node, source)
        if prepared is None:
            continue
        props, stmt, extras, alias, name_node, name = prepared
        if not props or counts.get(name, 0) != 1:
            continue
        seen.add(node.start_byte)
        alias_name = node_text(source, alias[1]) if alias else None
        if alias and counts.get(alias_name, 0) != 1:
            continue
        if not _writes_are_local(tree, source, name, name_node.start_byte, extras, alias):
            continue
        if alias:
            use_name = alias_name
            use_start = alias[1].start_byte
            delete_stmts = [stmt, *extras, alias[0]]
        else:
            use_name = name
            use_start = name_node.start_byte
            delete_stmts = [stmt, *extras]
        use_reps = _use_replacements(tree, source, use_name, use_start, props)
        if use_reps is None or not use_reps:
            continue
        for item in delete_stmts:
            start, end = stmt_span(source, item)
            reps.append((start, end, ""))
        reps.extend(use_reps)
        if all(item[0] == "literal" for item in props.values()):
            literal = True
        else:
            dispatcher = True
    if not reps:
        return None
    if dispatcher:
        return reps, "Inlined control-flow dispatcher"
    if literal:
        return reps, "Inlined constant object properties"
    return reps, "Inlined constant object properties"


def _prepare_object(decl, source: str):
    name_node = decl.child_by_field_name("name")
    value = _unwrap(decl.child_by_field_name("value"))
    if name_node is None or name_node.type != "identifier" or value is None or value.type != "object":
        return None
    props = _props_of_object(value, source)
    if props is None:
        return None
    stmt = _stmt(decl)
    if _sole_declarator(stmt) is None:
        return None
    if stmt.parent is None or stmt.parent.type not in {"statement_block", "program"}:
        return None
    stmts = _block_stmts(stmt.parent)
    try:
        index = next(i for i, item in enumerate(stmts) if item.start_byte == stmt.start_byte)
    except StopIteration:
        return None
    name = node_text(source, name_node)
    extras = []
    cursor = index + 1
    while cursor < len(stmts):
        got = _prop_assignment(stmts[cursor], name, source)
        if got is None:
            break
        key, raw_value = got
        classified = _classify_value(raw_value, source)
        if classified is None:
            break
        props[key] = classified
        extras.append(stmts[cursor])
        cursor += 1
    alias = _alias_of(stmts[cursor], name, source) if cursor < len(stmts) else None
    return props, stmt, extras, alias, name_node, name


def _writes_are_local(tree, source, name, decl_start, extras, alias) -> bool:
    extra_starts = {item.start_byte for item in extras}
    alias_start = alias[0].start_byte if alias else None
    for ref in _refs(tree, source, name, decl_start):
        kind = _ref_kind(ref, source)
        if kind[0] == "member-write" and _stmt(ref) is not None and _stmt(ref).start_byte in extra_starts:
            continue
        if kind[0] == "alias" and alias_start is not None and _stmt(ref) is not None and _stmt(ref).start_byte == alias_start:
            continue
        if kind[0] == "member-read" and alias is None:
            continue
        return False
    return True


def _use_replacements(tree, source, name, decl_start, props):
    reps = []
    for ref in _refs(tree, source, name, decl_start):
        kind = _ref_kind(ref, source)
        if kind[0] != "member-read":
            return None
        classified = props.get(kind[1])
        if classified is None:
            return None
        emitted = _emit_member(kind[2], classified, source)
        if emitted is None:
            return None
        reps.append(emitted)
    return reps


def _inline_anonymous_objects(tree, source: str):
    reps = []
    for node in walk(tree.root_node):
        if node.type not in {"member_expression", "subscript_expression"}:
            continue
        obj = _unwrap(node.child_by_field_name("object"))
        if obj is None or obj.type != "object":
            continue
        props = _props_of_object(obj, source)
        if not props:
            continue
        key = _member_key(node, source)
        classified = props.get(key) if key else None
        if classified is None:
            continue
        emitted = _emit_member(node, classified, source)
        if emitted is None:
            continue
        reps.append(emitted)
    if not reps:
        return None
    return reps, "Inlined constant object properties"


def _is_pure(node, source: str) -> bool:
    for item in walk(node):
        if item.type in _PURE_SKIP:
            return False
    val = _const(node, source)
    return val is not None and not val.splice_raw


def _string_compare_truth(node, source: str):
    node = _unwrap(node)
    if node is None:
        return None
    if node.type == "sequence_expression":
        parts = list(node.named_children)
        if len(parts) < 2 or not all(_is_pure(part, source) for part in parts[:-1]):
            return None
        node = _unwrap(parts[-1])
    neg = False
    if node is not None and node.type == "unary_expression" and _unary_op(node) == "!":
        neg = True
        arg = node.named_children[0] if node.named_children else None
        node = _unwrap(arg)
    if node is None or node.type != "binary_expression":
        return None
    op = _binary_op(node)
    if op not in _COMPARE_OPS:
        return None
    left = _const(node.child_by_field_name("left"), source)
    right = _const(node.child_by_field_name("right"), source)
    if (
        left is None
        or right is None
        or left.splice_raw
        or right.splice_raw
        or not isinstance(left.py, str)
        or not isinstance(right.py, str)
    ):
        return None
    truth = left.py == right.py if op in {"===", "=="} else left.py != right.py
    return (not truth) if neg else truth


def _dead_string_branches(tree, source: str):
    reps = []
    for node in walk(tree.root_node):
        if node.type == "if_statement":
            truth = _string_compare_truth(node.child_by_field_name("condition"), source)
            if truth is None:
                continue
            kept = node.child_by_field_name("consequence") if truth else node.child_by_field_name("alternative")
            if kept is None:
                text = ""
            else:
                if kept.type == "else_clause":
                    named = kept.named_children
                    kept = named[-1] if named else None
                text = node_text(source, kept) if kept is not None else ""
            start, end = stmt_span(source, node)
            reps.append((start, end, text))
        elif node.type == "ternary_expression":
            truth = _string_compare_truth(node.child_by_field_name("condition"), source)
            if truth is None:
                continue
            kept = node.child_by_field_name("consequence") if truth else node.child_by_field_name("alternative")
            if kept is None:
                continue
            reps.append((node.start_byte, node.end_byte, node_text(source, kept)))
    if not reps:
        return None
    return reps, "Removed dead string-comparison branch"


def _split_pipe(node, source: str) -> str | None:
    node = _unwrap(node)
    if node is None or node.type != "call_expression":
        return None
    fn = node.child_by_field_name("function")
    if fn is None or _member_key(fn, source) != "split":
        return None
    obj = fn.child_by_field_name("object")
    args = _call_args(node)
    if obj is None or len(args) != 1:
        return None
    sep = _const(args[0], source)
    seq = _const(obj, source)
    if sep is None or seq is None or sep.py != "|" or not isinstance(seq.py, str):
        return None
    if not _SEQ_RE.fullmatch(seq.py):
        return None
    return seq.py


def _sequence_value(node, source: str) -> str | None:
    node = _unwrap(node)
    if node is None:
        return None
    piped = _split_pipe(node, source)
    if piped is not None:
        return piped
    if node.type != "array":
        return None
    parts: list[str] = []
    for child in node.named_children:
        if child.type == "spread_element":
            return None
        val = _const(child, source)
        if val is None or val.splice_raw or not isinstance(val.py, str) or not _DIGIT_RE.fullmatch(val.py):
            return None
        parts.append(val.py)
    if not parts:
        return None
    return "|".join(parts)


def _sequence_decl(stmt, source: str):
    decl = _sole_declarator(stmt)
    if decl is None:
        return None
    name = decl.child_by_field_name("name")
    seq = _sequence_value(decl.child_by_field_name("value"), source)
    if name is None or name.type != "identifier" or seq is None:
        return None
    return node_text(source, name), seq


def _iterator_decl(stmt, source: str):
    decl = _sole_declarator(stmt)
    if decl is None:
        return None
    name = decl.child_by_field_name("name")
    init = decl.child_by_field_name("value")
    if name is None or name.type != "identifier" or init is None:
        return None
    val = _const(init, source)
    if val is None or isinstance(val.py, bool) or val.py != 0:
        return None
    return node_text(source, name)


def _is_double_bang_empty_array(node) -> bool:
    if node is None or node.type != "unary_expression" or _unary_op(node) != "!":
        return False
    arg = node.named_children[0] if node.named_children else None
    arg = _unwrap(arg)
    if arg is None or arg.type != "unary_expression" or _unary_op(arg) != "!":
        return False
    arr = _unwrap(arg.named_children[0] if arg.named_children else None)
    return arr is not None and arr.type == "array" and not arr.named_children


def _is_forced_true(node, source: str) -> bool:
    node = _unwrap(node)
    if node is None:
        return False
    if node.type == "true":
        return True
    if node.type == "number" and node_text(source, node) in {"1", "1.0"}:
        return True
    if _is_double_bang_empty_array(node):
        return True
    if node.type == "unary_expression" and _unary_op(node) == "!":
        arg = _unwrap(node.named_children[0] if node.named_children else None)
        if arg is not None and arg.type == "false":
            return True
        if arg is not None and arg.type == "number" and node_text(source, arg) == "0":
            return True
    return False


def _is_infinite_loop(stmt, source: str) -> bool:
    if stmt.type == "while_statement":
        return _is_forced_true(stmt.child_by_field_name("condition"), source)
    if stmt.type == "for_statement":
        cond = stmt.child_by_field_name("condition")
        if cond is None or cond.type == "empty_statement":
            return True
        return _is_forced_true(cond, source)
    return False


def _case_map(switch, source: str):
    body = switch.child_by_field_name("body")
    if body is None:
        return None
    if any(child.type == "switch_default" for child in body.named_children):
        return None
    cases = {}
    for child in body.named_children:
        if child.type != "switch_case":
            return None
        test = _const(child.child_by_field_name("value"), source)
        if test is None or not isinstance(test.py, str) or not _DIGIT_RE.fullmatch(test.py) or test.py in cases:
            return None
        statements = _field_children(child, "body")
        if statements and statements[-1].type == "continue_statement":
            statements = statements[:-1]
        cases[test.py] = statements
    return cases


def _flatten_loop(loop, seq_name: str, seq: str, iter_name: str, source: str) -> str | None:
    body = loop.child_by_field_name("body")
    stmts = _block_stmts(body)
    if len(stmts) != 2 or stmts[0].type != "switch_statement" or stmts[1].type != "break_statement":
        return None
    switch = stmts[0]
    disc = _unwrap(switch.child_by_field_name("value"))
    if disc is None or disc.type != "subscript_expression":
        return None
    obj = disc.child_by_field_name("object")
    index = disc.child_by_field_name("index")
    if obj is None or obj.type != "identifier" or node_text(source, obj) != seq_name:
        return None
    if index is None or index.type != "update_expression":
        return None
    arg = index.child_by_field_name("argument")
    if arg is None or arg.type != "identifier" or node_text(source, arg) != iter_name:
        return None
    if not any(not child.is_named and child.type == "++" for child in index.children):
        return None
    cases = _case_map(switch, source)
    if cases is None:
        return None
    parts = seq.split("|")
    if any(part not in cases for part in parts):
        return None
    lines = []
    for part in parts:
        for statement in cases[part]:
            lines.append(node_text(source, statement).strip())
    text = "\n".join(lines)
    return text + ("\n" if text else "")


def _flatten_switches(tree, source: str):
    reps = []
    for block in walk(tree.root_node):
        if block.type not in {"statement_block", "program"}:
            continue
        stmts = _block_stmts(block)
        for index in range(len(stmts) - 2):
            seq = _sequence_decl(stmts[index], source)
            iterator = _iterator_decl(stmts[index + 1], source)
            loop = stmts[index + 2]
            if seq is None or iterator is None or not _is_infinite_loop(loop, source):
                continue
            flat = _flatten_loop(loop, seq[0], seq[1], iterator, source)
            if flat is None:
                continue
            _start, end = stmt_span(source, loop)
            reps.append((stmts[index].start_byte, end, flat))
    if not reps:
        return None
    return reps, "Flattened control-flow switch"


def _binding_defined(tree, source: str, name: str) -> bool:
    return _name_counts(tree, source).get(name, 0) > 0


def _cleanup_replacements(tree, source: str):
    reps = []
    undefined_free = not _binding_defined(tree, source, "undefined")
    infinity_free = not _binding_defined(tree, source, "Infinity")
    for node in walk(tree.root_node):
        if node.type == "expression_statement" and node.named_children:
            expr = node.named_children[0]
            if expr.type == "sequence_expression":
                parts = list(expr.named_children)
                if len(parts) >= 2:
                    text = "\n".join(f"{node_text(source, part)};" for part in parts)
                    start, end = stmt_span(source, node)
                    reps.append((start, end, text + "\n"))
                    continue
        if node.type == "return_statement" and node.named_children:
            expr = _unwrap(node.named_children[0])
            if expr is not None and expr.type == "sequence_expression":
                parts = list(expr.named_children)
                if len(parts) >= 2:
                    head = "\n".join(f"{node_text(source, part)};" for part in parts[:-1])
                    text = f"{head}\nreturn {node_text(source, parts[-1])};"
                    start, end = stmt_span(source, node)
                    reps.append((start, end, text + "\n"))
                    continue
        if node.type == "sequence_expression":
            parts = list(node.named_children)
            if len(parts) >= 2 and all(_is_pure(part, source) for part in parts):
                reps.append((node.start_byte, node.end_byte, node_text(source, parts[-1])))
                continue
        if undefined_free and node.type == "unary_expression" and _unary_op(node) == "void":
            arg = node.named_children[0] if node.named_children else None
            if arg is not None and arg.type == "number" and node_text(source, arg) == "0":
                reps.append((node.start_byte, node.end_byte, "undefined"))
                continue
        if infinity_free and node.type == "binary_expression" and _binary_op(node) == "/":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if right is not None and right.type == "number" and node_text(source, right) == "0":
                if left is not None and left.type == "number" and node_text(source, left) == "1":
                    reps.append((node.start_byte, node.end_byte, "Infinity"))
                elif (
                    left is not None
                    and left.type == "unary_expression"
                    and _unary_op(left) == "-"
                    and left.named_children
                    and left.named_children[0].type == "number"
                    and node_text(source, left.named_children[0]) == "1"
                ):
                    reps.append((node.start_byte, node.end_byte, "-Infinity"))
        if node.type == "subscript_expression":
            obj = node.child_by_field_name("object")
            index = node.child_by_field_name("index")
            if obj is None or obj.type not in _SAFE_DOT_OBJECT or index is None or index.type != "string":
                continue
            val = _const(index, source)
            if val is None or not isinstance(val.py, str) or not _IDENT_RE.fullmatch(val.py) or val.py == "__proto__":
                continue
            reps.append((node.start_byte, node.end_byte, f"{node_text(source, obj)}.{val.py}"))
    if not reps:
        return None
    return reps, ""


def _function_name(node, source: str) -> str | None:
    if node.type == "function_declaration":
        name = node.child_by_field_name("name")
        if name is not None and name.type == "identifier":
            return node_text(source, name)
    return None


def _contains_debugger(node, source: str) -> bool:
    for item in walk(node):
        if item.type == "debugger_statement":
            return True
        if item.type == "string":
            val = _const(item, source)
            if val is not None and isinstance(val.py, str) and "debugger" in val.py:
                return True
    return False


def _timer_statement(ident, source: str):
    parent = ident.parent
    if parent is None or parent.type != "arguments":
        return None
    call = parent.parent
    if call is None or call.type != "call_expression":
        return None
    args = _call_args(call)
    if not args or not _same(args[0], ident):
        return None
    fn = call.child_by_field_name("function")
    called = None
    if fn is not None and fn.type == "identifier":
        called = node_text(source, fn)
    elif fn is not None and fn.type == "member_expression":
        prop = fn.child_by_field_name("property")
        if prop is not None and prop.type == "property_identifier":
            called = node_text(source, prop)
    if called not in {"setInterval", "setTimeout"}:
        return None
    return _stmt(call)


def _debug_protection(tree, source: str):
    reps = []
    counts = _name_counts(tree, source)
    for node in walk(tree.root_node):
        target = None
        name = None
        name_start = None
        if node.type == "function_declaration":
            target = node
            name = _function_name(node, source)
            ident = node.child_by_field_name("name")
            name_start = ident.start_byte if ident is not None else None
        elif node.type == "variable_declarator":
            value = _unwrap(node.child_by_field_name("value"))
            ident = node.child_by_field_name("name")
            if value is None or value.type != "function_expression" or ident is None:
                continue
            target = value
            name = node_text(source, ident)
            name_start = ident.start_byte
        else:
            continue
        if not name or name_start is None or counts.get(name, 0) != 1:
            continue
        if not _contains_debugger(target, source):
            continue
        body = target.child_by_field_name("body")
        if body is None or not any(item.type == "try_statement" for item in walk(body)):
            continue
        if not any(item.type == "update_expression" and any(child.type == "++" for child in item.children) for item in walk(body)):
            continue
        refs = _refs(tree, source, name, name_start)
        if not refs:
            continue
        timers = []
        ok = True
        for ref in refs:
            timer = _timer_statement(ref, source)
            if timer is None:
                ok = False
                break
            timers.append(timer)
        if not ok or not timers:
            continue
        stmt = node if node.type == "function_declaration" else _stmt(node)
        if stmt is None:
            continue
        start, end = stmt_span(source, stmt)
        reps.append((start, end, ""))
        for timer in timers:
            start, end = stmt_span(source, timer)
            reps.append((start, end, ""))
    if not reps:
        return None
    return reps, "Removed debug-protection stub"


def _is_empty_function(node) -> bool:
    node = _unwrap(node)
    if node is None or node.type not in {"function_expression", "function_declaration", "arrow_function"}:
        return False
    body = node.child_by_field_name("body")
    return body is not None and body.type == "statement_block" and not body.named_children


def _is_call_controller(node, source: str) -> bool:
    node = _unwrap(node)
    if node is None or node.type != "call_expression" or _call_args(node):
        return False
    fn = _unwrap(node.child_by_field_name("function"))
    if fn is None or fn.type != "function_expression":
        return False
    parsed = _params(fn, source)
    if parsed is None or parsed[0] or parsed[1] is not None:
        return False
    body = fn.child_by_field_name("body")
    if body is None:
        return False
    text = node_text(source, body)
    if "apply" not in text or "arguments" not in text:
        return False
    saw_false = saw_null = saw_true = saw_empty = saw_return_fn = False
    for item in walk(body):
        if item.type == "true":
            saw_true = True
        elif item.type == "false":
            parent = item.parent
            if parent is not None and parent.type == "assignment_expression" and _same(parent.child_by_field_name("right"), item):
                saw_false = True
        elif item.type == "null":
            parent = item.parent
            if parent is not None and parent.type == "assignment_expression" and _same(parent.child_by_field_name("right"), item):
                saw_null = True
        elif _is_empty_function(item):
            saw_empty = True
        elif item.type == "return_statement" and item.named_children:
            ret = _unwrap(item.named_children[0])
            if ret is not None and ret.type == "function_expression":
                saw_return_fn = True
    return saw_false and saw_null and saw_true and saw_empty and saw_return_fn


def _zero_arg_call_stmt(ident):
    parent = ident.parent
    if parent is None or parent.type != "call_expression":
        return None
    if _call_args(parent):
        return None
    if not _same(parent.child_by_field_name("function"), ident):
        return None
    return _stmt(parent)


def _self_defending(tree, source: str):
    reps = []
    counts = _name_counts(tree, source)
    for node in walk(tree.root_node):
        if node.type != "variable_declarator":
            continue
        value = node.child_by_field_name("value")
        ident = node.child_by_field_name("name")
        if ident is None or ident.type != "identifier" or not _is_call_controller(value, source):
            continue
        name = node_text(source, ident)
        if counts.get(name, 0) != 1:
            continue
        refs = _refs(tree, source, name, ident.start_byte)
        if not refs:
            continue
        remove = []
        ok = True
        for ref in refs:
            parent = ref.parent
            if parent is None or parent.type != "call_expression" or not _same(parent.child_by_field_name("function"), ref):
                ok = False
                break
            outer = parent.parent
            if outer is not None and outer.type == "call_expression" and _same(outer.child_by_field_name("function"), parent):
                stmt = _stmt(outer)
                if stmt is None:
                    ok = False
                    break
                remove.append(stmt)
                continue
            if outer is not None and outer.type == "variable_declarator" and _same(outer.child_by_field_name("value"), parent):
                alias = outer.child_by_field_name("name")
                if alias is None or alias.type != "identifier" or counts.get(node_text(source, alias), 0) != 1:
                    ok = False
                    break
                alias_refs = _refs(tree, source, node_text(source, alias), alias.start_byte)
                calls = []
                for alias_ref in alias_refs:
                    call_stmt = _zero_arg_call_stmt(alias_ref)
                    if call_stmt is None:
                        ok = False
                        break
                    calls.append(call_stmt)
                if not ok or not calls:
                    ok = False
                    break
                remove.extend(calls)
                stmt = _stmt(outer)
                if stmt is None:
                    ok = False
                    break
                remove.append(stmt)
                continue
            ok = False
            break
        if not ok:
            continue
        stmt = _stmt(node)
        if stmt is None:
            continue
        start, end = stmt_span(source, stmt)
        reps.append((start, end, ""))
        for item in remove:
            start, end = stmt_span(source, item)
            reps.append((start, end, ""))
    if not reps:
        return None
    return reps, "Removed self-defending wrapper"
