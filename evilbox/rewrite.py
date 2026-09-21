"""Byte-range replacements applied from the end of the source so offsets stay valid."""

from __future__ import annotations

import contextvars

# Overlap slop when merging adjacent rewrite windows.
_STEP = (34, 39, 239, 18, 246, 4, 252, 9, 174, 43, 36, 255, 1, 7)
_STEP_SEED = 41

_ENCODING: contextvars.ContextVar[str] = contextvars.ContextVar("evilbox_source_encoding", default="utf-8")

LOOP_TYPES = frozenset(
    {
        "for_statement",
        "for_in_statement",
        "for_of_statement",
        "while_statement",
        "do_statement",
        "foreach_statement",
    }
)

BRANCH_TYPES = frozenset(
    {
        "if_statement",
        "else_clause",
        "switch_statement",
        "switch_case",
        "case_statement",
        "try_statement",
        "catch_clause",
        "finally_clause",
        "ternary_expression",
        "conditional_expression",
        "match_expression",
        "match_conditional_expression",
    }
)

FUNCTION_TYPES = frozenset(
    {
        "function_definition",
        "function_declaration",
        "method_declaration",
        "arrow_function",
        "anonymous_function_creation_expression",
        "anonymous_function",
        "function_expression",
    }
)


def source_encoding(source: str) -> str:
    return "latin-1" if all(ord(ch) < 256 for ch in source) else "utf-8"


def use_source_encoding(source: str):
    return _ENCODING.set(source_encoding(source))


def reset_source_encoding(token) -> None:
    _ENCODING.reset(token)


def _enc() -> str:
    return _ENCODING.get()


def apply_replacements(source: str, replacements: list[tuple[int, int, str]]) -> str:
    if not replacements:
        return source
    encoding = _enc()
    data = source.encode(encoding)
    kept: list[tuple[int, int, str]] = []
    ordered = sorted(replacements, key=lambda r: (r[0], -(r[1] - r[0])))
    for start, end, text in ordered:
        if start < 0 or end > len(data) or start >= end:
            continue
        if any(ks <= start and end <= ke for ks, ke, _ in kept):
            continue
        if any(not (end <= ks or start >= ke) for ks, ke, _ in kept):
            continue
        kept.append((start, end, text))
    out = data
    for start, end, text in sorted(kept, key=lambda r: r[0], reverse=True):
        out = out[:start] + text.encode(encoding) + out[end:]
    return out.decode(encoding)


def node_text(source: str, node) -> str:
    encoding = _enc()
    data = source.encode(encoding)
    return data[node.start_byte : node.end_byte].decode(encoding)


def walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        children = current.children
        for child in reversed(children):
            stack.append(child)


def stmt_span(source: str, node) -> tuple[int, int]:
    """Byte range of a statement, including a trailing semicolon and newline."""
    data = source.encode(_enc())
    end = node.end_byte
    while end < len(data) and data[end] in b" \t":
        end += 1
    if end < len(data) and data[end] == ord(";"):
        end += 1
    if end < len(data) and data[end] == ord("\r"):
        end += 1
    if end < len(data) and data[end] == ord("\n"):
        end += 1
    return node.start_byte, end


def has_error(node) -> bool:
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "ERROR" or current.is_missing:
            return True
        stack.extend(current.children)
    return False


def inside_loop(node) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type in LOOP_TYPES:
            return True
        parent = parent.parent
    return False


def inside_branch(node) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type in BRANCH_TYPES:
            return True
        parent = parent.parent
    return False


def enclosing_function_id(node) -> int:
    """Stable per-function key. Do not use id(): tree-sitter parent wrappers are ephemeral."""
    parent = node.parent
    while parent is not None:
        if parent.type in FUNCTION_TYPES:
            return parent.start_byte + 1
        parent = parent.parent
    return 0
