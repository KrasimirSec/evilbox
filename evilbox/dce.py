"""Dead-code and filler elimination via data-flow reachability to sinks.

Fake WordPress plugins often bury a small malicious core under large amounts of
unused helper functions and assignments. Anything that never reaches a
side-effecting sink (or a call from the top-level / entry path) is dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from evilbox.behavior import JS_SINKS, PHP_DECODERS, PHP_SINKS, JS_DECODERS
from evilbox.parsers import parse_js, parse_php
from evilbox.rewrite import (
    apply_replacements,
    has_error,
    node_text,
    reset_source_encoding,
    stmt_span,
    use_source_encoding,
    walk,
)

PHP_KEEP_VARS = frozenset(
    {
        "this",
        "GLOBALS",
        "_GET",
        "_POST",
        "_REQUEST",
        "_COOKIE",
        "_SERVER",
        "_FILES",
        "_ENV",
        "_SESSION",
    }
)

# Top-level calls that keep a function "live" even when they are not malware sinks.
PHP_ENTRY_KEEPERS = frozenset(
    {
        "add_action",
        "add_filter",
        "register_activation_hook",
        "register_deactivation_hook",
        "register_uninstall_hook",
        "spl_autoload_register",
        "register_shutdown_function",
        "ob_start",
        "set_error_handler",
        "set_exception_handler",
    }
)

JS_ENTRY_KEEPERS = frozenset(
    {
        "addeventlistener",
        "settimeout",
        "setinterval",
        "requestanimationframe",
    }
)


@dataclass
class DceResult:
    text: str
    removed_statements: int = 0
    removed_functions: int = 0
    bytes_before: int = 0
    bytes_after: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "removed_statements": self.removed_statements,
            "removed_functions": self.removed_functions,
            "bytes_before": self.bytes_before,
            "bytes_after": self.bytes_after,
            "bytes_removed": self.bytes_before - self.bytes_after,
            "warnings": list(self.warnings),
        }


def eliminate_dead_code(source: str, *, language: str) -> DceResult:
    """Remove statements and functions that never flow into a live sink/entry."""
    result = DceResult(text=source, bytes_before=len(source), bytes_after=len(source))
    if not source.strip():
        return result
    if language == "php":
        return _eliminate_php(source, result)
    return _eliminate_js(source, result)


def _eliminate_php(source: str, result: DceResult) -> DceResult:
    token = use_source_encoding(source)
    try:
        tree = parse_php(source)
        if has_error(tree.root_node):
            result.warnings.append("Skipped dead-code elimination: parse errors remain.")
            return result

        # Collect function definitions and which names they reference / call.
        functions: dict[str, object] = {}
        function_calls: dict[str, set[str]] = {}
        function_vars_read: dict[str, set[str]] = {}
        function_has_sink: dict[str, bool] = {}
        top_calls: set[str] = set()
        top_var_reads: set[str] = set()
        top_has_sink = False

        def enclosing_fn_name(node) -> str | None:
            parent = node.parent
            while parent is not None:
                if parent.type == "function_definition":
                    name_node = parent.child_by_field_name("name")
                    if name_node is None:
                        return None
                    return node_text(source, name_node)
                parent = parent.parent
            return None

        for node in walk(tree.root_node):
            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                if name_node is None:
                    continue
                name = node_text(source, name_node)
                functions[name] = node
                function_calls.setdefault(name, set())
                function_vars_read.setdefault(name, set())
                function_has_sink.setdefault(name, False)

        for node in walk(tree.root_node):
            fn = enclosing_fn_name(node)
            if node.type == "variable_name":
                raw = node_text(source, node)
                name = raw[1:] if raw.startswith("$") else raw
                if name in PHP_KEEP_VARS:
                    continue
                # Skip the left-hand side of a simple assignment.
                parent = node.parent
                if parent is not None and parent.type == "assignment_expression":
                    left = parent.child_by_field_name("left")
                    if left is not None and left.start_byte == node.start_byte:
                        continue
                if fn:
                    function_vars_read.setdefault(fn, set()).add(name)
                else:
                    top_var_reads.add(name)
                continue

            callee = None
            if node.type == "eval_expression":
                callee = "eval"
            elif node.type in {
                "include_expression",
                "include_once_expression",
                "require_expression",
                "require_once_expression",
            }:
                callee = node.type.replace("_expression", "").replace("_once", "_once")
            elif node.type == "function_call_expression":
                fn_node = node.child_by_field_name("function")
                if fn_node is not None and fn_node.type == "name":
                    callee = node_text(source, fn_node).lstrip("\\")

            if not callee:
                continue
            lowered = callee.lower()
            is_malware_sink = lowered in PHP_SINKS or lowered == "eval"
            is_decoder = lowered in PHP_DECODERS
            is_entry = lowered in PHP_ENTRY_KEEPERS
            if fn:
                function_calls.setdefault(fn, set()).add(callee)
                if is_malware_sink or is_decoder:
                    function_has_sink[fn] = True
            else:
                top_calls.add(callee)
                if is_malware_sink or is_decoder:
                    top_has_sink = True
                if is_entry:
                    top_calls.add(callee)

        # Live set: functions called from top-level or from other live functions,
        # plus any function that itself contains a malware sink.
        live: set[str] = set()
        queue = list(top_calls)
        for name, has_sink in function_has_sink.items():
            if has_sink:
                live.add(name)
                queue.append(name)
        # Keep WordPress / hook callbacks named as string literals.
        for match in re.finditer(
            r"""(?:add_action|add_filter|register_\w+_hook|add_options_page|add_menu_page|add_submenu_page)\s*\([^;]{0,200}?['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\)""",
            source,
            re.I,
        ):
            queue.append(match.group(1))
        for match in re.finditer(
            r"""(?:add_action|add_filter|register_\w+_hook)\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]""",
            source,
            re.I,
        ):
            queue.append(match.group(1))

        while queue:
            name = queue.pop()
            if name not in functions:
                continue
            if name not in live:
                live.add(name)
            for callee in function_calls.get(name, ()):
                if callee in functions and callee not in live:
                    live.add(callee)
                    queue.append(callee)

        # Only strip filler when a malware/decoder sink is present. Clean plugins
        # with add_action hooks stay intact.
        any_malware = top_has_sink or any(function_has_sink.values())
        if not any_malware:
            result.bytes_after = len(source)
            return result

        replacements: list[tuple[int, int, str]] = []
        removed_fns = 0
        for name, node in functions.items():
            if name in live:
                continue
            start, end = stmt_span(source, node)
            replacements.append((start, end, ""))
            removed_fns += 1

        # Drop top-level assignments to variables never read anywhere live.
        # Prefer long filler blobs (fake-plugin padding); keep short folded values
        # that an analyst may still want to see next to the shell.
        live_reads = set(top_var_reads)
        for name in live:
            live_reads |= function_vars_read.get(name, set())
        for name, node in functions.items():
            if name not in live:
                continue
            for child in walk(node):
                if child.type != "variable_name":
                    continue
                raw = node_text(source, child)
                vname = raw[1:] if raw.startswith("$") else raw
                if vname not in PHP_KEEP_VARS:
                    live_reads.add(vname)

        removed_stmts = 0
        for node in walk(tree.root_node):
            if node.type != "expression_statement":
                continue
            if enclosing_fn_name(node) is not None:
                continue
            expr = node.named_children[0] if node.named_children else None
            if expr is None or expr.type not in {"assignment_expression", "augmented_assignment_expression"}:
                continue
            left = expr.child_by_field_name("left")
            if left is None or left.type != "variable_name":
                continue
            raw = node_text(source, left)
            vname = raw[1:] if raw.startswith("$") else raw
            if vname in PHP_KEEP_VARS or vname in live_reads:
                continue
            rhs = expr.child_by_field_name("right")
            if rhs is not None and _php_has_side_effect(rhs, source):
                continue
            rhs_text = node_text(source, rhs) if rhs is not None else ""
            # Filler heuristic: long literal / array padding, or name looks decoy.
            is_filler = (
                len(rhs_text) >= 40
                or re.search(r"(?i)(?:unused|padding|filler|decoy|dummy|junk)", vname) is not None
            )
            if not is_filler:
                continue
            start, end = stmt_span(source, node)
            replacements.append((start, end, ""))
            removed_stmts += 1

        text = apply_replacements(source, replacements)
        text = re.sub(r"\n{3,}", "\n\n", text)
        result.text = text
        result.removed_functions = removed_fns
        result.removed_statements = removed_stmts
        result.bytes_after = len(text)
        if removed_fns or removed_stmts:
            result.warnings.append(
                f"Dead-code pass removed {removed_fns} unused function(s) "
                f"and {removed_stmts} unread assignment(s)."
            )
        return result
    finally:
        reset_source_encoding(token)


def _php_has_side_effect(node, source: str) -> bool:
    for child in walk(node):
        if child.type == "eval_expression":
            return True
        if child.type in {
            "include_expression",
            "include_once_expression",
            "require_expression",
            "require_once_expression",
        }:
            return True
        if child.type == "function_call_expression":
            fn = child.child_by_field_name("function")
            if fn is not None and fn.type == "name":
                name = node_text(source, fn).lstrip("\\").lower()
                if name in PHP_SINKS or name in PHP_DECODERS or name in PHP_ENTRY_KEEPERS:
                    return True
            else:
                return True
    return False


def _eliminate_js(source: str, result: DceResult) -> DceResult:
    token = use_source_encoding(source)
    try:
        tree = parse_js(source)
        if has_error(tree.root_node):
            result.warnings.append("Skipped dead-code elimination: parse errors remain.")
            return result

        functions: dict[str, object] = {}
        function_calls: dict[str, set[str]] = {}
        function_has_sink: dict[str, bool] = {}
        top_calls: set[str] = set()

        def enclosing_fn(node) -> str | None:
            parent = node.parent
            while parent is not None:
                if parent.type == "function_declaration":
                    name_node = parent.child_by_field_name("name")
                    return node_text(source, name_node) if name_node is not None else None
                if parent.type == "variable_declarator":
                    value = parent.child_by_field_name("value")
                    name_node = parent.child_by_field_name("name")
                    if (
                        value is not None
                        and value.type in {"function_expression", "arrow_function"}
                        and name_node is not None
                        and name_node.type == "identifier"
                    ):
                        # Only if node is inside that value.
                        cur = node
                        while cur is not None:
                            if cur.start_byte == value.start_byte and cur.type == value.type:
                                return node_text(source, name_node)
                            cur = cur.parent
                parent = parent.parent
            return None

        for node in walk(tree.root_node):
            if node.type == "function_declaration":
                name_node = node.child_by_field_name("name")
                if name_node is None:
                    continue
                name = node_text(source, name_node)
                functions[name] = node
                function_calls.setdefault(name, set())
                function_has_sink.setdefault(name, False)

        for node in walk(tree.root_node):
            if node.type not in {"call_expression", "new_expression"}:
                continue
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                continue
            callee = node_text(source, fn_node).strip("\"'")
            simple = callee.split(".")[-1].lower()
            owner = enclosing_fn(node)
            is_sink = simple in JS_SINKS or simple in JS_DECODERS or simple in JS_ENTRY_KEEPERS
            if owner:
                function_calls.setdefault(owner, set()).add(callee.split(".")[-1])
                if is_sink:
                    function_has_sink[owner] = True
            else:
                top_calls.add(callee.split(".")[-1])

        live: set[str] = set()
        queue = list(top_calls)
        for name, has_sink in function_has_sink.items():
            if has_sink:
                live.add(name)
                queue.append(name)
        while queue:
            name = queue.pop()
            if name not in functions:
                continue
            if name not in live:
                live.add(name)
            for callee in function_calls.get(name, ()):
                if callee in functions and callee not in live:
                    live.add(callee)
                    queue.append(callee)

        if not live and not any(function_has_sink.values()):
            return result

        replacements: list[tuple[int, int, str]] = []
        removed_fns = 0
        for name, node in functions.items():
            if name in live:
                continue
            start, end = stmt_span(source, node)
            replacements.append((start, end, ""))
            removed_fns += 1

        text = apply_replacements(source, replacements)
        text = re.sub(r"\n{3,}", "\n\n", text)
        result.text = text
        result.removed_functions = removed_fns
        result.bytes_after = len(text)
        if removed_fns:
            result.warnings.append(f"Dead-code pass removed {removed_fns} unused function(s).")
        return result
    finally:
        reset_source_encoding(token)
