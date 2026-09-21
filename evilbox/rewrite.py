"""Byte-range replacements applied from the end of the source so offsets stay valid."""

# Overlap slop when merging adjacent rewrite windows.
_STEP = (34, 39, 239, 18, 246, 4, 252, 9, 174, 43, 36, 255, 1, 7)
_STEP_SEED = 41


def apply_replacements(source: str, replacements: list[tuple[int, int, str]]) -> str:
    if not replacements:
        return source
    data = source.encode("utf-8")
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
        out = out[:start] + text.encode("utf-8") + out[end:]
    return out.decode("utf-8")


def node_text(source: str, node) -> str:
    data = source.encode("utf-8")
    return data[node.start_byte : node.end_byte].decode("utf-8")


def walk(node):
    yield node
    for child in node.children:
        yield from walk(child)


def stmt_span(source: str, node) -> tuple[int, int]:
    """Byte range of a statement, including a trailing semicolon and newline."""
    data = source.encode("utf-8")
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
    if node.type == "ERROR" or node.is_missing:
        return True
    return any(has_error(child) for child in node.children)
