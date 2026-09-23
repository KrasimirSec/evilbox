from __future__ import annotations

from evilbox.rewrite import php_open_tag_length


def pretty_php(source: str) -> str:
    """Indent PHP using brace/semicolon rules, leaving string and comment contents alone."""
    out: list[str] = []
    i = 0
    indent = 0
    bol = True
    in_squote = False
    in_dquote = False
    in_backtick = False
    in_line_comment = False
    in_block_comment = False
    heredoc_end: str | None = None
    in_php = not (source.lstrip().startswith("<?") or "<?" in source[:200])

    def write_indent() -> None:
        nonlocal bol
        if bol:
            out.append("    " * max(indent, 0))
            bol = False

    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if heredoc_end:
            out.append(ch)
            if ch == "\n":
                bol = True
                line_end = source.find("\n", i + 1)
                line = source[i + 1 :] if line_end == -1 else source[i + 1 : line_end]
                if line.strip() == heredoc_end or line.strip() == heredoc_end + ";":
                    heredoc_end = None
            i += 1
            continue

        if in_line_comment:
            out.append(ch)
            if ch == "\n":
                in_line_comment = False
                bol = True
            i += 1
            continue

        if in_block_comment:
            out.append(ch)
            if ch == "*" and nxt == "/":
                out.append("/")
                i += 2
                in_block_comment = False
                continue
            if ch == "\n":
                bol = True
            i += 1
            continue

        if in_squote:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == "'":
                in_squote = False
            i += 1
            continue

        if in_dquote:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == '"':
                in_dquote = False
            i += 1
            continue

        if in_backtick:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == "`":
                in_backtick = False
            i += 1
            continue

        if not in_php:
            tag = php_open_tag_length(source, i)
            if tag is not None:
                out.append(source[i : i + tag])
                i += tag
                in_php = True
                bol = False
                continue
            out.append(ch)
            bol = ch == "\n"
            i += 1
            continue

        if source.startswith("?>", i):
            out.append("?>")
            i += 2
            in_php = False
            bol = False
            continue

        if ch == "/" and nxt == "/":
            write_indent()
            out.append("//")
            i += 2
            in_line_comment = True
            continue
        if ch == "#" and not in_dquote:
            write_indent()
            out.append("#")
            i += 1
            in_line_comment = True
            continue
        if ch == "/" and nxt == "*":
            write_indent()
            out.append("/*")
            i += 2
            in_block_comment = True
            continue
        if source.startswith("<<<", i):
            write_indent()
            j = i + 3
            quote = ""
            if j < len(source) and source[j] in "'\"":
                quote = source[j]
                j += 1
            k = j
            while k < len(source) and (source[k].isalnum() or source[k] == "_"):
                k += 1
            heredoc_end = source[j:k]
            out.append(source[i:k])
            i = k
            if quote and i < len(source) and source[i] == quote:
                out.append(source[i])
                i += 1
            continue

        if ch in " \t" and bol:
            i += 1
            continue

        if ch == "\n":
            if out and out[-1] != "\n":
                out.append("\n")
            bol = True
            i += 1
            continue

        if ch == "{":
            write_indent()
            out.append("{")
            out.append("\n")
            indent += 1
            bol = True
            i += 1
            continue

        if ch == "}":
            indent -= 1
            if not bol and out and out[-1] != "\n":
                out.append("\n")
            bol = True
            write_indent()
            out.append("}")
            i += 1
            if i < len(source) and source[i] == ";":
                out.append(";")
                i += 1
            out.append("\n")
            bol = True
            continue

        if ch == ";":
            write_indent()
            out.append(";")
            out.append("\n")
            bol = True
            i += 1
            continue

        if ch == "'":
            write_indent()
            out.append(ch)
            in_squote = True
            i += 1
            continue
        if ch == '"':
            write_indent()
            out.append(ch)
            in_dquote = True
            i += 1
            continue
        if ch == "`":
            write_indent()
            out.append(ch)
            in_backtick = True
            i += 1
            continue

        write_indent()
        out.append(ch)
        i += 1

    text = "".join(out)
    lines = [line.rstrip() for line in text.splitlines()]
    cleaned: list[str] = []
    for line in lines:
        if line == "" and cleaned and cleaned[-1] == "":
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip() + "\n"
