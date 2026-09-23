from __future__ import annotations

import sys
from pathlib import Path


def run_interactive(run_argv) -> int:
    """Menu when evilbox is started with no arguments. run_argv is cli._main."""
    print("Evilbox")
    print("  1) Deobfuscate a file")
    print("  2) Sandbox dump (PHP evalhook or JS Chromium: log, skip payloads)")
    print("  3) Sandbox observe (isolated Docker: PHP or headless Chromium)")
    print("  4) Batch a directory of .js / .php samples")
    print("  5) Open the web decoder (paste/upload in a browser)")
    print("  6) Quit")
    choice = _ask("Select", "1")
    if choice in {"6", "q", "quit"}:
        return 0
    if choice not in {"1", "2", "3", "4", "5"}:
        print("error: choose 1-6", file=sys.stderr)
        return 2

    if choice == "5":
        host = _ask("Bind address", "127.0.0.1")
        port = _ask("Port", "8080")
        open_browser = _ask("Open browser y/n", "y")
        argv = ["serve", "--host", host, "--port", port]
        if open_browser.lower() in {"y", "yes"}:
            argv.append("--open")
        return run_argv(argv)

    if choice == "4":
        folder = _ask_path("Directory of samples")
        if folder is None:
            return 2
        out = _ask("Output directory (blank = ./evilbox-out)", "")
        argv = [folder]
        if out:
            argv.extend(["-o", out])
        return run_argv(argv)

    sample = _ask_path("Sample file")
    if sample is None:
        return 2
    argv = [sample]
    if choice == "1":
        out = _ask("Write cleaned file to (blank = stdout)", "")
        if out:
            argv.extend(["-o", out])
        report = _ask("JSON report path (blank = skip / auto with -o)", "")
        if report:
            argv.extend(["--report", report])
        lang = _ask("Language auto/js/php", "auto")
        if lang in {"js", "php"}:
            argv.extend(["--lang", lang])
        return run_argv(argv)

    logs = _ask("Sandbox logs directory", "./sandbox-logs")
    timeout = _ask("Timeout seconds", "20")
    mode = "dump" if choice == "2" else "observe"
    argv.extend(["--sandbox", mode, "--logs-dir", logs, "--timeout", timeout])
    out = _ask("Write cleaned file to (blank = stdout)", "")
    if out:
        argv.extend(["-o", out])
    return run_argv(argv)


def _ask(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    line = input(f"{label}{suffix}: ").strip()
    return line if line else default


def _ask_path(label: str) -> str | None:
    raw = _ask(label, "")
    if not raw:
        print("error: a path is required", file=sys.stderr)
        return None
    return str(Path(raw).expanduser())
