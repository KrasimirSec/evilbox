from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from evilbox.classify import cluster_groups
from evilbox.detect import PHP_EXTS, JS_EXTS, detect_language
from evilbox.extract import extract_indicators, format_indicators
from evilbox.interactive import run_interactive
from evilbox.pipeline import deobfuscate
from evilbox.report import build_report, dump_json, format_analysis, render_html
from evilbox.sandbox import SandboxError, default_logs_root, run_php_sandbox

SAMPLE_EXTS = JS_EXTS | PHP_EXTS


class CliError(Exception):
    """User-facing CLI failure; message is printed without a traceback."""


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except SandboxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
    except OSError as exc:
        print(f"error: {_os_message(exc)}", file=sys.stderr)
        return 2
    except Exception as exc:
        if os.environ.get("EVILBOX_DEBUG"):
            raise
        print(f"error: unexpected failure ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 2


def _os_message(exc: OSError, path: str | None = None) -> str:
    target = path or getattr(exc, "filename", None) or getattr(exc, "filename2", None)
    detail = exc.strerror or str(exc)
    if isinstance(exc, FileNotFoundError):
        return f"file not found: {target}" if target else "file not found"
    if isinstance(exc, PermissionError):
        return f"permission denied: {target}" if target else f"permission denied ({detail})"
    if isinstance(exc, IsADirectoryError):
        return f"expected a file, got a directory: {target}"
    if isinstance(exc, NotADirectoryError):
        return f"not a directory: {target}"
    if target:
        return f"cannot access {target}: {detail}"
    return detail


def _read_text(path: Path) -> str:
    if not path.exists():
        raise CliError(f"file not found: {path}")
    if path.is_dir():
        raise CliError(f"expected a file, got a directory: {path}")
    if not path.is_file():
        raise CliError(f"not a readable file: {path}")
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise CliError(_os_message(exc, str(path))) from exc


def _write_text(path: Path, text: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise CliError(_os_message(exc, str(path))) from exc


def _main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw:
        return run_interactive(_main)
    if raw and raw[0] == "serve":
        from evilbox.web import serve_main

        return serve_main(raw[1:])

    parser = argparse.ArgumentParser(
        prog="evilbox",
        description="Evilbox: deobfuscate JavaScript or PHP, classify capabilities/roles, and extract scanner-visible signatures from the original file.",
        epilog="evilbox serve [--host HOST] [--port PORT]  opens a local web UI for paste/upload decoding (static analysis only).",
    )
    parser.add_argument("input", nargs="?", help="Input file, directory of samples, or - for stdin")
    parser.add_argument("-o", "--output", help="Write cleaned source to this file (or directory in batch mode)")
    parser.add_argument(
        "--lang",
        choices=("auto", "js", "php"),
        default="auto",
        help="Language (default: auto-detect from path and contents)",
    )
    parser.add_argument("--max-passes", type=int, default=16, help="Maximum unwrap/fold iterations (default: 16)")
    parser.add_argument(
        "--php-version",
        default="8.3",
        help="PHP language version for folds and sandbox image (5.6, 7.4, 8.3; default: 8.3)",
    )
    parser.add_argument(
        "--sandbox-profile",
        choices=("default", "googlebot", "google-referrer", "wp-cookie"),
        default="default",
        help="Sandbox request profile (User-Agent / referrer / WordPress cookies)",
    )
    parser.add_argument(
        "--sandbox",
        choices=("dump", "observe"),
        help="Run the sample in an isolated Docker lab. PHP uses evalhook. JavaScript is deobfuscated statically (no PHP sandbox).",
    )
    parser.add_argument(
        "--logs-dir",
        help="Directory for sandbox logs (default: EVILBOX_LOGS or ./sandbox-logs)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Sandbox PHP timeout in seconds (default: 15)",
    )
    parser.add_argument("--report", help="Write JSON report to this path (directory in batch mode)")
    parser.add_argument("--html", help="Write HTML report to this path (directory in batch mode)")
    parser.add_argument("--who", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(raw)

    if args.who:
        from evilbox.hashutil import _who

        sys.stdout.write(_who() + "\n")
        return 0
    if not args.input:
        parser.error("the following arguments are required: input")

    if args.input != "-" and Path(args.input).is_dir():
        return _run_batch(args)

    path: str | None
    source: str
    if args.input == "-":
        source = sys.stdin.read()
        path = None
    else:
        path = args.input
        source = _read_text(Path(args.input))

    lang = detect_language(source, path=path, lang=args.lang)

    if args.sandbox:
        if lang == "js":
            print(
                "warning: --sandbox dump/observe uses the PHP evalhook lab; "
                "this file is JavaScript, so running static JS cleanup instead.",
                file=sys.stderr,
            )
            result = deobfuscate(source, language="js", path=path, max_passes=args.max_passes)
            return _emit(args, result, path)
        return _run_sandbox(args, source, path)

    result = deobfuscate(
        source, language=lang, path=path, max_passes=args.max_passes, php_version=args.php_version
    )
    return _emit(args, result, path)


def _run_batch(args) -> int:
    root = Path(args.input)
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SAMPLE_EXTS)
    if not files:
        raise CliError(f"no .js/.php samples in directory: {root}")
    out_dir = Path(args.output) if args.output else Path(args.report) if args.report else root / "evilbox-out"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CliError(_os_message(exc, str(out_dir))) from exc
    html_dir = Path(args.html) if args.html else None
    if html_dir:
        try:
            html_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CliError(_os_message(exc, str(html_dir))) from exc
    status = 0
    cluster_samples: list[tuple[str, str]] = []
    for sample in files:
        try:
            source = _read_text(sample)
        except CliError as exc:
            print(f"error: {exc}", file=sys.stderr)
            status = 2
            continue
        result = deobfuscate(
            source,
            language=args.lang,
            path=str(sample),
            max_passes=args.max_passes,
            php_version=getattr(args, "php_version", "8.3"),
        )
        cluster_samples.append((str(sample), result.text))
        dest = out_dir / (sample.stem + ".clean" + sample.suffix)
        report_path = out_dir / (sample.stem + ".report.json")
        html_path = (html_dir / (sample.stem + ".report.html")) if html_dir else None
        fake = argparse.Namespace(
            output=str(dest),
            report=str(report_path),
            html=str(html_path) if html_path else None,
        )
        code = _emit(fake, result, str(sample), stdout_code=False)
        if code:
            status = code
        print(f"{sample.name}: {', '.join(r.name for r in result.classification.roles) or 'unclassified'}", file=sys.stderr)
    clusters = cluster_groups(cluster_samples)
    _write_text(out_dir / "clusters.json", json.dumps(clusters, indent=2) + "\n")
    return status


def _run_sandbox(args, source: str, path: str | None) -> int:
    logs_root = Path(args.logs_dir) if args.logs_dir else default_logs_root()
    tmp_sample: Path | None = None
    if path is None or args.input == "-":
        try:
            logs_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CliError(_os_message(exc, str(logs_root))) from exc
        tmp_sample = logs_root / ".stdin-sample.php"
        _write_text(tmp_sample, source)
        sample = tmp_sample
    else:
        sample = Path(path)

    try:
        result = run_php_sandbox(
            sample,
            mode=args.sandbox,
            logs_root=logs_root,
            timeout=args.timeout,
            php_version=getattr(args, "php_version", "8.3"),
            profile=getattr(args, "sandbox_profile", "default"),
        )
    except SandboxError as exc:
        raise CliError(str(exc)) from exc
    finally:
        if tmp_sample is not None:
            tmp_sample.unlink(missing_ok=True)

    print(f"sandbox logs: {result.log_dir}", file=sys.stderr)
    analysis = result.analysis
    iocs = extract_indicators(result.deobfuscated, extra_domains=result.domains)
    sandbox_meta = {
        "log_dir": str(result.log_dir),
        "mode": args.sandbox,
        "domains": result.domains,
        "http": result.http,
        "eval_dumps": [p.name for p in result.eval_dumps],
        "docker_status": result.docker_status,
        "php_version": getattr(args, "php_version", "8.3"),
        "profile": getattr(args, "sandbox_profile", "default"),
        "cross_check": getattr(analysis, "sandbox_cross_check", None) if analysis is not None else None,
    }
    _write_text(result.log_dir / "indicators.json", json.dumps(iocs.to_dict(), indent=2) + "\n")
    if result.eval_dumps:
        print("eval dumps: " + ", ".join(p.name for p in result.eval_dumps), file=sys.stderr)
    if analysis is None:
        return _write_output(args.output, result.deobfuscated)
    analysis.indicators = iocs
    return _emit(args, analysis, str(sample), sandbox=sandbox_meta)


def _emit(args, result, path: str | None, sandbox=None, stdout_code: bool = True) -> int:
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    report = build_report(result=result, path=path, sandbox=sandbox)
    sys.stderr.write(format_indicators(result.indicators))
    sys.stderr.write(format_analysis(report))
    _write_iocs(args, result.indicators)
    report_path = getattr(args, "report", None)
    html_path = getattr(args, "html", None)
    output = getattr(args, "output", None)
    if not report_path and output:
        report_path = str(Path(output).with_name(Path(output).stem + ".report.json"))
    if report_path:
        _write_text(Path(report_path), dump_json(report))
    if html_path:
        _write_text(Path(html_path), render_html(report))
    if sandbox and sandbox.get("log_dir"):
        _write_text(Path(sandbox["log_dir"]) / "report.json", dump_json(report))
    if stdout_code:
        _write_output(output, result.text)
    elif output:
        _write_text(Path(output), result.text)
    if not result.parse_ok:
        print("error: parse failed after deobfuscation", file=sys.stderr)
        return 1
    if getattr(result, "failed_folds", False):
        print("error: unresolved decoder folds remain", file=sys.stderr)
        return 1
    return 0


def _write_iocs(args, iocs) -> None:
    output = getattr(args, "output", None)
    if output:
        out = Path(output)
        _write_text(out.with_name(out.stem + ".iocs.json"), json.dumps(iocs.to_dict(), indent=2) + "\n")


def _write_output(output: str | None, text: str) -> int:
    if output:
        _write_text(Path(output), text)
        return 0
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")
    return 0
