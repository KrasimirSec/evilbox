"""Run PHP codec snippets in a real interpreter when `php` is on PATH."""

from __future__ import annotations

import json
import shutil
import subprocess


def php_binary() -> str | None:
    return shutil.which("php")


def php_eval_json(expr: str, *, timeout: float = 5.0) -> object:
    """Evaluate a PHP expression and decode `json_encode` of the result."""
    binary = php_binary()
    if binary is None:
        raise FileNotFoundError("php is not installed")
    script = "<?php echo json_encode(" + expr + ");"
    proc = subprocess.run(
        [binary, "-d", "display_errors=0", "-d", "log_errors=0"],
        input=script,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or "php failed")
    if not proc.stdout:
        raise RuntimeError(proc.stderr or "php produced no output")
    return json.loads(proc.stdout)
