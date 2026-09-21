"""Run PHP codec snippets in a real interpreter when `php` is on PATH."""

from __future__ import annotations

import json
import shutil
import subprocess


def php_binary() -> str | None:
    return shutil.which("php")


def php_eval_json(expr: str, *, timeout: float = 5.0) -> object:
    """Evaluate a PHP expression. Strings come back as latin-1 via byte arrays."""
    binary = php_binary()
    if binary is None:
        raise FileNotFoundError("php is not installed")
    script = """<?php
$__v = (%s);
if (is_string($__v)) {
    $bytes = ($__v === '') ? array() : array_values(unpack('C*', $__v));
    echo json_encode(array('t' => 's', 'b' => $bytes));
} elseif (is_bool($__v) || $__v === null || is_int($__v) || is_float($__v)) {
    echo json_encode(array('t' => 'v', 'v' => $__v));
} else {
    echo json_encode(array('t' => 'v', 'v' => $__v));
}
""" % (expr,)
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
    payload = json.loads(proc.stdout)
    if payload.get("t") == "s":
        return bytes(payload.get("b") or []).decode("latin-1")
    return payload.get("v")
