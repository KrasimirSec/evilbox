from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from evilbox.pipeline import deobfuscate

IMAGE_NAME = "evilbox-php-sandbox"
QUERY_RE = re.compile(r"query\[[^\]]+\]\s+(\S+)", re.I)
PHP_IMAGES = {
    "8.3": IMAGE_NAME,
    "8.0": IMAGE_NAME,
    "7.4": IMAGE_NAME + "-7.4",
    "5.6": IMAGE_NAME + "-5.6",
}
SANDBOX_PROFILES = ("default", "googlebot", "google-referrer", "wp-cookie")


class SandboxError(RuntimeError):
    pass


def sandbox_context_dir() -> Path:
    start = Path(__file__).resolve().parent
    for base in [start, *start.parents]:
        candidate = base / "sandbox" / "php" / "Dockerfile"
        if candidate.is_file():
            return candidate.parent
    raise SandboxError("Could not find sandbox/php/Dockerfile (run from the Evilbox repo).")


@dataclass
class SandboxResult:
    log_dir: Path
    domains: list[str]
    eval_dumps: list[Path]
    deobfuscated: str
    docker_status: int
    image_tag: str
    http: list[dict]
    analysis: object | None = None


def _run(cmd: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout)


def build_image(context: Path, tag: str, *, dockerfile: Path | None = None) -> None:
    cmd = ["docker", "build", "-t", tag]
    if dockerfile is not None:
        cmd.extend(["-f", str(dockerfile)])
    cmd.append(str(context))
    proc = _run(cmd, timeout=600)
    if proc.returncode != 0:
        raise SandboxError(
            "docker build failed:\n" + (proc.stderr or proc.stdout or "no output")
        )


def sandbox_dockerfile(php_version: str = "8.3") -> Path:
    context = sandbox_context_dir()
    major = php_version.split(".")[0]
    if php_version.startswith("5.6") or major == "5":
        candidate = context / "Dockerfile.5.6"
        if candidate.is_file():
            return candidate
    if php_version.startswith("7.4") or php_version.startswith("7."):
        candidate = context / "Dockerfile.7.4"
        if candidate.is_file():
            return candidate
    return context / "Dockerfile"


def docker_run_args(
    *,
    tag: str,
    sample: Path,
    log_dir: Path,
    mode: str,
    timeout: int,
    container_name: str,
    profile: str = "default",
    php_version: str = "8.3",
) -> list[str]:
    if profile not in SANDBOX_PROFILES:
        profile = "default"
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--network",
        "none",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--cpus",
        "1",
        "--pids-limit",
        "128",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--env",
        f"SANDBOX_MODE={mode}",
        "--env",
        f"SANDBOX_TIMEOUT={timeout}",
        "--env",
        "SANDBOX_LOGS=/logs",
        "--env",
        f"SANDBOX_PROFILE={profile}",
        "--env",
        f"SANDBOX_PHP_VERSION={php_version}",
        "--mount",
        f"type=bind,src={sample},dst=/samples/sample.php,readonly=true",
        "--mount",
        f"type=bind,src={log_dir},dst=/logs",
        "--mount",
        "type=tmpfs,destination=/tmp",
        tag,
        "/samples/sample.php",
    ]


def finalize_logs(log_dir: Path) -> tuple[list[str], list[Path]]:
    domains: set[str] = set()
    domains_file = log_dir / "domains.txt"
    if domains_file.exists():
        domains.update(
            line.strip().lower()
            for line in domains_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        )
    dns_log = log_dir / "dns.log"
    if dns_log.exists():
        for line in dns_log.read_text(encoding="utf-8", errors="replace").splitlines():
            match = QUERY_RE.search(line)
            if match:
                host = match.group(1).rstrip(".").lower()
                if host and host not in {".", "localhost"}:
                    domains.add(host)
    http_jsonl = log_dir / "http.jsonl"
    if http_jsonl.exists():
        for line in http_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = str(rec.get("host") or "").split(":")[0].lower()
            if host:
                domains.add(host)
    dumps = sorted(log_dir.glob("eval-*.php"))
    summary = {
        "domains": sorted(domains),
        "eval_dumps": [p.name for p in dumps],
    }
    (log_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    domains_file.write_text("".join(d + "\n" for d in sorted(domains)), encoding="utf-8")
    return sorted(domains), dumps


def collect_http(log_dir: Path) -> list[dict]:
    http_jsonl = log_dir / "http.jsonl"
    if not http_jsonl.exists():
        return []
    rows: list[dict] = []
    for line in http_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows.append(
            {
                "host": rec.get("host"),
                "path": rec.get("path") or rec.get("url"),
                "method": rec.get("method"),
            }
        )
    return rows


def _best_source(sample: Path, dumps: list[Path]) -> str:
    if dumps:
        return dumps[-1].read_text(encoding="utf-8", errors="replace")
    return sample.read_text(encoding="utf-8", errors="replace")


def run_php_sandbox(
    sample: Path,
    *,
    mode: str,
    logs_root: Path,
    timeout: int = 15,
    php_version: str = "8.3",
    profile: str = "default",
) -> SandboxResult:
    if shutil.which("docker") is None:
        raise SandboxError("docker is not installed or not on PATH.")
    if mode not in {"dump", "observe"}:
        raise SandboxError("mode must be dump or observe")

    sample = sample.resolve()
    if not sample.is_file():
        raise SandboxError(f"sample not found: {sample}")

    context = sandbox_context_dir()
    dockerfile = sandbox_dockerfile(php_version)
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    tag = f"{IMAGE_NAME}:{run_id}"
    container_name = f"evilbox-{run_id}"
    log_dir = (logs_root / run_id).resolve()
    log_dir.mkdir(parents=True, exist_ok=True)

    build_image(context, tag, dockerfile=dockerfile)
    args = docker_run_args(
        tag=tag,
        sample=sample,
        log_dir=log_dir,
        mode=mode,
        timeout=timeout,
        container_name=container_name,
        profile=profile,
        php_version=php_version,
    )
    host_timeout = timeout + 90
    proc: subprocess.CompletedProcess[str] | None = None
    timed_out = False
    try:
        proc = _run(args, timeout=host_timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _run(["docker", "rm", "-f", container_name], timeout=30)
    finally:
        rmi = _run(["docker", "rmi", "-f", tag], timeout=60)
        if rmi.returncode != 0:
            (log_dir / "docker.rmi.err").write_text(rmi.stderr or "", encoding="utf-8")

    if proc is not None:
        (log_dir / "docker.stdout.log").write_text(proc.stdout or "", encoding="utf-8")
        (log_dir / "docker.stderr.log").write_text(proc.stderr or "", encoding="utf-8")
        (log_dir / "docker.status").write_text(str(proc.returncode) + "\n", encoding="utf-8")
        status = proc.returncode
    else:
        (log_dir / "docker.status").write_text("timeout\n", encoding="utf-8")
        status = -1

    domains, dumps = finalize_logs(log_dir)
    original = sample.read_text(encoding="utf-8", errors="replace")
    source = _best_source(sample, dumps)
    static = deobfuscate(original, language="php", path=str(sample), php_version=php_version)
    cleaned = deobfuscate(source, language="php", path=str(sample), surface_text=original, php_version=php_version)
    from evilbox.pipeline import cross_check_layers

    cross = cross_check_layers(original_inner=static.text, dump_text=source, static_text=cleaned.text)
    if not cross["agree"]:
        cleaned.warnings.append("static inner disagrees with sandbox dump layer")
    cleaned.sandbox_cross_check = cross
    http = collect_http(log_dir)
    (log_dir / "deobfuscated.php").write_text(cleaned.text, encoding="utf-8")
    (log_dir / "cross-check.json").write_text(json.dumps(cross, indent=2) + "\n", encoding="utf-8")
    if timed_out:
        raise SandboxError(f"sandbox timed out after {host_timeout}s; logs kept at {log_dir}")
    return SandboxResult(
        log_dir=log_dir,
        domains=domains,
        eval_dumps=dumps,
        deobfuscated=cleaned.text,
        docker_status=status,
        image_tag=tag,
        http=http,
        analysis=cleaned,
    )


def default_logs_root() -> Path:
    env = os.environ.get("EVILBOX_LOGS") or os.environ.get("DEOBFUSCATOR_LOGS")
    if env:
        return Path(env)
    return Path.cwd() / "sandbox-logs"
