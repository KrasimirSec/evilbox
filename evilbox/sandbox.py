from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from evilbox.pipeline import deobfuscate

IMAGE_NAME = "evilbox-php-sandbox"
DOCKER_INFO_TIMEOUT = 10
DOCKER_BUILD_TIMEOUT = 600
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
    tcp: list[dict] | None = None


def _status(message: str) -> None:
    print(f"evilbox: {message}", file=sys.stderr, flush=True)


def _run(cmd: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout)


def _run_logged(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    """Run a command, echoing its output live so long jobs are not silent."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    chunks: list[str] = []

    def _pump() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            chunks.append(line)
            sys.stderr.write(line)
            sys.stderr.flush()

    reader = threading.Thread(target=_pump, daemon=True)
    reader.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pass
        reader.join(timeout=5)
        raise subprocess.TimeoutExpired(cmd, timeout, output="".join(chunks)) from exc
    reader.join(timeout=5)
    return subprocess.CompletedProcess(cmd, proc.returncode or 0, stdout="".join(chunks), stderr="")


def ensure_docker(*, timeout: int = DOCKER_INFO_TIMEOUT) -> None:
    if shutil.which("docker") is None:
        raise SandboxError(
            "docker is not installed or not on PATH. "
            "The PHP sandbox needs a running Docker daemon. "
            "Omit --sandbox to decode statically without executing the sample."
        )
    try:
        proc = _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(
            f"docker did not respond within {timeout}s (is the daemon starting?). "
            "Start Docker Desktop / dockerd and retry, or omit --sandbox for static decode."
        ) from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "daemon not reachable").strip().splitlines()
        hint = detail[-1] if detail else "daemon not reachable"
        raise SandboxError(
            f"docker is installed but the daemon is not running ({hint}). "
            "Start Docker and retry, or omit --sandbox for static decode."
        )


def context_digest(context: Path, dockerfile: Path) -> str:
    hasher = hashlib.sha256()
    hasher.update(dockerfile.name.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(dockerfile.read_bytes())
    for path in sorted(context.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix == ".pyc" or path.name in {".DS_Store", "Thumbs.db"}:
            continue
        rel = path.relative_to(context).as_posix().encode("utf-8")
        hasher.update(rel)
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()[:16]


def cached_image_tag(context: Path, dockerfile: Path, php_version: str) -> str:
    ver = re.sub(r"[^0-9.]+", "", php_version) or "php"
    return f"{IMAGE_NAME}:{ver}-{context_digest(context, dockerfile)}"


def docker_image_exists(tag: str) -> bool:
    proc = _run(["docker", "image", "inspect", "--format", "{{.Id}}", tag], timeout=DOCKER_INFO_TIMEOUT)
    return proc.returncode == 0


def prepare_sandbox_image(php_version: str) -> tuple[Path, Path, str]:
    context = sandbox_context_dir()
    dockerfile = sandbox_dockerfile(php_version)
    tag = cached_image_tag(context, dockerfile, php_version)
    if docker_image_exists(tag):
        _status(f"using cached sandbox image {tag}")
        return context, dockerfile, tag
    _status(
        f"building sandbox image {tag} (PHP {php_version}; "
        "first run pulls the PHP base image and compiles evalhook — often several minutes)"
    )
    build_image(context, tag, dockerfile=dockerfile)
    return context, dockerfile, tag


def build_image(context: Path, tag: str, *, dockerfile: Path | None = None) -> None:
    cmd = ["docker", "build", "--progress=plain", "-t", tag]
    if dockerfile is not None:
        cmd.extend(["-f", str(dockerfile)])
    cmd.append(str(context))
    try:
        proc = _run_logged(cmd, timeout=DOCKER_BUILD_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(
            f"docker build timed out after {DOCKER_BUILD_TIMEOUT}s. "
            "Check network access to pull the PHP image, or omit --sandbox for static decode."
        ) from exc
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


def docker_has_runtime(name: str) -> bool:
    proc = _run(["docker", "info", "--format", "{{json .Runtimes}}"], timeout=DOCKER_INFO_TIMEOUT)
    if proc.returncode != 0:
        return False
    return name in (proc.stdout or "")


def docker_mount_root() -> Path:
    return Path.home() / ".cache" / "evilbox" / "docker-mounts"


def restricted_file_sharing() -> bool:
    """Docker Desktop (macOS) and snap Docker only share the home directory by default."""
    if sys.platform == "darwin":
        return True
    docker_bin = shutil.which("docker") or ""
    return "/snap/" in docker_bin


def docker_supports_memory_swap() -> bool:
    # Docker Desktop's Linux VM often rejects --memory-swap even when --memory works.
    return sys.platform != "darwin"


def stage_bind_source(src: Path, *, run_id: str, name: str) -> Path:
    src = src.resolve()
    if not restricted_file_sharing():
        return src
    dest_dir = docker_mount_root() / run_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / name
    shutil.copy2(src, dest)
    return dest


def cleanup_bind_stage(run_id: str) -> None:
    shutil.rmtree(docker_mount_root() / run_id, ignore_errors=True)


def docker_run_args(
    *,
    tag: str,
    sample: Path,
    log_dir: Path | None = None,
    mode: str,
    timeout: int,
    container_name: str,
    profile: str = "default",
    php_version: str = "8.3",
    keep_name: bool = False,
    stage_file: Path | None = None,
    gvisor: bool = False,
    memory_swap: bool | None = None,
) -> list[str]:
    del log_dir  # logs are copied out after the run; never bind-mounted
    if profile not in SANDBOX_PROFILES:
        profile = "default"
    if memory_swap is None:
        memory_swap = docker_supports_memory_swap()
    sample_name = sample.name if keep_name else "sample.php"
    if "/" in sample_name or sample_name in {".", ".."} or not sample_name:
        sample_name = "sample.php"
    dst = f"/samples/{sample_name}"
    sample_src = sample.resolve()
    args = [
        "docker",
        "run",
        "--name",
        container_name,
        "--network",
        "none",
        "--read-only",
        "--memory",
        "512m",
    ]
    if memory_swap:
        args.extend(["--memory-swap", "512m"])
    args.extend(
        [
        "--cpus",
        "1",
        "--pids-limit",
        "128",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_ADMIN",
        "--cap-add",
        "NET_RAW",
        "--cap-add",
        "NET_BIND_SERVICE",
        "--cap-add",
        "SETUID",
        "--cap-add",
        "SETGID",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "FOWNER",
        "--cap-add",
        "DAC_OVERRIDE",
        "--security-opt",
        "no-new-privileges",
        "--env",
        f"SANDBOX_MODE={mode}",
        "--env",
        f"SANDBOX_TIMEOUT={timeout}",
        "--env",
        f"SANDBOX_PROFILE={profile}",
        "--env",
        f"SANDBOX_PHP_VERSION={php_version}",
        "--env",
        f"SANDBOX_SAMPLE={dst}",
        "--mount",
        f"type=bind,src={sample_src},dst={dst},readonly=true",
        "--mount",
        "type=tmpfs,destination=/logs,tmpfs-mode=1777",
        "--mount",
        "type=tmpfs,destination=/tmp,tmpfs-mode=1777",
        "--mount",
        "type=tmpfs,destination=/run,tmpfs-mode=1777",
        ]
    )
    if stage_file is not None:
        args.extend(
            [
                "--mount",
                f"type=bind,src={stage_file.resolve()},dst=/opt/sandbox/stage.bin,readonly=true",
            ]
        )
    if gvisor:
        args[2:2] = ["--runtime", "runsc"]
    args.extend([tag, dst])
    return args


def _is_safe_regular_file(path: Path, root: Path) -> bool:
    try:
        if path.is_symlink() or not path.is_file():
            return False
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _reject_symlinks(root: Path) -> None:
    if not root.exists():
        return
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            try:
                path.unlink()
            except OSError:
                pass


def _safe_read_text(path: Path, root: Path) -> str:
    if not _is_safe_regular_file(path, root):
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _safe_write_text(path: Path, text: str, root: Path) -> None:
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise SandboxError(f"refusing to write outside log dir: {path}") from exc
    if path.is_symlink() or path.parent.is_symlink():
        raise SandboxError(f"refusing to write through a symlink: {path}")
    path.write_text(text, encoding="utf-8")


def finalize_logs(log_dir: Path) -> tuple[list[str], list[Path]]:
    log_dir = log_dir.resolve()
    _reject_symlinks(log_dir)
    domains: set[str] = set()
    domains_file = log_dir / "domains.txt"
    if _is_safe_regular_file(domains_file, log_dir):
        domains.update(
            line.strip().lower()
            for line in _safe_read_text(domains_file, log_dir).splitlines()
            if line.strip()
        )
    dns_log = log_dir / "dns.log"
    if _is_safe_regular_file(dns_log, log_dir):
        for line in _safe_read_text(dns_log, log_dir).splitlines():
            match = QUERY_RE.search(line)
            if match:
                host = match.group(1).rstrip(".").lower()
                if host and host not in {".", "localhost"}:
                    domains.add(host)
    http_jsonl = log_dir / "http.jsonl"
    if _is_safe_regular_file(http_jsonl, log_dir):
        for line in _safe_read_text(http_jsonl, log_dir).splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = str(rec.get("host") or "").split(":")[0].lower()
            if host:
                domains.add(host)
    dumps = sorted(
        p
        for p in list(log_dir.glob("eval-*.php")) + list(log_dir.glob("php/eval-*.php"))
        if _is_safe_regular_file(p, log_dir)
    )
    summary = {
        "domains": sorted(domains),
        "eval_dumps": [p.name for p in dumps],
    }
    _safe_write_text(log_dir / "summary.json", json.dumps(summary, indent=2) + "\n", log_dir)
    if domains_file.exists() and domains_file.is_symlink():
        domains_file.unlink()
    _safe_write_text(domains_file, "".join(d + "\n" for d in sorted(domains)), log_dir)
    return sorted(domains), dumps


def collect_http(log_dir: Path) -> list[dict]:
    log_dir = log_dir.resolve()
    http_jsonl = log_dir / "http.jsonl"
    if not _is_safe_regular_file(http_jsonl, log_dir):
        return []
    rows: list[dict] = []
    for line in _safe_read_text(http_jsonl, log_dir).splitlines():
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
                "scheme": rec.get("scheme"),
                "headers": rec.get("headers") or {},
                "body": rec.get("body") or "",
            }
        )
    return rows


def collect_tcp(log_dir: Path) -> list[dict]:
    log_dir = log_dir.resolve()
    path = log_dir / "tcp.jsonl"
    if not _is_safe_regular_file(path, log_dir):
        return []
    rows: list[dict] = []
    for line in _safe_read_text(path, log_dir).splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _copy_container_logs(container_name: str, log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    proc = _run(["docker", "cp", f"{container_name}:/logs/.", str(log_dir)], timeout=60)
    if proc.returncode != 0:
        (log_dir / "docker.cp.err").write_text(proc.stderr or proc.stdout or "", encoding="utf-8")
    _reject_symlinks(log_dir)


def run_php_sandbox(
    sample: Path,
    *,
    mode: str,
    logs_root: Path,
    timeout: int = 15,
    php_version: str = "8.3",
    profile: str = "default",
    keep_name: bool = False,
    stage_file: Path | None = None,
) -> SandboxResult:
    if mode not in {"dump", "observe"}:
        raise SandboxError("mode must be dump or observe")
    ensure_docker()

    sample = sample.resolve()
    if not sample.is_file():
        raise SandboxError(f"sample not found: {sample}")
    if sample.is_symlink():
        raise SandboxError(f"refusing to run a symlinked sample: {sample}")
    if stage_file is not None:
        stage_file = stage_file.resolve()
        if not stage_file.is_file() or stage_file.is_symlink():
            raise SandboxError(f"stage file not found or is a symlink: {stage_file}")

    _status(f"preparing PHP {php_version} sandbox ({mode})")
    _context, _dockerfile, tag = prepare_sandbox_image(php_version)
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    container_name = f"evilbox-{run_id}"
    log_dir = (logs_root / run_id).resolve()
    log_dir.mkdir(parents=True, exist_ok=True)

    mount_name = sample.name if keep_name else "sample.php"
    if "/" in mount_name or mount_name in {".", ".."} or not mount_name:
        mount_name = "sample.php"
    mount_sample = stage_bind_source(sample, run_id=run_id, name=mount_name)
    mount_stage = (
        stage_bind_source(stage_file, run_id=run_id, name="stage.bin") if stage_file is not None else None
    )
    args = docker_run_args(
        tag=tag,
        sample=mount_sample,
        mode=mode,
        timeout=timeout,
        container_name=container_name,
        profile=profile,
        php_version=php_version,
        keep_name=True,
        stage_file=mount_stage,
        gvisor=docker_has_runtime("runsc"),
    )
    host_timeout = timeout + 90
    _status(
        f"running {sample.name} in an isolated container "
        f"(PHP limited to {timeout}s; host waits up to {host_timeout}s)"
    )
    proc: subprocess.CompletedProcess[str] | None = None
    timed_out = False
    try:
        try:
            proc = _run(args, timeout=host_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _status("container exceeded host timeout; killing it")
            _run(["docker", "kill", container_name], timeout=30)
        try:
            _status("copying /logs out of the container")
            _copy_container_logs(container_name, log_dir)
        finally:
            _run(["docker", "rm", "-f", container_name], timeout=30)
    finally:
        cleanup_bind_stage(run_id)

    if proc is not None:
        (log_dir / "docker.stdout.log").write_text(proc.stdout or "", encoding="utf-8")
        (log_dir / "docker.stderr.log").write_text(proc.stderr or "", encoding="utf-8")
        (log_dir / "docker.status").write_text(str(proc.returncode) + "\n", encoding="utf-8")
        status = proc.returncode
    else:
        (log_dir / "docker.status").write_text("timeout\n", encoding="utf-8")
        status = -1

    domains, dumps = finalize_logs(log_dir)
    original = sample.read_text(encoding="latin-1", errors="replace")
    extra_layers: list[tuple[str, str]] = []
    dump_texts: list[str] = []
    for index, dump in enumerate(dumps, start=1):
        text = _safe_read_text(dump, log_dir)
        dump_texts.append(text)
        extra_layers.append((f"eval-dump-{index}", text))
    source = dump_texts[-1] if dump_texts else original
    static = deobfuscate(original, language="php", path=str(sample), php_version=php_version)
    cleaned = deobfuscate(
        source,
        language="php",
        path=str(sample),
        surface_text=original,
        php_version=php_version,
        extra_layers=extra_layers[:-1] if extra_layers else None,
    )
    from evilbox.pipeline import cross_check_layers

    cross = cross_check_layers(original_inner=static.text, dump_text=source, static_text=cleaned.text)
    if not cross["agree"]:
        cleaned.warnings.append("static inner disagrees with sandbox dump layer")
    cleaned.sandbox_cross_check = cross
    http = collect_http(log_dir)
    tcp = collect_tcp(log_dir)
    out_php = log_dir / "deobfuscated.php"
    if out_php.is_symlink():
        out_php.unlink()
    _safe_write_text(out_php, cleaned.text, log_dir)
    _safe_write_text(log_dir / "cross-check.json", json.dumps(cross, indent=2) + "\n", log_dir)
    if timed_out:
        raise SandboxError(f"sandbox timed out after {host_timeout}s; logs kept at {log_dir}")
    _status(f"sandbox finished (docker status {status}); logs at {log_dir}")
    return SandboxResult(
        log_dir=log_dir,
        domains=domains,
        eval_dumps=dumps,
        deobfuscated=cleaned.text,
        docker_status=status,
        image_tag=tag,
        http=http,
        analysis=cleaned,
        tcp=tcp,
    )


def default_logs_root() -> Path:
    env = os.environ.get("EVILBOX_LOGS") or os.environ.get("DEOBFUSCATOR_LOGS")
    if env:
        return Path(env)
    return Path.cwd() / "sandbox-logs"
