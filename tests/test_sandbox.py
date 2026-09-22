import subprocess
import sys
from pathlib import Path

import pytest

from evilbox.sandbox import (
    SandboxError,
    build_image,
    cached_image_tag,
    cleanup_bind_stage,
    docker_run_args,
    docker_supports_memory_swap,
    ensure_docker,
    finalize_logs,
    prepare_sandbox_image,
    sandbox_context_dir,
    sandbox_dockerfile,
    stage_bind_source,
    _run_logged,
)


def test_sandbox_dockerfile_present():
    context = sandbox_context_dir()
    assert (context / "Dockerfile").is_file()
    assert (context / "entrypoint.sh").is_file()
    assert (context / "Dockerfile.7.4").is_file()
    assert (context / "Dockerfile.5.6").is_file()
    assert (context / "wp-stubs.php").is_file()
    assert (context / "sleep_hook.c").is_file()
    text = (context / "Dockerfile").read_text(encoding="utf-8")
    assert "git clone" not in text
    assert "vendor/php-eval-hook" in text
    assert "@sha256:" in text
    assert (context / "debian-archive.sh").is_file()
    archive_sh = (context / "debian-archive.sh").read_text(encoding="utf-8")
    assert "archive.debian.org/debian" in archive_sh
    assert "debian-security" not in archive_sh
    dockerfile_74 = (context / "Dockerfile.7.4").read_text(encoding="utf-8")
    assert "deb http://archive.debian.org/debian bullseye main" in dockerfile_74
    assert "deb http://archive.debian.org/debian-security" not in dockerfile_74
    assert "php:7.4-cli-bullseye" in dockerfile_74
    dockerfile_56 = (context / "Dockerfile.5.6").read_text(encoding="utf-8")
    assert "debian-archive.sh" in dockerfile_56
    assert (context / "vendor" / "php-eval-hook" / "evalhook.c").is_file()
    assert (context / "tcp_logger.py").is_file()
    entry = (context / "entrypoint.sh").read_text(encoding="utf-8")
    assert "ip route add local 0.0.0.0/0" in entry
    assert "setpriv" in entry
    prepend = (context / "prepend.php").read_text(encoding="utf-8")
    assert "getenv('SANDBOX_LOGS')" not in prepend
    assert "getenv('SANDBOX_MODE')" not in prepend
    commit = (context / "vendor" / "php-eval-hook.COMMIT").read_text(encoding="utf-8").splitlines()[-1].strip()
    assert commit == "25e4e2a9b84b4f4c45f3d2dfa35121ed7938b889"


def test_docker_run_is_isolated(tmp_path):
    sample = tmp_path / "sample.php"
    sample.write_text("<?php echo 1;", encoding="utf-8")
    logs = tmp_path / "logs"
    logs.mkdir()
    args = docker_run_args(
        tag="evilbox-php-sandbox:test",
        sample=sample,
        log_dir=logs,
        mode="observe",
        timeout=15,
        container_name="evilbox-test",
    )
    assert "--network" in args
    assert args[args.index("--network") + 1] == "none"
    assert "--rm" not in args
    assert "--read-only" in args
    assert "--cap-drop" in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert "--pids-limit" in args
    assert "--memory" in args
    joined = " ".join(args)
    assert "readonly=true" in joined
    assert "SANDBOX_MODE=observe" in joined
    assert "SANDBOX_LOGS=" not in joined
    assert "dst=/logs" not in joined
    assert "type=tmpfs,destination=/logs" in joined
    assert "no-new-privileges" in joined
    assert "seccomp=unconfined" not in joined
    assert "NET_ADMIN" in joined
    if docker_supports_memory_swap():
        assert "--memory-swap" in args
    else:
        assert "--memory-swap" not in args
    mount = next(item for item in args if item.startswith("type=bind,src="))
    src = mount.split("src=", 1)[1].split(",", 1)[0]
    assert Path(src).is_absolute()


def test_docker_run_omits_memory_swap_on_macos(tmp_path, monkeypatch):
    monkeypatch.setattr("evilbox.sandbox.sys.platform", "darwin")
    sample = tmp_path / "sample.php"
    sample.write_text("<?php echo 1;", encoding="utf-8")
    args = docker_run_args(
        tag="evilbox-php-sandbox:test",
        sample=sample,
        mode="observe",
        timeout=15,
        container_name="evilbox-test",
    )
    assert "--memory" in args
    assert "--memory-swap" not in args


def test_stage_bind_source_copies_under_home_on_macos(tmp_path, monkeypatch):
    share = tmp_path / "docker-mounts"
    monkeypatch.setattr("evilbox.sandbox.sys.platform", "darwin")
    monkeypatch.setattr("evilbox.sandbox.docker_mount_root", lambda: share)
    src = tmp_path / "outside" / "sample.php"
    src.parent.mkdir()
    src.write_text("<?php echo 1;", encoding="utf-8")
    dest = stage_bind_source(src, run_id="run1", name="sample.php")
    assert dest == share / "run1" / "sample.php"
    assert dest.read_text(encoding="utf-8") == "<?php echo 1;"
    cleanup_bind_stage("run1")
    assert not dest.exists()


def test_finalize_logs_collects_domains(tmp_path):
    (tmp_path / "dns.log").write_text("query[A] evil.example from 127.0.0.1\n", encoding="utf-8")
    (tmp_path / "http.jsonl").write_text(
        '{"host": "cdn.example:443", "path": "/a"}\n',
        encoding="utf-8",
    )
    (tmp_path / "eval-0001.php").write_text("echo 1;", encoding="utf-8")
    domains, dumps = finalize_logs(tmp_path)
    assert "evil.example" in domains
    assert "cdn.example" in domains
    assert dumps[0].name == "eval-0001.php"
    summary = (tmp_path / "summary.json").read_text(encoding="utf-8")
    assert "evil.example" in summary


def test_finalize_logs_rejects_symlinks(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("secret", encoding="utf-8")
    link = tmp_path / "domains.txt"
    link.symlink_to(victim)
    (tmp_path / "eval-0001.php").write_text("echo 1;", encoding="utf-8")
    domains, dumps = finalize_logs(tmp_path)
    assert dumps[0].name == "eval-0001.php"
    assert not link.is_symlink()
    assert victim.read_text(encoding="utf-8") == "secret"


def test_ensure_docker_missing(monkeypatch):
    monkeypatch.setattr("evilbox.sandbox.shutil.which", lambda _: None)
    with pytest.raises(SandboxError, match="docker is not installed"):
        ensure_docker()


def test_ensure_docker_daemon_down(monkeypatch):
    monkeypatch.setattr("evilbox.sandbox.shutil.which", lambda _: "/usr/bin/docker")

    def fake_run(cmd, *, timeout=None):
        return subprocess.CompletedProcess(
            cmd, 1, stdout="", stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
        )

    monkeypatch.setattr("evilbox.sandbox._run", fake_run)
    with pytest.raises(SandboxError, match="daemon is not running"):
        ensure_docker()


def test_ensure_docker_timeout(monkeypatch):
    monkeypatch.setattr("evilbox.sandbox.shutil.which", lambda _: "/usr/bin/docker")

    def hang(cmd, *, timeout=None):
        raise subprocess.TimeoutExpired(cmd, timeout or 10)

    monkeypatch.setattr("evilbox.sandbox._run", hang)
    with pytest.raises(SandboxError, match="did not respond"):
        ensure_docker()


def test_cached_image_tag_is_stable():
    context = sandbox_context_dir()
    dockerfile = sandbox_dockerfile("7.4")
    first = cached_image_tag(context, dockerfile, "7.4")
    second = cached_image_tag(context, dockerfile, "7.4")
    other = cached_image_tag(context, sandbox_dockerfile("8.3"), "8.3")
    assert first == second
    assert first.startswith("evilbox-php-sandbox:7.4-")
    assert other.startswith("evilbox-php-sandbox:8.3-")
    assert first != other


def test_prepare_sandbox_image_reuses_cache(monkeypatch):
    messages: list[str] = []
    monkeypatch.setattr("evilbox.sandbox.docker_image_exists", lambda _tag: True)
    monkeypatch.setattr(
        "evilbox.sandbox.build_image",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not rebuild")),
    )
    monkeypatch.setattr("evilbox.sandbox._status", messages.append)
    _context, _dockerfile, tag = prepare_sandbox_image("7.4")
    assert tag.startswith("evilbox-php-sandbox:7.4-")
    assert any("cached" in line for line in messages)


def test_prepare_sandbox_image_builds_when_missing(monkeypatch):
    built: list[str] = []
    monkeypatch.setattr("evilbox.sandbox.docker_image_exists", lambda _tag: False)
    monkeypatch.setattr(
        "evilbox.sandbox.build_image",
        lambda context, tag, dockerfile=None: built.append(tag),
    )
    monkeypatch.setattr("evilbox.sandbox._status", lambda _msg: None)
    _context, _dockerfile, tag = prepare_sandbox_image("7.4")
    assert built == [tag]


def test_build_image_uses_plain_progress(monkeypatch):
    seen: list[tuple[list[str], int]] = []

    def fake_logged(cmd, *, timeout):
        seen.append((cmd, timeout))
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr("evilbox.sandbox._run_logged", fake_logged)
    build_image(Path("/tmp"), "evilbox-php-sandbox:x", dockerfile=Path("/tmp/Dockerfile"))
    cmd, timeout = seen[0]
    assert cmd[:4] == ["docker", "build", "--progress=plain", "-t"]
    assert timeout == 600


def test_run_logged_streams_output(capsys):
    proc = _run_logged(
        [sys.executable, "-c", "import sys; print('hello-sandbox'); sys.stderr.write('from-err\\n')"],
        timeout=10,
    )
    assert proc.returncode == 0
    err = capsys.readouterr().err
    assert "hello-sandbox" in proc.stdout
    assert "hello-sandbox" in err
    assert "from-err" in err
