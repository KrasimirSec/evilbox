from pathlib import Path

from evilbox.sandbox import docker_run_args, finalize_logs, sandbox_context_dir


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
    assert (context / "vendor" / "php-eval-hook" / "evalhook.c").is_file()
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
    assert "--rm" in args
    assert "--cap-drop" in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert "--pids-limit" in args
    assert "--memory" in args
    joined = " ".join(args)
    assert "readonly=true" in joined
    assert "SANDBOX_MODE=observe" in joined
    assert "no-new-privileges" in joined
    assert "seccomp=unconfined" not in joined


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
