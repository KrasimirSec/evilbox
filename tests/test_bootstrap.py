from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "bin" / "evilbox"


def test_launcher_upgrades_pip_before_editable_install():
    text = LAUNCHER.read_text(encoding="utf-8")
    upgrade_at = text.index("pip install -q --upgrade pip")
    editable_at = text.index("pip install -q -e")
    assert upgrade_at < editable_at
    assert '"$PY" -m pip' in text or "'$PY' -m pip" in text or '-m pip' in text
    assert "pip setuptools wheel" in text
    assert "pyproject.toml" in text
    assert "setup.py not found" in text


def test_launcher_retries_a_half_created_venv():
    text = LAUNCHER.read_text(encoding="utf-8")
    assert ".evilbox-ready" in text
    assert "finishing local environment" in text
    assert "creating local environment" in text


def test_project_is_pyproject_only():
    assert (ROOT / "pyproject.toml").is_file()
    assert not (ROOT / "setup.py").exists()
    assert LAUNCHER.is_file()
    assert LAUNCHER.stat().st_mode & 0o111


def test_launcher_requires_python_310():
    text = LAUNCHER.read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.10"' in pyproject
    assert "tree-sitter-javascript>=0.23" in pyproject
    assert "python3.12" in text
    assert "python3.11" in text
    assert "python3.10" in text
    assert "sys.version_info >= (3, 10)" in text
    assert "tree-sitter-javascript 0.23+" in text
    assert "rm -rf" in text
    assert "EVILBOX_PYTHON" in text
