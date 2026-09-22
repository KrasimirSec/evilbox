from pathlib import Path

from evilbox.sandbox import sandbox_context_dir


def test_sink_init_ca_with_openssl(tmp_path):
    import importlib.util

    source = sandbox_context_dir() / "sink.py"
    spec = importlib.util.spec_from_file_location("evilbox_sink", source)
    assert spec and spec.loader
    sink = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sink)
    ca_dir = tmp_path / "ca"
    sink.init_ca(ca_dir)
    assert (ca_dir / "ca.crt").is_file()
    assert (ca_dir / "ca.key").is_file()
    crt = (ca_dir / "ca.crt").read_text(encoding="utf-8")
    assert "BEGIN CERTIFICATE" in crt


def test_sink_does_not_import_cryptography():
    text = Path(sandbox_context_dir() / "sink.py").read_text(encoding="utf-8")
    assert "from cryptography" not in text
    assert "import cryptography" not in text
