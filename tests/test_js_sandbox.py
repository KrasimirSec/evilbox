from pathlib import Path

from evilbox.sandbox import (
    docker_js_run_args,
    guess_js_host,
    js_sandbox_root,
)


def test_guess_js_host_prefers_sample_domain():
    src = 'fetch("https://pay.victim-shop.com/gate.js"); var cdn = "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js";'
    assert guess_js_host(src) == "pay.victim-shop.com"


def test_guess_js_host_explicit_overrides():
    assert guess_js_host("fetch('https://a.example')", "https://cdn.store.test/app.js") == "cdn.store.test"


def test_guess_js_host_fallback():
    assert guess_js_host("var x = 1;") == "www.shop-assets.net"


def test_js_wrap_looks_like_a_shop():
    import importlib.util

    path = js_sandbox_root() / "js" / "wrap.py"
    spec = importlib.util.spec_from_file_location("js_wrap", path)
    wrap = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(wrap)
    html = wrap.wrap_html(host="www.blue-harbor.test", script_src="/assets/app.min.js")
    low = html.lower()
    assert "<!doctype html>" in low
    assert 'src="/assets/app.min.js"' in html
    assert "blue" in low or "harbor" in low
    assert "sandbox" not in low
    assert "headless" not in low
    assert "webdriver" not in low
    assert "evilbox" not in low
    serp = wrap.google_serp_html(target_url="https://www.blue-harbor.test/", brand="Blue Harbor")
    assert 'id="result"' in serp
    assert "https://www.blue-harbor.test/" in serp


def test_js_hook_and_stealth_have_no_lab_strings():
    root = js_sandbox_root() / "js"
    stealth = (root / "stealth.js").read_text(encoding="utf-8").lower()
    hook = (root / "hook.js").read_text(encoding="utf-8").lower()
    blob = stealth + hook
    assert "evilbox" not in blob
    assert "sandbox" not in blob
    assert "headless" not in blob
    assert "webdriver" in stealth
    assert "sendbeacon" in hook
    assert "__mode__" in hook


def test_js_dockerfile_copies_chromium_and_php_sink():
    text = (js_sandbox_root() / "js" / "Dockerfile").read_text(encoding="utf-8")
    assert "chromium" in text.lower()
    assert "php/sink.py" in text
    assert "js/visit.py" in text
    assert "git clone" not in text


def test_docker_js_run_is_isolated(tmp_path):
    sample = tmp_path / "sample.js"
    sample.write_text("1", encoding="utf-8")
    args = docker_js_run_args(
        tag="evilbox-js-sandbox:test",
        sample=sample,
        mode="observe",
        timeout=20,
        container_name="evilbox-js-test",
        profile="google-referrer",
        host="www.blue-harbor.test",
    )
    assert args[args.index("--network") + 1] == "none"
    assert "--read-only" in args
    assert "--shm-size" in args
    assert "SANDBOX_HOST=www.blue-harbor.test" in args
    assert "SANDBOX_MODE=observe" in args
    assert "HOME=/tmp" in args
    joined = " ".join(args)
    assert "seccomp=unconfined" in joined
    assert "type=tmpfs,destination=/logs" in joined
    assert "SANDBOX_LOGS=" not in joined
    mount = next(item for item in args if item.startswith("type=bind,src="))
    src = mount.split("src=", 1)[1].split(",", 1)[0]
    assert Path(src).is_absolute()


def test_guess_js_host_skips_cdn_and_filenames():
    src = 'var u = "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js";'
    assert guess_js_host(src) == "www.shop-assets.net"


def test_js_image_build_is_allowed_online():
    from evilbox.sandbox import _build_is_offline, sandbox_context_dir

    js_df = js_sandbox_root() / "js" / "Dockerfile"
    assert _build_is_offline(js_df) is False
    php_df = sandbox_context_dir() / "Dockerfile"
    assert _build_is_offline(php_df) is True


def test_finalize_logs_reads_js_eval_and_cdp(tmp_path):
    from evilbox.sandbox import finalize_logs

    php_dir = tmp_path / "php"
    php_dir.mkdir()
    (php_dir / "eval-0001.js").write_text("eval('1')", encoding="utf-8")
    (tmp_path / "cdp-network.jsonl").write_text(
        '{"method": "Network.requestWillBeSent", "url": "https://c2.victim-shop.com/gate"}\n',
        encoding="utf-8",
    )
    domains, dumps = finalize_logs(tmp_path)
    assert "c2.victim-shop.com" in domains
    assert dumps[0].name == "eval-0001.js"


def test_visit_uses_google_click_through():
    text = (js_sandbox_root() / "js" / "visit.py").read_text(encoding="utf-8")
    assert "www.google.com/search" in text
    assert 'getElementById(\'result\')' in text or 'getElementById("result")' in text
    assert "HeadlessChrome" not in text
    assert "wordpress_logged_in_sandbox" not in text
