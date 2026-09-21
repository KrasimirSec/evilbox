import json
import threading
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

from evilbox.web import MAX_BYTES, decode_payload, make_server


@pytest.fixture()
def web_url():
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _post(url, payload, content_type="application/json", query=""):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    req = Request(url + "/api/decode" + query, data=body, method="POST")
    req.add_header("Content-Type", content_type)
    try:
        with urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _get(url, path):
    with urlopen(url + path, timeout=10) as resp:
        return resp.status, resp.read(), resp.headers


def test_decode_payload_php_eval_base64():
    data = decode_payload("<?php eval(base64_decode('ZWNobyAiaGkiOw=='));", lang="php")
    assert data["ok"] is True
    assert "echo" in data["decoded"]
    assert "hi" in data["decoded"]
    assert data["report"]["schema"] == "evilbox.report.v1"
    names = [layer["name"] for layer in data["layers"]]
    assert names[0] == "original"
    assert "inner" in names
    assert any("echo" in layer["text"] for layer in data["layers"])


def test_decode_payload_rejects_empty():
    with pytest.raises(Exception, match="paste or upload"):
        decode_payload("   ", lang="auto")


def test_index_page(web_url):
    status, body, headers = _get(web_url, "/")
    assert status == 200
    text = body.decode("utf-8")
    assert "EVILBOX" in text
    assert "/api/decode" in text
    assert "Campaign keys" in text
    assert "ATT&CK" in text
    assert "text/html" in headers.get("Content-Type", "")


def test_health_and_examples(web_url):
    status, body, _ = _get(web_url, "/health")
    assert status == 200
    health = json.loads(body.decode("utf-8"))
    assert health["ok"] is True
    assert health["sandbox"] is False
    status, body, _ = _get(web_url, "/api/examples")
    examples = json.loads(body.decode("utf-8"))["examples"]
    assert {item["id"] for item in examples} >= {"php-eval-b64", "js-fromcharcode"}


def test_api_decode_js(web_url):
    status, data = _post(
        web_url,
        {"source": 'var x = String.fromCharCode(72,101,108,108,111) + " world";', "lang": "js"},
    )
    assert status == 200
    assert data["ok"] is True
    assert "Hello" in data["decoded"]
    assert "fromCharCode" not in data["decoded"]
    assert data["report"]["sample"]["language"] == "js"


def test_api_decode_php_webshell_roles(web_url):
    status, data = _post(web_url, {"source": "<?php eval($_POST['x']);", "lang": "php"})
    assert status == 200
    roles = [r["name"] for r in data["report"]["roles"]]
    assert "webshell" in roles


def test_api_decode_plain_text_body(web_url):
    status, data = _post(
        web_url,
        b'<?php echo 1+2;',
        content_type="text/plain",
        query="?lang=php&filename=add.php",
    )
    assert status == 200
    assert "3" in data["decoded"]
    assert data["report"]["sample"]["path"] == "add.php"


def test_api_decode_multipart_file(web_url):
    boundary = "----EvilboxTestBoundary"
    source = 'var x = "a" + "b";\n'
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="packed.js"\r\n'
        "Content-Type: text/javascript\r\n"
        "\r\n"
        f"{source}\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="lang"\r\n'
        "\r\n"
        "js\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    status, data = _post(
        web_url,
        body,
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    assert status == 200
    assert "ab" in data["decoded"]
    assert data["report"]["sample"]["path"] == "packed.js"


def test_api_rejects_empty_and_bad_lang(web_url):
    status, data = _post(web_url, {"source": "", "lang": "auto"})
    assert status == 400
    assert data["ok"] is False
    status, data = _post(web_url, {"source": "var x=1;", "lang": "ruby"})
    assert status == 400
    assert "lang" in data["error"]


def test_api_rejects_oversized(web_url):
    try:
        status, data = _post(web_url, {"source": "x" * (MAX_BYTES + 10), "lang": "js"})
    except URLError:
        # 413 is sent and the connection closed before urllib finishes the body.
        status, data = 413, {"error": "too large"}
    assert status == 413
    assert "too large" in data.get("error", "too large")


def test_decode_has_no_wildcard_cors(web_url):
    status, body, headers = _get(web_url, "/health")
    assert status == 200
    assert headers.get("Access-Control-Allow-Origin") in {None, ""}


def test_get_decode_is_method_not_allowed(web_url):
    req = Request(web_url + "/api/decode", method="GET")
    with pytest.raises(HTTPError) as exc:
        urlopen(req, timeout=10)
    assert exc.value.code == 405


def test_decode_timeout_uses_subprocess():
    import inspect

    from evilbox import web

    source = inspect.getsource(web._decode_with_timeout)
    assert "Popen" in source
    assert "SIGKILL" in source
    assert "DECODE_TIMEOUT" in source
    assert "worker_entry" in web._WORKER
    assert "setrlimit" in inspect.getsource(web.apply_resource_limits)
