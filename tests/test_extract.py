from evilbox.correlate import build_correlation, campaign_keys
from evilbox.extract import Indicators, extract_indicators, ingest_sandbox
from evilbox.pipeline import deobfuscate
from evilbox.report import build_report


def test_extract_url_domain_file_and_apis():
    src = '''
    var x = "http://strangerltd.top/777.exe";
    var y = new ActiveXObject("MSXML2.XMLHTTP");
    var z = "WScript.Shell";
    var c = "cmd.exe";
    '''
    iocs = extract_indicators(src)
    assert any("strangerltd.top/777.exe" in u for u in iocs.urls)
    assert "strangerltd.top" in iocs.domains
    assert "wscript.shell" not in iocs.domains
    assert "msxml2.xmlhttp" not in iocs.domains
    assert "777.exe" in iocs.files
    assert "cmd.exe" in iocs.files
    assert "ActiveXObject" in iocs.apis
    assert "MSXML2.XMLHTTP" in iocs.apis
    assert "WScript.Shell" in iocs.apis


def test_extract_skips_container_hostname():
    iocs = extract_indicators("var x = 1;", extra_domains=["ef76d2a6b8a9", "evil.example"])
    assert "ef76d2a6b8a9" not in iocs.domains
    assert "evil.example" in iocs.domains


def test_pipeline_attaches_indicators():
    src = 'var a = ["htt"]; var b = ["p://evil.example/a.exe"]; var x = a[0] + b[0];'
    result = deobfuscate(src, language="js")
    assert "evil.example" in result.indicators.domains
    assert any("evil.example" in u for u in result.indicators.urls)


def test_extract_campaign_pivots():
    xmr = "4A" + ("1" * 93)
    src = f'''
    $c2 = "hxxp://evil[.]example/gate.php?id=7";
    $ip = "203.0.113.10:4444";
    $v6 = "[2001:db8::53]";
    $onion = "facebookcorewwwi.onion";
    $mail = "drops@evil.example";
    $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    $btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    $eth = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0";
    $xmr = "{xmr}";
    $tg = "123456789:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    $hook = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";
    $aws = "AKIAIOSFODNN7EXAMPLE";
    $md5 = "d41d8cd98f00b204e9800998ecf8427e";
    $sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    $uuid = "550e8400-e29b-41d4-a716-446655440000";
    $cve = "CVE-2024-12345";
    $mutex = "Global\\\\EvilboxMutex";
    $pipe = "\\\\.\\pipe\\evilbox";
    $unix = "/tmp/evil.sh";
    $pdb = "C:\\\\build\\\\dropper.pdb";
    $pool = "stratum+tcp://pool.hashvault.pro:7777";
    $paste = "https://pastebin.com/raw/abc123";
    $xor_key = "deadbeefcafebabe";
    eval($_POST["cmd"]);
    setcookie("sid", "x");
    fsockopen("203.0.113.10", 4444);
    '''
    iocs = extract_indicators(src)
    assert any("evil.example/gate.php" in u for u in iocs.urls)
    assert "evil.example" in iocs.domains
    assert "203.0.113.10" in iocs.ipv4
    assert "203.0.113.10:4444" in iocs.ip_ports
    assert any(v.startswith("2001:db8") for v in iocs.ipv6)
    assert "facebookcorewwwi.onion" in iocs.onion
    assert "drops@evil.example" in iocs.emails
    assert "/gate.php" in iocs.url_paths
    assert "id" in iocs.query_keys
    assert "POST:cmd" in iocs.request_params
    assert any("Mozilla/5.0" in ua for ua in iocs.user_agents)
    assert any(w.startswith("btc:") for w in iocs.wallets)
    assert any(w.lower().startswith("eth:0x742d35") for w in iocs.wallets)
    assert any(w.startswith("xmr:") for w in iocs.wallets)
    assert any("123456789:" in t for t in iocs.telegram)
    assert any("discord.com/api/webhooks" in d for d in iocs.discord)
    assert any(s.startswith("aws:AKIA") for s in iocs.secrets)
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs.md5
    assert any(h.startswith("e3b0c44298fc1c14") for h in iocs.sha256)
    assert "550e8400-e29b-41d4-a716-446655440000" in iocs.uuids
    assert "CVE-2024-12345" in iocs.cves
    assert any("EvilboxMutex" in m for m in iocs.mutexes)
    assert any("pipe" in p.lower() for p in iocs.named_pipes)
    assert "/tmp/evil.sh" in iocs.unix_paths
    assert any(p.lower().endswith(".pdb") for p in iocs.pdb_paths)
    assert any("stratum+tcp://" in s for s in iocs.stratum)
    assert any("pastebin.com" in u for u in iocs.paste_urls)
    assert "sid" in iocs.cookies
    assert "deadbeefcafebabe" in iocs.crypto_keys
    assert "127.0.0.1" not in iocs.ipv4


def test_ingest_sandbox_http_tcp_and_merge():
    base = extract_indicators('<?php echo "ok"; $host = "static.example";')
    other = extract_indicators('<?php $u = "http://other.example/a";')
    merged = base.merge(other)
    assert "static.example" in merged.domains
    assert "other.example" in merged.domains
    http = [
        {
            "host": "cdn.evil.example:443",
            "path": "/gate.php?id=1",
            "method": "POST",
            "scheme": "https",
            "headers": {"User-Agent": "Mozilla/5.0 (compatible; sandbox)"},
            "body": "token=123456789:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        }
    ]
    tcp = [{"banner": "stratum+tcp://pool.evil.example:3333 extra"}]
    iocs = ingest_sandbox(
        merged,
        extra_domains=["cdn.evil.example", "ef76d2a6b8a9"],
        http=http,
        tcp=tcp,
    )
    assert "cdn.evil.example" in iocs.domains
    assert "ef76d2a6b8a9" not in iocs.domains
    assert "POST" in iocs.http_methods
    assert any("gate.php" in p for p in iocs.url_paths)
    assert any("Mozilla/5.0" in ua for ua in iocs.user_agents)
    assert any("stratum+tcp://pool.evil.example" in s for s in iocs.stratum)
    assert any("123456789:" in t for t in iocs.telegram)


def test_report_correlation_attack_and_campaign_keys():
    src = '<?php eval($_POST["x"]); $u = "http://c2.evil.example/gate.php"; $btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";'
    result = deobfuscate(src, language="php")
    report = build_report(result=result, path="shell.php")
    corr = report["correlation"]
    attack_ids = {row["id"] for row in corr["attack"]}
    assert "T1505.003" in attack_ids
    assert "T1059" in attack_ids
    keys = corr["campaign_keys"]
    assert any(k.startswith("domain:c2.evil.example") for k in keys)
    assert any(k.startswith("wallet:btc:") for k in keys)
    assert any(k.startswith("param:POST:x") for k in keys)
    assert corr["cluster"]["inner_sha256"] == result.inner_sha256
    assert campaign_keys(result.indicators)
    bundled = build_correlation(
        indicators=result.indicators.to_dict(),
        capabilities=report["capabilities"],
        roles=report["roles"],
        sample=report["sample"],
    )
    assert bundled["attack"]


def test_empty_indicators():
    iocs = extract_indicators("var x = 1 + 2;")
    assert isinstance(iocs, Indicators)
    assert "urls" in iocs.to_dict()
    assert "wallets" in iocs.to_dict()
    assert "mutexes" in iocs.to_dict()
