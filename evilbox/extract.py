"""Pull analyst-oriented indicators from deobfuscated (and original) source."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, fields
from urllib.parse import parse_qs, urlparse

# hxxp / http(s) / ftp, optional defanging
URL_RE = re.compile(
    r"(?i)\b((?:h(?:xx|tt)ps?|f(?:xx|t)p)://[^\s\"'<>\\]+)",
)
IPV4_RE = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2}))\b"
)
IP_PORT_RE = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2}):"
    r"(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]))\b"
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,24}\b", re.I)
WIN_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\(?:[^\\/:*?\"<>|\s]+\\)*[^\\/:*?\"<>|\s]+")
UNC_PATH_RE = re.compile(r"\\\\[A-Za-z0-9._$-]+\\[^\s\"']+")
REG_RE = re.compile(r"(?i)\b(?:HKEY_[A-Z_]+|HK[CLU][UM])\\[^\s\"']+")
HOST_IN_QUOTES_RE = re.compile(
    r"[\"']((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})[\"']"
)
FILENAME_RE = re.compile(
    r"(?i)\b([A-Za-z0-9._\-]+\.(?:exe|dll|scr|bat|cmd|com|ps1|vbs|vbe|js|jse|wsf|wsh|"
    r"hta|msi|jar|php|phtml|php5|phar|asp|aspx|jsp|war|sh|py|so|elf|apk|bin|dat))\b"
)
ONION_RE = re.compile(r"\b([a-z2-7]{16,56}\.onion)\b", re.I)
IPV6_BRACKET_RE = re.compile(r"\[([0-9a-fA-F:]+)\]")
QUOTED_IPV6_RE = re.compile(r"[\"']([0-9a-fA-F:]{4,})[\"']")
UNIX_PATH_RE = re.compile(
    r"[\"']((?:/etc|/tmp|/var|/root|/home|/opt|/usr/bin|/usr/sbin|/proc|/dev)/[^\s\"']{1,200})[\"']"
)
PHP_PARAM_RE = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[\s*['\"]([^'\"]{1,80})['\"]\s*\]"
)
QUERY_IN_URL_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-]{0,63})=")
FSOCK_RE = re.compile(
    r"(?:fsockopen|stream_socket_client|pfsockopen)\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\d{1,5})",
    re.I,
)
UA_RE = re.compile(
    r"[\"']((?:Mozilla|Opera|curl|Wget|python-requests|Go-http-client|PHP|okhttp)/[^\n\"']{3,180})[\"']"
)
TELEGRAM_BOT_RE = re.compile(r"\b(\d{8,12}:[A-Za-z0-9_-]{30,45})\b")
TELEGRAM_URL_RE = re.compile(
    r"(?i)https?://(?:api\.telegram\.org/bot[^\s\"']+|t(?:elegram)?\.me/[^\s\"']+)"
)
DISCORD_WEBHOOK_RE = re.compile(
    r"(?i)https://(?:(?:ptb\.|canary\.)?discord(?:app)?\.com)/api/webhooks/\d+/[A-Za-z0-9_-]+"
)
SLACK_WEBHOOK_RE = re.compile(r"(?i)https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+")
AWS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
GITHUB_TOKEN_RE = re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,})\b")
GOOGLE_API_RE = re.compile(r"\b(AIza[0-9A-Za-z\-_]{30,})\b")
SLACK_TOKEN_RE = re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")
STRIPE_KEY_RE = re.compile(r"\b(sk_(?:live|test)_[A-Za-z0-9]{16,})\b")
JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")
PEM_RE = re.compile(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----")
QUOTED_BTC_RE = re.compile(r"[\"'](bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})[\"']")
QUOTED_ETH_RE = re.compile(r"[\"'](0x[a-fA-F0-9]{40})[\"']")
QUOTED_XMR_RE = re.compile(r"[\"']([48][0-9AB][1-9A-HJ-NP-Za-km-z]{93})[\"']")
QUOTED_MD5_RE = re.compile(r"[\"']([0-9a-fA-F]{32})[\"']")
QUOTED_SHA1_RE = re.compile(r"[\"']([0-9a-fA-F]{40})[\"']")
QUOTED_SHA256_RE = re.compile(r"[\"']([0-9a-fA-F]{64})[\"']")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.I)
MUTEX_RE = re.compile(r"[\"']((?:Global|Local)\\[^\"']{2,80})[\"']")
CREATE_MUTEX_RE = re.compile(
    r"CreateMutex(?:A|W|ExA|ExW)?\s*\([^)]*[\"']([^\"']{2,80})[\"']",
    re.I,
)
PIPE_RE = re.compile(r"[\"']([^\"']*pipe\\[A-Za-z0-9._-]{1,80})[\"']", re.I)
PDB_RE = re.compile(r"([A-Za-z]:\\[^\n\"']+\.pdb)", re.I)
COOKIE_RE = re.compile(
    r"(?:document\.cookie|Set-Cookie:)\s*[\"']?([A-Za-z0-9_-]{2,80})\s*=",
    re.I,
)
SETCOOKIE_RE = re.compile(r"setcookie\s*\(\s*['\"]([^'\"]{1,80})['\"]", re.I)
CRON_RE = re.compile(
    r"[\"'](@reboot|(?:\*(?:/\d+)?|\d{1,2})\s+(?:\*(?:/\d+)?|\d{1,2})\s+"
    r"(?:\*(?:/\d+)?|\d{1,2})\s+(?:\*(?:/\d+)?|\d{1,2})\s+(?:\*(?:/\d+)?|\d{1,2})"
    r"[^\"']{0,80})[\"']"
)
STRATUM_RE = re.compile(r"(?i)(stratum\+tcp://[^\s\"']+)")
KEY_ASSIGN_RE = re.compile(
    r"""(?:\$|(?:var|let|const)\s+)(?:xor_?key|rc4_?key|aes_?key|key|secret|passwd|password|token|auth|api_?key)\s*=\s*['\"]([^'\"]{4,128})['\"]""",
    re.I,
)
HOST_PORT_RE = re.compile(
    r"[\"']((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}:\d{2,5})[\"']"
)

FILE_TLDS = {
    "exe",
    "dll",
    "scr",
    "bat",
    "cmd",
    "com",
    "ps1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "hta",
    "msi",
    "jar",
    "php",
    "asp",
    "aspx",
    "png",
    "jpg",
    "gif",
    "css",
    "map",
    "phtml",
    "php5",
    "phar",
    "jsp",
    "war",
    "sh",
    "py",
    "so",
    "elf",
    "apk",
    "bin",
    "dat",
}

NOISE_HOSTS = {
    "www.w3.org",
    "schema.org",
    "example.com",
    "example.org",
    "localhost",
}

NOISE_IPS = {
    "0.0.0.0",
    "127.0.0.1",
    "255.255.255.255",
    "::1",
    "https://example.com/p/anvil",
}

PASTE_HOSTS = {
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "ghostbin.com",
    "rentry.co",
    "ix.io",
    "dpaste.com",
    "paste.debian.net",
    "gist.github.com",
    "0bin.net",
    "paste2.org",
    "justpaste.it",
    "termbin.com",
    "controlc.com",
}

# COM/OLE ProgIDs look like hostnames; do not report them as domains.
PROGID_SUFFIXES = {
    "shell",
    "xmlhttp",
    "stream",
    "filesystemobject",
    "application",
    "object",
    "file",
    "dictionary",
}

API_PATTERNS = (
    ("WScript.Shell", re.compile(r"WScript\.Shell", re.I)),
    ("WScript", re.compile(r"\bWScript\b")),
    ("ActiveXObject", re.compile(r"ActiveXObject")),
    ("MSXML2.XMLHTTP", re.compile(r"MSXML2\.XMLHTTP", re.I)),
    ("WinHttp.WinHttpRequest", re.compile(r"WinHttp\.WinHttpRequest", re.I)),
    ("XMLHTTP", re.compile(r"XMLHTTP", re.I)),
    ("XMLHttpRequest", re.compile(r"\bXMLHttpRequest\b")),
    ("ADODB.Stream", re.compile(r"ADODB\.Stream", re.I)),
    ("Scripting.FileSystemObject", re.compile(r"Scripting\.FileSystemObject", re.I)),
    ("Shell.Application", re.compile(r"Shell\.Application", re.I)),
    ("WMI", re.compile(r"\b(?:GetObject|SWbem|Win32_Process)\b")),
    ("cmd.exe", re.compile(r"cmd\.exe", re.I)),
    ("powershell", re.compile(r"\bpowershell(?:\.exe)?\b", re.I)),
    ("bitsadmin", re.compile(r"\bbitsadmin\b", re.I)),
    ("certutil", re.compile(r"\bcertutil\b", re.I)),
    ("mshta", re.compile(r"\bmshta(?:\.exe)?\b", re.I)),
    ("rundll32", re.compile(r"\brundll32(?:\.exe)?\b", re.I)),
    ("regsvr32", re.compile(r"\bregsvr32(?:\.exe)?\b", re.I)),
    ("schtasks", re.compile(r"\bschtasks(?:\.exe)?\b", re.I)),
    ("wmic", re.compile(r"\bwmic(?:\.exe)?\b", re.I)),
    ("netsh", re.compile(r"\bnetsh(?:\.exe)?\b", re.I)),
    ("wget", re.compile(r"\bwget(?:\.exe)?\b", re.I)),
    ("curl", re.compile(r"\bcurl(?:_init|_exec|_setopt)?\s*\(")),
    ("fsockopen", re.compile(r"\bfsockopen\s*\(")),
    ("proc_open", re.compile(r"\bproc_open\s*\(")),
    ("passthru", re.compile(r"\bpassthru\s*\(")),
    ("shell_exec", re.compile(r"\bshell_exec\s*\(")),
    ("system()", re.compile(r"\bsystem\s*\(")),
    ("imap_open", re.compile(r"\bimap_open\s*\(")),
    ("move_uploaded_file", re.compile(r"\bmove_uploaded_file\s*\(")),
    ("eval", re.compile(r"\beval\s*\(")),
    ("Function()", re.compile(r"\bnew\s+Function\s*\(")),
    ("fromCharCode", re.compile(r"fromCharCode")),
    ("base64_decode", re.compile(r"base64_decode\s*\(")),
    ("gzinflate", re.compile(r"gzinflate\s*\(")),
    ("WebSocket", re.compile(r"\bWebSocket\b")),
    ("child_process", re.compile(r"child_process")),
    ("CreateMutex", re.compile(r"CreateMutex", re.I)),
    ("VirtualAlloc", re.compile(r"VirtualAlloc", re.I)),
    ("ShellExecute", re.compile(r"ShellExecute", re.I)),
    ("CreateObject", re.compile(r"CreateObject", re.I)),
    ("xmrig", re.compile(r"\bxmrig\b", re.I)),
    ("crontab", re.compile(r"\bcrontab\b", re.I)),
)


@dataclass
class Indicators:
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    ip_ports: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    onion: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    url_paths: list[str] = field(default_factory=list)
    query_keys: list[str] = field(default_factory=list)
    request_params: list[str] = field(default_factory=list)
    http_methods: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    paste_urls: list[str] = field(default_factory=list)
    telegram: list[str] = field(default_factory=list)
    discord: list[str] = field(default_factory=list)
    wallets: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    crypto_keys: list[str] = field(default_factory=list)
    md5: list[str] = field(default_factory=list)
    sha1: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    uuids: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    mutexes: list[str] = field(default_factory=list)
    named_pipes: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    unix_paths: list[str] = field(default_factory=list)
    registry: list[str] = field(default_factory=list)
    pdb_paths: list[str] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)
    cron: list[str] = field(default_factory=list)
    stratum: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, list[str]]:
        return {item.name: list(getattr(self, item.name)) for item in fields(self)}

    def is_empty(self) -> bool:
        return not any(getattr(self, item.name) for item in fields(self))

    def merge(self, other: Indicators | None) -> Indicators:
        if other is None:
            return Indicators(**{item.name: list(getattr(self, item.name)) for item in fields(self)})
        kwargs: dict[str, list[str]] = {}
        names = {item.name for item in fields(self)} | {item.name for item in fields(other)}
        for name in names:
            left = list(getattr(self, name, []) or [])
            right = list(getattr(other, name, []) or [])
            kwargs[name] = _unique(left + right)
        return Indicators(**{item.name: kwargs.get(item.name, []) for item in fields(self)})


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.strip()
        if not key:
            continue
        folded = key.lower()
        if folded in seen:
            continue
        seen.add(folded)
        out.append(key)
    return out


def _refang_text(text: str) -> str:
    text = re.sub(r"(?i)\bhxxps://", "https://", text)
    text = re.sub(r"(?i)\bhxxp://", "http://", text)
    text = re.sub(r"(?i)\bfxp://", "ftp://", text)
    text = text.replace("[.]", ".").replace("(.)", ".").replace("[://]", "://")
    text = text.replace("[:]", ":")
    return text


def _refang_url(url: str) -> str:
    url = url.rstrip(").,;]")
    lower = url.lower()
    if lower.startswith("hxxps://"):
        return "https://" + url[8:]
    if lower.startswith("hxxp://"):
        return "http://" + url[7:]
    if lower.startswith("fxp://"):
        return "ftp://" + url[6:]
    return url


def _host_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or host in NOISE_HOSTS:
        return None
    if host.count(".") == 0:
        return None
    return host


def _is_domain(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host in NOISE_HOSTS or not host or " " in host:
        return False
    tld = host.rsplit(".", 1)[-1]
    if tld in FILE_TLDS or tld.isdigit() or tld in PROGID_SUFFIXES:
        return False
    if len(tld) < 2 or not tld.isalpha():
        return False
    if re.fullmatch(r"[0-9a-f]{8,}", host.replace(".", "")):
        return False
    return True


def _valid_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except Exception:
        return False
    return str(ip) not in NOISE_IPS


def _valid_ipv6(value: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(value)
    except Exception:
        return False
    text = str(ip)
    return text not in NOISE_IPS and not ip.is_loopback and not ip.is_unspecified


def _ipv6_candidates(blob: str) -> list[str]:
    found: list[str] = []
    for match in IPV6_BRACKET_RE.findall(blob) + QUOTED_IPV6_RE.findall(blob):
        if match.count(":") < 2:
            continue
        if _valid_ipv6(match):
            found.append(str(ipaddress.IPv6Address(match)))
    return found


def _url_parts(urls: list[str]) -> tuple[list[str], list[str], list[str]]:
    paths: list[str] = []
    keys: list[str] = []
    pastes: list[str] = []
    for url in urls:
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        path = parsed.path or ""
        if path and path != "/":
            paths.append(path)
        if parsed.query:
            for key in parse_qs(parsed.query, keep_blank_values=True):
                keys.append(key)
        host = (parsed.hostname or "").lower()
        if host in PASTE_HOSTS or any(host.endswith("." + paste) for paste in PASTE_HOSTS):
            pastes.append(url)
    return paths, keys, pastes


def extract_indicators(
    *texts: str,
    extra_domains: list[str] | None = None,
    extra_urls: list[str] | None = None,
) -> Indicators:
    blob = _refang_text("\n".join(t for t in texts if t))
    urls = [_refang_url(m) for m in URL_RE.findall(blob)]
    urls.extend(extra_urls or [])
    urls.extend(STRATUM_RE.findall(blob))
    urls = [u for u in urls if "://" in u]

    domains: list[str] = []
    for url in urls:
        host = _host_from_url(url)
        if host and (_is_domain(host) or host.endswith(".onion")):
            domains.append(host)
    for match in HOST_IN_QUOTES_RE.findall(blob):
        if _is_domain(match) or match.lower().endswith(".onion"):
            domains.append(match.lower())
    if extra_domains:
        for host in extra_domains:
            host = host.lower().rstrip(".")
            if host.count(".") == 0:
                continue
            if re.fullmatch(r"[0-9a-f]{8,12}", host):
                continue
            if _is_domain(host) or host.endswith(".onion") or host not in NOISE_HOSTS:
                domains.append(host)

    url_paths, query_keys, paste_urls = _url_parts(urls)
    query_keys.extend(QUERY_IN_URL_RE.findall(blob))

    request_params: list[str] = []
    for kind, name in PHP_PARAM_RE.findall(blob):
        request_params.append(f"{kind}:{name}")
        query_keys.append(name)

    endpoints: list[str] = []
    endpoints.extend(IP_PORT_RE.findall(blob))
    endpoints.extend(HOST_PORT_RE.findall(blob))
    for host, port in FSOCK_RE.findall(blob):
        host = host.strip().split("/")[-1]
        endpoints.append(f"{host}:{port}")

    wallets = [f"btc:{m}" for m in QUOTED_BTC_RE.findall(blob)]
    wallets.extend(f"eth:{m}" for m in QUOTED_ETH_RE.findall(blob))
    wallets.extend(f"xmr:{m}" for m in QUOTED_XMR_RE.findall(blob))

    secrets = [f"aws:{m}" for m in AWS_KEY_RE.findall(blob)]
    secrets.extend(f"github:{m}" for m in GITHUB_TOKEN_RE.findall(blob))
    secrets.extend(f"google:{m}" for m in GOOGLE_API_RE.findall(blob))
    secrets.extend(f"slack:{m}" for m in SLACK_TOKEN_RE.findall(blob))
    secrets.extend(f"slack-webhook:{m}" for m in SLACK_WEBHOOK_RE.findall(blob))
    secrets.extend(f"stripe:{m}" for m in STRIPE_KEY_RE.findall(blob))
    secrets.extend(f"jwt:{m}" for m in JWT_RE.findall(blob))
    secrets.extend(f"pem:{m}" for m in PEM_RE.findall(blob))

    telegram = list(TELEGRAM_BOT_RE.findall(blob)) + list(TELEGRAM_URL_RE.findall(blob))
    discord = list(DISCORD_WEBHOOK_RE.findall(blob))

    sha256 = list(QUOTED_SHA256_RE.findall(blob))
    sha1 = [m for m in QUOTED_SHA1_RE.findall(blob) if not m.lower().startswith("0x")]
    md5 = [
        m
        for m in QUOTED_MD5_RE.findall(blob)
        if m.lower() not in {s.lower()[:32] for s in sha256} and not re.fullmatch(r"0+", m)
    ]

    files = [m for m in FILENAME_RE.findall(blob)]
    paths = WIN_PATH_RE.findall(blob) + UNC_PATH_RE.findall(blob)
    apis = [label for label, pattern in API_PATTERNS if pattern.search(blob)]

    return Indicators(
        urls=_unique(urls),
        domains=_unique(domains),
        ipv4=_unique([ip for ip in IPV4_RE.findall(blob) if _valid_ipv4(ip)]),
        ipv6=_unique(_ipv6_candidates(blob)),
        ip_ports=_unique(IP_PORT_RE.findall(blob)),
        endpoints=_unique(endpoints),
        onion=_unique([m.lower() for m in ONION_RE.findall(blob)]),
        emails=_unique(EMAIL_RE.findall(blob)),
        url_paths=_unique(url_paths),
        query_keys=_unique(query_keys),
        request_params=_unique(request_params),
        user_agents=_unique(UA_RE.findall(blob)),
        paste_urls=_unique(paste_urls),
        telegram=_unique(telegram),
        discord=_unique(discord),
        wallets=_unique(wallets),
        secrets=_unique(secrets),
        crypto_keys=_unique(KEY_ASSIGN_RE.findall(blob)),
        md5=_unique(md5),
        sha1=_unique(sha1),
        sha256=_unique(sha256),
        uuids=_unique(UUID_RE.findall(blob)),
        cves=_unique([m.upper() for m in CVE_RE.findall(blob)]),
        mutexes=_unique(MUTEX_RE.findall(blob) + CREATE_MUTEX_RE.findall(blob)),
        named_pipes=_unique(PIPE_RE.findall(blob)),
        files=_unique(files),
        paths=_unique(paths),
        unix_paths=_unique(UNIX_PATH_RE.findall(blob)),
        registry=_unique(REG_RE.findall(blob)),
        pdb_paths=_unique(PDB_RE.findall(blob)),
        cookies=_unique(COOKIE_RE.findall(blob) + SETCOOKIE_RE.findall(blob)),
        cron=_unique(CRON_RE.findall(blob)),
        stratum=_unique(STRATUM_RE.findall(blob)),
        apis=apis,
    )


def ingest_sandbox(
    iocs: Indicators | None,
    *,
    extra_domains: list[str] | None = None,
    http: list[dict] | None = None,
    tcp: list[dict] | None = None,
) -> Indicators:
    """Fold observed sandbox DNS/HTTP/TCP into the static indicator set."""
    base = iocs or Indicators()
    extra_urls: list[str] = []
    extra_text: list[str] = []
    observed = Indicators()
    if extra_domains:
        observed.domains = [
            host.lower().rstrip(".")
            for host in extra_domains
            if host
            and host.count(".") >= 1
            and not re.fullmatch(r"[0-9a-f]{8,12}", host.lower().rstrip("."))
        ]
    for rec in http or []:
        host = str(rec.get("host") or "").strip()
        path = str(rec.get("path") or rec.get("url") or "")
        method = str(rec.get("method") or "").upper()
        scheme = str(rec.get("scheme") or "http") or "http"
        headers = rec.get("headers") or {}
        body = str(rec.get("body") or "")
        host_name = host.split("@")[-1]
        if ":" in host_name and host_name.rsplit(":", 1)[-1].isdigit():
            observed.endpoints.append(host_name)
            host_name = host_name.rsplit(":", 1)[0]
        if host_name:
            observed.domains.append(host_name.lower())
            extra_urls.append(f"{scheme}://{host_name}{path or ''}")
        if path:
            extra_text.append(path)
            observed.url_paths.append(path.split("?")[0])
        if method:
            observed.http_methods.append(method)
        ua = ""
        if isinstance(headers, dict):
            ua = str(headers.get("User-Agent") or headers.get("user-agent") or "")
        if ua:
            observed.user_agents.append(ua)
        if body:
            extra_text.append(body)
    for rec in tcp or []:
        banner = str(rec.get("banner") or "")
        if banner:
            extra_text.append(banner)
    extracted = extract_indicators(*extra_text, extra_domains=extra_domains, extra_urls=extra_urls)
    return base.merge(extracted).merge(observed)


def locate_indicators(
    layers: list[tuple[str, str]],
    extra_domains: list[str] | None = None,
    http: list[dict] | None = None,
    tcp: list[dict] | None = None,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for name, text in layers:
        extra = extra_domains if name in {"inner", "sandbox"} else None
        iocs = extract_indicators(text, extra_domains=extra)
        if name == "sandbox":
            iocs = ingest_sandbox(iocs, extra_domains=extra_domains, http=http, tcp=tcp)
        for kind, values in iocs.to_dict().items():
            for value in values:
                key = (kind, value.lower(), name)
                if key in seen:
                    continue
                seen.add(key)
                rows.append({"kind": kind, "value": value, "layer": name})
    return rows


def format_indicators(iocs: Indicators) -> str:
    if iocs.is_empty():
        return "indicators: (none)\n"
    lines = ["indicators:"]
    for key, values in iocs.to_dict().items():
        if not values:
            continue
        lines.append(f"  {key}:")
        for value in values:
            lines.append(f"    {value}")
    return "\n".join(lines) + "\n"
