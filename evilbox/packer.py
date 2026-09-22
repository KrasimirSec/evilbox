from __future__ import annotations

import re

_HINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("eval+base64", re.compile(r"eval\s*\(\s*base64_decode\s*\(", re.I)),
    ("eval+gzinflate", re.compile(r"eval\s*\(\s*gzinflate\s*\(", re.I)),
    ("eval+gzuncompress", re.compile(r"eval\s*\(\s*gzuncompress\s*\(", re.I)),
    ("eval+gzdecode", re.compile(r"eval\s*\(\s*gzdecode\s*\(", re.I)),
    ("eval+bzdecompress", re.compile(r"eval\s*\(\s*bzdecompress\s*\(", re.I)),
    ("eval+str_rot13", re.compile(r"eval\s*\(\s*str_rot13\s*\(", re.I)),
    ("eval+strrev", re.compile(r"eval\s*\(\s*strrev\s*\(", re.I)),
    ("eval+urldecode", re.compile(r"eval\s*\(\s*(?:raw)?urldecode\s*\(", re.I)),
    ("eval+bitwise-not", re.compile(r"eval\s*\(\s*~", re.I)),
    ("nested-decode-chain", re.compile(r"eval\s*\(\s*(?:gzinflate|gzuncompress|gzdecode|bzdecompress|base64_decode|str_rot13|strrev|hex2bin)\s*\([^)]{0,80}(?:gzinflate|base64_decode|str_rot13)", re.I)),
    ("dean-edwards-packer", re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,", re.I)),
    ("jsfuck", re.compile(r"^(?:\s*[\[\]()!+]){24,}\s*$")),
    ("jjencode", re.compile(r"=\s*~\s*\[\s*\]\s*;\s*[$\w]+\s*=\s*\{")),
    ("aaencode", re.compile(r"ﾟωﾟ|ﾟｰﾟ|ﾟДﾟ|aaencode", re.I)),
    ("sojson-jsjiami", re.compile(r"sojson\.v\d|jsjiami\.com", re.I)),
    ("javascript-obfuscator", re.compile(r"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\+/=")),
    ("js-string-array", re.compile(r"\b(?:push|shift)\s*\([^;]{0,40}\b(?:push|shift)\s*\(")),
    ("function-constructor", re.compile(r"\b(?:new\s+)?Function\s*\(")),
    ("setTimeout-string", re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*['\"]", re.I)),
    ("computed-fromCharCode", re.compile(r"""String\s*\[\s*['\"]fromCharCode['\"]\s*\]""")),
    ("fromCharCode", re.compile(r"fromCharCode\s*\(")),
    ("hex-escape", re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")),
    ("unicode-escape", re.compile(r"(?:\\u[0-9a-fA-F]{4}){8,}")),
    ("chr-chain", re.compile(r"(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){4,}chr\s*\(", re.I)),
    ("string-concat", re.compile(r"""(['"][^'"]{0,16}['"]\s*(?:\.(?!=)|\+)\s*){2,}['"]""")),
    ("preg_replace/e", re.compile(r"preg_replace\s*\([^;]{0,120}e['\"]\s*,", re.I)),
    ("create_function", re.compile(r"create_function\s*\(", re.I)),
    ("assert+decode", re.compile(r"assert\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)", re.I)),
    ("call_user_func", re.compile(r"\bcall_user_func(?:_array)?\s*\(", re.I)),
    ("register_shutdown_function", re.compile(r"\bregister_shutdown_function\s*\(", re.I)),
    ("ob_start-callback", re.compile(r"\bob_start\s*\(", re.I)),
    ("array_map-callback", re.compile(r"\b(?:array_map|array_filter|array_walk|usort)\s*\(", re.I)),
    ("variable-function", re.compile(r"\$[A-Za-z_][\w]*\s*\(")),
    ("variable-variable", re.compile(r"\$\$[A-Za-z_]", re.I)),
    ("include+decode", re.compile(r"(?:include|require)(?:_once)?\s*\(\s*(?:base64_decode|gzinflate)", re.I)),
    ("pack-H*", re.compile(r"pack\s*\(\s*['\"]H\*", re.I)),
    ("unpack", re.compile(r"\bunpack\s*\(", re.I)),
    ("hex2bin", re.compile(r"\bhex2bin\s*\(", re.I)),
    ("convert_uudecode", re.compile(r"\bconvert_uudecode\s*\(", re.I)),
    ("halt-compiler", re.compile(r"__halt_compiler\s*\(", re.I)),
    ("self-read", re.compile(r"fopen\s*\(\s*__FILE__|file_get_contents\s*\(\s*__FILE__", re.I)),
    ("request-driven", re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[", re.I)),
    ("pas-keyed", re.compile(
        r"md5\s*\(\s*\$\w+\s*\)\s*\.\s*substr\s*\(\s*md5\s*\(\s*strrev",
        re.I,
    )),
    ("auto-prepend", re.compile(r"auto_prepend_file|auto_append_file", re.I)),
    ("string-xor", re.compile(r"""['"][^'"]{4,}['"]\s*\^\s*['"]""")),
    ("goto-labels", re.compile(r"\bgoto\s+\w+", re.I)),
    ("control-flow-flatten", re.compile(r"while\s*\(.+\)\s*\{[^}]{0,80}\bswitch\s*\(", re.S | re.I)),
    ("self-defending", re.compile(r"\bdebugger\b|toString\s*\[|integrity", re.I)),
    ("domain-lock", re.compile(r"location\.hostname|document\.domain", re.I)),
    ("cloaking-referrer", re.compile(r"HTTP_REFERER|document\.referrer", re.I)),
    ("cloaking-ua", re.compile(r"HTTP_USER_AGENT|navigator\.userAgent", re.I)),
    ("remote-payload", re.compile(r"pastebin\.|githubusercontent|discord\.com/api|api\.telegram|dns-query|etherscan|infura\.io", re.I)),
    ("exif-stego", re.compile(r"exif_read_data|getimagesize\s*\(", re.I)),
    ("htaccess-hide", re.compile(r"\.htaccess", re.I)),
    ("fopo", re.compile(r"fopo\.com\.ar|Free Online PHP Obfuscator", re.I)),
    ("yakpro-po", re.compile(r"yakpro|YAK Pro", re.I)),
    ("myobfuscate", re.compile(r"myobfuscate\.com", re.I)),
    ("buffer-from-hex", re.compile(r"Buffer\s*\.\s*from\s*\([^;]{0,80}['\"]hex['\"]", re.I)),
    ("ioncube-encoded", re.compile(r"ionCube\s+Loader|ioncube_loader", re.I)),
    ("zend-guard-encoded", re.compile(r"Zend\s+Guard|@Zend;", re.I)),
    ("sourceguardian-encoded", re.compile(r"sourceguardian|sg_load\s*\(", re.I)),
)


def packer_hints(source: str) -> list[str]:
    found: list[str] = []
    for label, pattern in _HINTS:
        if pattern.search(source):
            found.append(label)
    return found
