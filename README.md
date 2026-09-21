# Evilbox

Evilbox **statically** deobfuscates JavaScript and PHP, then classifies what the sample can do. It unwraps common encodings and packers, folds constant expressions on the syntax tree, labels malware roles, extracts IOCs, and suggests **scanner-visible** strings from the original packed file.

It does **not** execute the input in a JS or PHP engine. `evilbox serve` is the same static path as a paste/upload web UI. The optional Docker PHP sandbox is a separate, isolated lab and is **CLI-only**.

## What you get

| Surface | What it does |
| --- | --- |
| Cleaned source | Unwrapped codecs, spliced `eval` payloads, renamed junk identifiers |
| Roles / capabilities | Multi-label hints (`webshell`, `dropper`, …) with evidence snippets |
| Indicators | URLs, domains, IPs, emails, files, paths, registry, APIs |
| Layers | Original → unwrap passes → inner. Sandbox eval dumps are extra layers |
| Unresolved folds | Decoder/packer/dispatch calls that did not simplify, per layer |
| Surface signatures | Full YARA rule + PCRE needles from the **packed** file only |
| Cluster keys | Exact inner hash (`cluster_sha256`) and fuzzy minhash family id |
| PHP sandbox | Isolated Docker run that dumps `eval()` and sinks C2 (CLI only) |

## Install

The Python environment lives in `.venv` and is created **automatically** the first time you run the wrapper. You do not activate it.

From this project folder:

```text
bin/evilbox
bin/evilbox --help
bin/evilbox serve
```

Optional: put `bin` on `PATH`, or use [direnv](https://direnv.net/) (`direnv allow` in this directory). Then `evilbox` works without the `bin/` prefix.

Python 3.10+ is required. Tree-sitter parsers are installed into `.venv` on first run. Docker is required only for `--sandbox`.

## Quick start

No arguments opens a menu (deobfuscate, sandbox dump/observe, batch, web decoder, quit). Any extra arguments skip the menu.

```text
evilbox packed.js -o clean.js
evilbox packed.php --lang php
evilbox packed.php --report report.json --html report.html
evilbox - --lang js < packed.js
evilbox ./samples -o ./evilbox-out
evilbox packed.php --sandbox dump
evilbox packed.php --sandbox observe --logs-dir ./sandbox-logs --timeout 20
evilbox serve
```

Stdout is the cleaned source. Roles, capabilities, IOCs, and unresolved folds go to stderr. `-o clean.js` also writes `clean.iocs.json` and `clean.report.json` unless `--report` is set.

## Command-line reference

```text
evilbox [INPUT] [options]
evilbox serve [--host HOST] [--port PORT] [--open]
```

`INPUT` is a file, a directory of samples, or `-` for stdin.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--lang auto\|js\|php` | `auto` | Language. `auto` uses the path, then `<?php`, then heuristics |
| `-o`, `--output PATH` | stdout | Cleaned source file, or a directory in batch mode |
| `--report PATH` | auto next to `-o` | JSON report (`evilbox.report.v1`) |
| `--html PATH` | off | HTML report (same fields as JSON) |
| `--max-passes N` | `16` | Unwrap/fold iterations |
| `--php-version 5.6\|7.4\|8.3` | `8.3` static, `7.4` observe | PHP dialect for `substr` and the sandbox image |
| `--sandbox dump\|observe` | off | Isolated PHP Docker lab. JS files stay on the static path |
| `--sandbox-profile …` | `default` | Request shape inside the sandbox (see [PHP sandbox](#php-sandbox-evalhook-no-real-internet)) |
| `--keep-name` | off | Mount the sample under its original filename inside `/samples` |
| `--stage-file PATH` | off | Bytes the sandbox HTTP/HTTPS sink serves instead of `OK` |
| `--logs-dir PATH` | `EVILBOX_LOGS` or `./sandbox-logs` | Sandbox log root |
| `--timeout N` | `15` | Sandbox PHP timeout in seconds |
| `serve` | — | Local web UI + JSON API (static analysis only) |

### Environment

| Variable | Meaning |
| --- | --- |
| `EVILBOX_DEBUG=1` | Print a traceback instead of a one-line `error:` |
| `EVILBOX_LOGS` | Default sandbox log root (`DEOBFUSCATOR_LOGS` is accepted as an alias) |
| `EVILBOX_WEB_MAX_BYTES` | Web sample size cap (default 2 MiB) |
| `EVILBOX_WEB_TIMEOUT` | Web decode timeout in seconds (default 20) |

### Exit status

| Code | Meaning |
| --- | --- |
| `0` | Parsed cleanly and inner-layer decoder folds resolved |
| `1` | Best-effort output was written, but the result still does not parse **or** decoder/packer folds remain unresolved (leftover `gzinflate`, recovered `convert_uudecode`, ionCube, …) |
| `2` | Missing file, permission problem, sandbox/Docker failure, or unexpected error (short `error:` line, no traceback) |
| `130` | Interrupted |

### Interactive menu

`evilbox` with no arguments:

1. Deobfuscate a file (optional `-o`, `--report`, `--lang`)
2. PHP sandbox dump (log `eval`, do not run payloads)
3. PHP sandbox observe (run in isolated Docker)
4. Batch a directory of `.js` / `.php` samples
5. Open the web decoder
6. Quit

## Batch mode

If `INPUT` is a directory, Evilbox walks `.js`, `.mjs`, `.cjs`, `.php`, `.phtml`, `.php5`, `.php7`, and `.phps` files.

```text
evilbox ./samples -o ./evilbox-out
evilbox ./samples --report ./evilbox-out --html ./evilbox-html
```

- Output **mirrors the relative layout**: `a/index.php` and `b/index.php` become `a/index.clean.php` and `b/index.clean.php`. They do not overwrite each other.
- Each file is decoded in isolation. A crash in one sample prints `error: <path>: …` and the rest of the run continues (exit `2` if any file failed).
- Each sample gets `*.clean.*`, `*.report.json`, and (with `--html`) `*.report.html`.
- `clusters.json` groups similar inner layers with a token n-gram **minhash** (a changed domain or XOR key still groups a family). `cluster_sha256` in each report is an exact whitespace-normalized hash of that sample’s inner text.

PHP files are read as latin-1 (byte strings). Other files try UTF-8, then latin-1.

## Web decoder

```text
evilbox serve
evilbox serve --host 127.0.0.1 --port 8080 --open
```

Open `http://127.0.0.1:8080/`. Paste source or upload a `.js` / `.php` file. Bind `--host 0.0.0.0` only if you intend other machines to reach it.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Browser UI |
| `GET` | `/health` | Liveness (`sandbox` is always `false`) |
| `GET` | `/api/examples` | Built-in demo samples |
| `POST` | `/api/decode` | Decode a sample |

POST body:

- JSON `{"source":"...","lang":"auto|js|php","filename":"optional.php","max_passes":16}`
- raw `text/plain` (language via `?lang=php`)
- `multipart/form-data` with a `file` field (optional `lang`, `filename`, `max_passes`)

```text
curl -s -X POST http://127.0.0.1:8080/api/decode \
  -H 'Content-Type: application/json' \
  -d '{"source":"<?php eval(base64_decode('"'"'ZWNobyAiaGkiOw=='"'"'));","lang":"php"}'

curl --data-binary @packed.php -H 'Content-Type: text/plain' \
  'http://127.0.0.1:8080/api/decode?lang=php&filename=packed.php'
```

The JSON response includes `ok`, `decoded`, `report` (`evilbox.report.v1`), `layers` (with full text), and `elapsed_ms`.

The web path is **static only**: samples stay in memory for that request, are not written to disk, and are not executed. `--sandbox` is not exposed. Defaults are 2 MiB and 20 seconds (see environment variables above). Each decode runs in a **subprocess** with CPU and address rlimits; a hang is killed with SIGKILL. Up to four decodes run at once; further requests get `503`. The UI is same-origin (no `Access-Control-Allow-Origin: *`).

## Unpacking (static)

No JS/PHP engine. Nested codec expressions fold in one pass when every function is implemented. Leftover `eval` wrappers iterate up to `--max-passes` (default 16).

### PHP codecs and string ops (folded when arguments are constants)

`base64_decode`, `gzinflate`, `gzuncompress`, `gzdecode`, `bzdecompress` / `bzinflate`, `str_rot13`, `hex2bin`, `hexdec`, `pack('H*')` / `unpack('H*')`, `chr` / `ord`, `strtr` (from/to strings **and** array maps, longest key first), `str_repeat`, `strrev`, `urldecode` / `rawurldecode`, `str_replace` / `str_ireplace` (array search/replace), `substr` (follows `--php-version`), `strtolower` / `strtoupper` / `mb_*` (ASCII letters only; high bytes stay), `implode` / `join`, `sprintf` (`%s` / `%d`; `%x` / `%e` / `%f` are left unfolded), `html_entity_decode` / `htmlspecialchars_decode`, `stripslashes` (`\0` is NUL; a trailing backslash is dropped), `quoted_printable_decode`, `convert_uudecode`, `intval`, `trim` / `ltrim` / `rtrim` (PHP charlist, including `a..z` ranges), `str_pad` (multi-character pad), `bin2hex`, string XOR (`^`) and `xor` / `str_xor` / `rc4` / `rc4crypt` when the key is a constant, `dirname`, `file_get_contents` / `readfile` of `__FILE__` or a sibling file next to the sample.

Nested chains such as `eval(gzinflate(base64_decode(str_rot13(...))))` fold in one pass.

### PHP dynamic execution (spliced when callback + payload are constants)

`eval`, `assert`, `create_function`, `preg_replace` with `/e`, `call_user_func` / `call_user_func_array`, `register_shutdown_function` / `register_tick_function`, `ob_start`, `array_map` / `array_filter` / `array_walk` / `usort` / `uasort` / `uksort`, variable functions (`$a('…')`), variable variables (`$$a`), function names stored in arrays (`$a[0]('…')`, `$a['d']('…')`), `include` / `require` / `*_once` of a decoded PHP payload.

### JavaScript codecs and string ops

String unescapes (`\xNN`, `\uNNNN`, `\u{…}`, octal, HTML entities) in both quote styles and template literals. `atob`, `unescape` (`%uXXXX` / `%HH`), `decodeURIComponent` / `decodeURI`, `String.fromCharCode` (including `.apply` and computed `String['fromCharCode']`), `parseInt` / `Number` / `String`, `Buffer.from(..., 'hex')`, string methods (`charAt`, `charCodeAt`, `concat`, `slice` / `substring` / `substr`, `split`, `replace` / `replaceAll`, `toLowerCase` / `toUpperCase`, `indexOf`, `repeat`), array `join` / `reverse` / `concat` / `slice`, number `toString(radix)`.

### JavaScript packers

- Dean Edwards `p.a.c.k.e.r.` (`eval(function(p,a,c,k,e,d)…`), including nested layers
- javascript-obfuscator / obfuscator.io / sojson / jsjiami string-array + rotator + index decoder (plain, base64, RC4, hex)
- JSFuck (`[]()!+`) Function-constructor payloads
- Percent-encoded bookmarklets, jjencode, best-effort AAEncode
- Split identifiers: `"at"+"ob"`, `window['at'+'ob']`

### JavaScript dynamic execution (spliced when the payload is a constant)

`eval`, `eval.call`, `window` / `globalThis` / `self` `['eval']`, `Function` / `new Function`, `setTimeout` / `setInterval` with a string.

### Layout and junk (both languages)

- Collapse huge blank-line / space runs
- Extract `__halt_compiler()` trailers (hex / base64 / zlib when they decode)
- Rename `_0x…`, lookalike `O0Il` names, long underscore names, and non-ASCII identifier homoglyphs

### How folding stays sound

PHP (and JS) folding is **per function**, not one table for the whole file.

- A later `$a = 'strrev'` does **not** rewrite an earlier `$a('aGVsbG8=')`. Real PHP prints `hello`; Evilbox matches that.
- Two functions may reuse the same variable name; each scope is folded on its own.
- Straight-line `$s .= …` / JS `s += …` chains collapse. Assignments inside `for` / `foreach` / `while` / `if` / `switch` do not (an empty loop must not become `$s = 'ab'`).
- Variables touched by `global`, references (`=&`), `extract`, `compact`, `parse_str`, or `foreach` are skipped.
- PHP strings are **bytes** (latin-1). `~`, XOR, `stripslashes`, `substr`, `strrev`, `ord`, `strtr`, and `strtoupper` work on bytes, not Unicode code points. Characters above U+00FF are an error, not replaced with `?`.
- Integer-looking floats stringify as PHP does (`6.0` → `6`). Shifts of 63 bits or more, and integers wider than 256 bits, are left unfolded (`echo 1 << 20000` does not crash).
- Left-nested `chr()` / `fromCharCode` chains of thousands of terms flatten iteratively (no `RecursionError`).
- `gzinflate` / `gzuncompress` / `gzdecode` / `bzdecompress` output is capped at **2 MiB**. Incomplete streams are refused (no unbounded `flush()`).
- `convert_uudecode` line-padding retries are marked **recovered** (exit `1` when they remain on the inner layer).
- `substr` past the end of the string: empty string on PHP 8, `false` on PHP 5/7 (`--php-version`).

Leftover Dean Edwards / JSFuck / JJEncode / AAEncode, `setTimeout("...")`, and remote loader URLs (pastebin, GitHub, Telegram, CDN, …) are **unresolved stages**, not fetched.

### Detected, not decoded

Need a missing key, another file, or a network/runtime: XOR/RC4 keys in cookies, POST, or a second file that is not next to the sample; EXIF / fake images / `.htaccess` `auto_prepend_file` / database options; request-driven shells with no payload; DNS TXT, blockchain, Telegram, pastebin, or CDN-fetched bodies; referrer/UA/geo cloaking; self-defending `debugger` traps; domain locks; full control-flow flattening / VM unpackers; **ionCube / Zend Guard / SourceGuardian** bytecode (`encoded, not analyzable`).

Packer **hints** (labels only, not a decode): `eval+base64`, `fromCharCode`, `preg_replace/e`, `javascript-obfuscator`, `fopo`, `yakpro-po`, `ioncube-encoded`, and the rest of the table in `evilbox/packer.py`.

## Classification

Roles are **multi-label** and evidence-backed. A sample can be a webshell and a mailer at the same time. Each role includes a score and snippets (layer + short excerpt).

Matching is done on **call nodes** in the parse tree. Strings and comments are skipped for generic words, so a WordPress `<input type="password">` or a cache plugin’s `file_get_contents` of a local file is not labelled stealer or dropper. `file_get_contents` is file-read unless the argument is a URL.

| Role | Typical evidence |
| --- | --- |
| `webshell` | `eval` / `assert` / `create_function` / `preg_replace /e` or OS exec, plus `$_GET` / `$_POST` / `$_COOKIE` / … |
| `backdoor` | Outbound HTTP/sockets plus eval, exec, or persistence |
| `dropper` | File write plus network, or a URL that drops `.exe` / `.dll` / `.ps1` / … |
| `injector` | Remote/dynamic `include`/`require`, or eval plus file write |
| `seo-spam` | Hidden links, `googlebot` / `bingbot` checks, WordPress post injection |
| `mailer` | `mail()` / PHPMailer / SMTP |
| `stealer` | Cookie/wallet harvest paths (`Cookies\Chrome`, `Login Data`, `wallet.dat`) plus read or exfil — not the word “password” in HTML |
| `phishing-kit` | Brand/OTP lures plus credential collection or file write |
| `cryptominer` | stratum / xmrig / miner pools |
| `wiper` | `unlink` / `rmdir` without webshell-style eval + superglobals |

Capabilities behind those labels: `eval-runtime`, `exec`, `superglobals`, `fs-write`, `fs-read`, `fs-delete`, `net-egress`, `persist`, `seo-inject`, `mail`, `credential-harvest`, `miner`, `phishing`, `payload-drop`, `include-remote`.

These are static (and sandbox-augmented) rules, not AV family names. Treat scores as hints and read the evidence.

## Reports

JSON schema id: `evilbox.report.v1`. Written by `--report`, next to `-o`, and (for sandbox runs) as `report.json` in the log directory. `--html` is the same data as a simple HTML page (malware strings are escaped).

| Field | Meaning |
| --- | --- |
| `sample` | Path, language, SHA-256 of the original file, SHA-256 of the inner layer, `cluster_sha256`, `cluster_minhash`, `php_version` |
| `packer` | Hints such as `eval+base64`, `fromCharCode`, `preg_replace/e` |
| `layers` | Original → unwrap passes → inner. Every sandbox eval dump is its own layer. Each layer lists `unresolved_folds` |
| `unresolved_folds` | Decoder/packer/dispatch calls that did not simplify, grouped per layer |
| `encoded_not_analyzable` | ionCube, Zend Guard, or SourceGuardian (`encoded, not analyzable`) |
| `failed_folds` | True when the inner layer still has decoder/packer leftovers |
| `roles` / `capabilities` | With evidence snippets |
| `indicators` | URLs, domains, IPs, emails, files, paths, registry, APIs |
| `indicators_by_layer` | The same IOCs tagged with the layer they appeared in |
| `surface_signatures` | Full YARA rule plus PCRE needles from the **original** file only |
| `sandbox` | Present when `--sandbox` was used (log dir, DNS hosts, HTTP, eval dump names, PHP version, request profile) |
| `sandbox_cross_check` | Static inner layer vs sandbox eval-dump layer; disagreements are flagged |

### Surface signatures

Inner decoded strings are **not** used for signature suggestions. A web scanner sees the packed file, not the unpacked payload.

From the original layer only:

- Decoder wrappers (`eval(base64_decode(…`, `String.fromCharCode(…`, `preg_replace` with `/e`, …)
- Long packed strings, including base64 blobs (a distinctive substring, not the full dump)
- Stable variable and function names that are not `_0x…` junk
- Distinctive comments

Each item has `kind`, `value`, a `yara` needle, a `pcre` pattern, and a short `why`. The report includes a complete YARA `rule` (`yara_rule`). Those rules are tested against a small clean WordPress plugin/theme corpus under `tests/corpus/wordpress_benign/`.

## PHP sandbox (evalhook, no real internet)

Optional Docker lab for packed PHP. JavaScript is never executed here; `--sandbox` on a `.js` file falls back to static JS cleanup.

```text
evilbox packed.php --sandbox dump
evilbox packed.php --sandbox observe --logs-dir ./sandbox-logs --timeout 20
evilbox packed.php --sandbox observe --php-version 7.4 --sandbox-profile googlebot
evilbox packed.php --sandbox observe --keep-name --stage-file ./second-stage.bin
```

| Mode | Behavior |
| --- | --- |
| `dump` | Log every `eval()` payload and **do not** execute it |
| `observe` | Log `eval()` **and** let the script run (requests hit the fake sink) |

Observe defaults to **PHP 7.4** so string `assert`, `create_function`, and `preg_replace /e` still execute. Pass `--php-version 8.3` or `5.6` to override. 8.3 and 7.4 compile evalhook; 5.6 cannot (no `zend_string`) and is observe/stub-only.

### Request profiles (`--sandbox-profile`)

| Profile | What the sample sees |
| --- | --- |
| `default` | `GET`, `Host: localhost`, UA `EvilboxSandbox/1.0` |
| `googlebot` | Googlebot 2.1 User-Agent |
| `google-referrer` | `Referer: https://www.google.com/` |
| `wp-cookie` | WordPress `wordpress_logged_in_*` / test cookies |

WordPress function stubs (`get_option`, `add_action`, `wp_mail`, …) are prepended. `sleep` / `usleep` / `nanosleep` return immediately (LD_PRELOAD, PHP process only).

`--keep-name` mounts the sample as `/samples/<original-basename>` instead of `/samples/sample.php`. `--stage-file` is what the HTTP/HTTPS sink returns instead of `OK\n` (analyst-supplied second stage).

### Isolation

Each run **builds a throwaway image tag**, starts a new container, then deletes the container and image tag.

- `--network none`, `--read-only` rootfs, tmpfs `/logs` `/tmp` `/run`
- `--cap-drop ALL`, then setup caps (`NET_ADMIN`, `NET_RAW`, `NET_BIND_SERVICE`, …) for dnsmasq / tcpdump / routing; `--security-opt no-new-privileges`
- `--memory 512m`, `--cpus 1`, `--pids-limit 128`
- Docker’s default seccomp profile stays enabled. If a `runsc` (gVisor) runtime is installed, it is used
- Sample bind-mounted **read-only**. **Logs are not bind-mounted.** After exit, the host copies `/logs` with `docker cp` and **rejects symlinks** before reading or writing `domains.txt` / `deobfuscated.php`
- PHP runs as uid **65534** with capabilities dropped. dnsmasq, tcpdump, the HTTP sink, and the TCP logger start first as root

### Inside the container

- [php-eval-hook](https://github.com/extremecoders-re/php-eval-hook) dumps every `eval()` to `/logs/php` (path is hardcoded; `putenv('SANDBOX_LOGS')` cannot redirect it)
- `SANDBOX_MODE` / `SANDBOX_LOGS` are **not** in the PHP process environment
- dnsmasq answers **every** DNS name with `127.0.0.1` (no upstream resolvers)
- `ip route add local 0.0.0.0/0 dev lo` so literal IP C2s hit the sink instead of `ENETUNREACH`
- HTTP/HTTPS sink on 80/443 returns **200 OK** (or `--stage-file`) and logs Host/URL/body; a sandbox CA is trusted by PHP `curl` / OpenSSL
- Catch-all TCP logger (iptables REDIRECT) records miners, SMTP, and reverse-shell ports (`tcp.jsonl`)
- tcpdump writes `traffic.pcap` on loopback
- Every eval dump is analysed as its own report layer (IOCs are merged). Stdout is the static cleanup of the **last** dump (or the original file if none). Surface signatures still come from the original packed file

Logs land in `./sandbox-logs/<timestamp-id>/`: `domains.txt`, `http.jsonl`, `tcp.jsonl`, `dns.log`, `php/eval-*.php`, `deobfuscated.php`, `indicators.json`, `report.json`, `cross-check.json`, `traffic.pcap`.

Requires Docker. The sample never gets a route to the public internet (`--network none`). That is still **malware execution inside the container** in `observe` mode — only use samples you intend to analyze.

### Supply chain (sandbox image)

- **evalhook** is **vendored** at a pinned commit under [`sandbox/php/vendor/php-eval-hook/`](sandbox/php/vendor/php-eval-hook/). The image **does not** `git clone` at build time. See [`sandbox/php/vendor/SOURCES.md`](sandbox/php/vendor/SOURCES.md) for the GitHub URL, commit, and archive SHA-256.
- **PHP** is not stored in git. The 8.3 Dockerfile uses `php:8.3-cli-bookworm@sha256:…` so the tag cannot drift. Docker still **pulls that digest once** if you do not already have it.
- Extra Debian packages (`dnsmasq`, `python3-cryptography`, `iptables`, …) are installed from apt on the first uncached build; they are not copied into this repo.

## Tests

```bash
pytest
pip install -e '.[dev]'   # pytest + Hypothesis
```

CI (`.github/workflows/test.yml`) runs the same suite. `tests/test_decode_fidelity.py` compares codecs against a real `php` CLI when it is on `PATH`. Hypothesis property tests for the string-literal scanner run when Hypothesis is installed.

## License

Evilbox is **dual-licensed**:

- **[GPL-3.0](LICENSE.GPL-3.0)** (copyleft) — personal use, research, education, and any use where you follow the GPL (including sharing source of derivatives).
- **[Commercial](LICENSE.COMMERCIAL)** (paid) — proprietary or closed-source products, paid services, and for-profit use without GPL obligations. You need a written agreement and payment from the copyright holder (Krasimir Konov). Contact via [the GitHub repo](https://github.com/KrasimirSec/evilbox).

See [LICENSE](LICENSE) for how the two paths work. Vendored php-eval-hook stays MIT.

This is not legal advice.
