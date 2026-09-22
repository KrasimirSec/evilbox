# Evilbox

CLI that **statically** deobfuscates JavaScript and PHP, then helps with **analysis and classification**. It unwraps common encodings, rewrites the syntax tree, labels capabilities and malware roles, extracts IOCs, and suggests **scanner-visible** strings from the original packed file. `evilbox serve` exposes the same static path as a paste/upload web UI.

It does **not** execute the input in a JS or PHP engine. The optional Docker PHP sandbox is a separate, isolated lab (CLI only).

## Install

The Python environment lives in `.venv` and is created **automatically** the first time you run the tool. You do not activate it.

From this project folder:

```text
bin/evilbox
bin/evilbox serve
bin/evilbox packed.php --sandbox observe --logs-dir ./sandbox-logs --timeout 20
```

In the Cursor/VS Code terminal for this workspace, `bin` is prepended to `PATH`, so `evilbox` works the same way (no `bin/` prefix). New terminals pick that up.

If you use [direnv](https://direnv.net/), `direnv allow` in this directory does the same for any shell: `cd` here, then type `evilbox`.

## Usage

No arguments opens a small menu. Any extra arguments skip the menu:

```text
evilbox
evilbox serve
evilbox packed.js -o clean.js
evilbox packed.php --lang php
evilbox - --lang js < packed.js
evilbox packed.php --report report.json --html report.html
evilbox ./samples -o ./evilbox-out
evilbox packed.php --sandbox dump
evilbox packed.php --sandbox observe --logs-dir ./sandbox-logs --timeout 20
```

| Flag | Meaning |
| --- | --- |
| `--lang auto\|js\|php` | Language (default: `auto` from path and contents) |
| `-o PATH` | Write cleaned source to a file (or a directory when the input is a folder) |
| `--report PATH` | JSON report (`evilbox.report.v1`) |
| `--html PATH` | HTML report |
| `--max-passes N` | Unwrap/fold iterations (default: 16) |
| `--php-version 5.6\|7.4\|8.3` | PHP language dialect for `substr` and the sandbox image. Static folds default to 8.3; `--sandbox observe` defaults to 7.4 so `assert` strings, `create_function`, and `preg_replace /e` still run |
| `--sandbox dump\|observe` | Isolated PHP Docker lab (JS files stay on the static path) |
| `--sandbox-profile default\|googlebot\|google-referrer\|wp-cookie` | Request shape inside the sandbox |
| `--keep-name` | Mount the sample under its original filename inside the sandbox |
| `--stage-file PATH` | Bytes the sandbox HTTP/HTTPS sink serves instead of `OK` (second-stage replay) |
| `--logs-dir PATH` | Sandbox log root (default: `EVILBOX_LOGS` or `./sandbox-logs`) |
| `--timeout N` | Sandbox PHP timeout in seconds (default: 15) |
| `serve` | Local web UI + JSON API for paste/upload decoding |

If the input is a directory, Evilbox walks `.js` / `.php` files and mirrors the relative layout under the output directory (`a/index.php` and `b/index.php` become `a/index.clean.php` and `b/index.clean.php`). Each file is decoded in isolation: a crash in one sample does not abort the batch. `clusters.json` groups similar inner layers with a token n-gram minhash (so a changed domain or key still groups a family). `cluster_sha256` remains an exact whitespace-normalized hash of the inner text.

`-o clean.js` also writes `clean.iocs.json` and `clean.report.json` unless `--report` is set.

Exit status `1` means the result still does not parse cleanly **or** decoder folds remain unresolved on the inner layer (for example a leftover `gzinflate` or a recovered `convert_uudecode`). The best-effort output is still written. Missing files, permission problems, and other failures print a short `error:` line (exit `2`) instead of a traceback. Set `EVILBOX_DEBUG=1` if you need the full stack.

## Web decoder

`evilbox serve` starts a small HTTP server (stdlib only) so anyone can paste source or upload a `.js` / `.php` file and get the same static decode + report the CLI produces.

```text
evilbox serve
evilbox serve --host 127.0.0.1 --port 8080 --open
```

Open `http://127.0.0.1:8080/`. Bind `--host 0.0.0.0` only if you intend other machines to reach it.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Browser UI |
| `GET` | `/health` | Liveness (`sandbox` is always `false`) |
| `GET` | `/api/examples` | Built-in demo samples |
| `POST` | `/api/decode` | Decode a sample |

POST body:

- JSON `{"source":"...","lang":"auto|js|php","filename":"optional.php"}`
- raw `text/plain` (language via `?lang=php`)
- `multipart/form-data` with a `file` field

```text
curl -s -X POST http://127.0.0.1:8080/api/decode \
  -H 'Content-Type: application/json' \
  -d '{"source":"<?php eval(base64_decode('"'"'ZWNobyAiaGkiOw=='"'"'));","lang":"php"}'

curl --data-binary @packed.php -H 'Content-Type: text/plain' \
  'http://127.0.0.1:8080/api/decode?lang=php&filename=packed.php'
```

The web path is **static only**: samples stay in memory for that request, are not written to disk, and are not executed. The header badge **Not executed** is that guarantee, not a failed run. The PHP Docker sandbox (`--sandbox dump|observe`) stays CLI-only. Default limits are 2 MiB and 20 seconds (`EVILBOX_WEB_MAX_BYTES`, `EVILBOX_WEB_TIMEOUT`). Each decode runs in a **subprocess** with CPU/address rlimits; a hang is killed with SIGKILL (a worker thread cannot interrupt a catastrophic regex). The UI is same-origin: there is no `Access-Control-Allow-Origin: *`.

The no-argument menu also has **Open the web decoder**.

## Classification

Roles are **multi-label** and evidence-backed. A sample can be a webshell and a mailer at the same time. Each role includes a score and snippets (layer + short excerpt).

| Role | Typical evidence |
| --- | --- |
| `webshell` | `eval` / `assert` / `create_function` / `preg_replace /e` or OS exec, plus `$_GET` / `$_POST` / `$_COOKIE` / … |
| `backdoor` | Outbound HTTP/sockets plus eval, exec, or persistence |
| `dropper` | File write plus network, or a URL that drops `.exe` / `.dll` / `.ps1` / … |
| `injector` | Remote/dynamic `include`/`require`, or eval plus file write |
| `seo-spam` | Hidden links, `googlebot` / `bingbot` checks, WordPress post injection |
| `mailer` | `mail()` / PHPMailer / SMTP |
| `stealer` | Credential/cookie/wallet harvest plus read or exfil |
| `phishing-kit` | Brand/OTP lures plus credential collection or file write |
| `cryptominer` | stratum / xmrig / miner pools |
| `wiper` | `unlink` / `rmdir` without webshell-style eval + superglobals |

Capabilities behind those labels include `eval-runtime`, `exec`, `superglobals`, `fs-write`, `fs-read`, `fs-delete`, `net-egress`, `persist`, `seo-inject`, `mail`, `credential-harvest`, `miner`, `phishing`, `payload-drop`, and `include-remote`.

These are static (and sandbox-augmented) rules, not AV family names. Treat scores as hints and read the evidence. Matching is done on **call nodes** in the parse tree, not raw text, so strings and comments (a WordPress `<input type="password">`, a cache plugin's `file_get_contents` of a local file) do not become stealers or droppers. `file_get_contents` is file-read unless the argument is a URL.

## Reports

JSON schema id: `evilbox.report.v1`. Fields include:

- **sample** — path, language, SHA-256 of the original file, SHA-256 of the inner layer, `cluster_sha256` (exact normalized inner code), `cluster_minhash` (structure minhash for fuzzy families)
- **packer** — hints such as `eval+base64`, `fromCharCode`, `preg_replace/e`
- **layers** — original → unwrap passes → inner (every sandbox eval dump is its own layer). Each layer lists `unresolved_folds`
- **unresolved_folds** — decoder/packer/dispatch calls that did not simplify, grouped per layer; remote loader URLs are unresolved stages
- **encoded_not_analyzable** — ionCube, Zend Guard, or SourceGuardian headers (`encoded, not analyzable`)
- **failed_folds** — true when the inner layer still has decoder/packer leftovers
- **roles** / **capabilities** — with evidence snippets
- **indicators** — campaign-oriented IOCs from every layer (and sandbox DNS/HTTP/TCP when used): URLs, domains, IPv4/IPv6, `host:port` endpoints, `.onion`, emails, URL paths, query keys, PHP `$_GET`/`$_POST`/`$_COOKIE`/`$_REQUEST` parameter names, HTTP methods, user-agents, paste sites, Telegram bots, Discord/Slack webhooks, BTC/ETH/XMR wallets, cloud tokens (AWS/GitHub/Google/Slack/Stripe), JWTs, PEM private-key markers, assigned crypto keys, MD5/SHA1/SHA256 literals, UUIDs, CVEs, mutexes, named pipes, files, Windows/UNC and Unix paths, registry keys, PDB paths, cookies, cron lines, stratum miners, and distinctive APIs
- **indicators_by_layer** — the same IOCs tagged with the layer they appeared in (`sandbox` for observed traffic)
- **correlation** — ATT&CK technique tags derived from capabilities/roles, typed `campaign_keys` (`domain:…`, `wallet:btc:…`, `mutex:…`, …) for joining samples, plus grouped pivots (network / identities / secrets / artifacts / behaviors) and cluster hashes
- **surface_signatures** — full YARA rule plus PCRE needles from the **original** file only
- **sandbox** — present when `--sandbox` was used (log dir, DNS hosts, HTTP/TCP, eval dump names, php version, request profile). Observed traffic is merged into `indicators` and tagged as layer `sandbox`
- **sandbox_cross_check** — static inner layer vs sandbox eval-dump layer; disagreements are flagged

`--html` is the same data as a simple HTML page.

## Surface signatures

Inner decoded strings are **not** used for signature suggestions. A web scanner sees the packed file, not the unpacked payload.

From the original layer only, Evilbox collects:

- Decoder wrappers (`eval(base64_decode(…`, `String.fromCharCode(…`, `preg_replace` with `/e`, …)
- Long packed strings, including base64 blobs (a distinctive substring, not the full dump)
- Stable variable and function names that are not `_0x…` junk
- Distinctive comments

Each item has `kind`, `value`, a `yara` needle, a `pcre` pattern, and a short `why`. The report also includes a complete YARA `rule` (`yara_rule`) whose strings are those needles. Those rules are tested against a small clean WordPress plugin/theme corpus under `tests/corpus/wordpress_benign/`.

## Unpacking

Still static: no JS/PHP engine. Nested codec expressions fold in one pass when every function is implemented; leftover `eval` wrappers iterate up to 16 times (configurable).

**Encoding and compression**

- Unescape string literals (`\xNN`, `\uNNNN`, octal, HTML entities) in JS (both quote styles) and PHP double quotes
- Whole-file hex dumps, `\xHH` / `\uHHHH` streams, `hex2bin` / `pack('H*')` / `unpack('H*')`, `Buffer.from(..., 'hex')`, `unescape('%uXXXX')`
- PHP: `base64_decode`, `gzinflate` / `gzuncompress` / `gzdecode`, `bzdecompress`, `str_rot13`, `strrev`, `urldecode` / `rawurldecode`, `convert_uudecode`, `quoted_printable_decode`
- Nested chains such as `eval(gzinflate(base64_decode(str_rot13(...))))`
- String XOR and repeating-key `xor` / `rc4` when the key is a constant in the same file
- Repeating-XOR `for` loops of the form `$out .= chr(ord($data[$i]) ^ ord($key[$i % K]))` followed by `eval` / `assert` / `print` of `gzinflate` / `base64_decode` / similar
- Quoted `print` / `echo` of a string that is itself `eval(gzinflate(base64_decode(...)))`
- Custom `hex2ascii` / hex-blob wrappers (`$p = '24617574…'; print(hex2ascii($p))`)
- `chr` / `ord` chains, `sprintf` / `implode` / `str_replace` / `substr` / `strtr`

**Packers and character encodings**

- Dean Edwards `p.a.c.k.e.r.` (`eval(function(p,a,c,k,e,d)…`), including nested layers
- javascript-obfuscator / obfuscator.io / sojson / jsjiami string-array + rotator + index decoder, including base64, RC4, and hex array encodings
- JSFuck (`[]()!+`) Function-constructor payloads, percent-encoded bookmarklets, jjencode, and a best-effort AAEncode unwrap
- Split identifiers: `$f = "bas"."e64"."_dec"."ode"` and `$f .= ...` / JS `"at"+"ob"` / `window['at'+'ob']`
- PHP charset-table indexes such as `$fn = $s[41].$s[16].…` used as `preg_replace /e` / `create_function` names
- PHP PAS-family cookie/POST autokey (`md5($p).substr(md5(strrev($p)),0,strlen($p))`, byte subtract, `gzinflate`, `create_function`). A small list of common webshell passwords is tried; the recovered key is reported

**Dynamic execution (static splice when the callback and payload are constants)**

- PHP: `eval`, `assert`, `create_function`, `preg_replace /e`, `call_user_func` / `call_user_func_array`, `register_shutdown_function`, `ob_start`, `array_map` / `array_filter` / `array_walk` / `usort`, variable functions, variable variables (`$$a`), function names stored in arrays
- JS: `Function` / `new Function`, `setTimeout` / `setInterval` with a string, `eval.call`, computed `window['atob']`. Leftover Dean Edwards / JSFuck / JJEncode / AAEncode and `setTimeout("...")` are reported as unresolved stages. Remote loader URLs (pastebin, GitHub, Telegram, CDN, …) are unresolved stages, not decoded.

**Layout and junk**

- Collapse huge blank-line / space runs
- Extract `__halt_compiler()` trailers (hex / base64 / zlib when they decode)
- Fold `file_get_contents(__FILE__)` / `__DIR__` sibling payloads when the extra file is next to the sample
- Rename `_0x…`, lookalike `O0Il` names, long underscore names, and non-ASCII identifier homoglyphs

**Detected, not decoded** (need a missing key, another file, or a network/runtime): XOR/RC4 keys in cookies, POST, or a second file that is not next to the sample (PAS cookie autokey is unwrapped when the password is a common webshell key); EXIF / fake images / `.htaccess` `auto_prepend_file` / database options; request-driven shells with no payload; DNS TXT, blockchain, Telegram, pastebin, or CDN-fetched bodies; referrer/UA/geo cloaking; self-defending `debugger` traps; domain locks; full control-flow flattening / VM unpackers; **ionCube / Zend Guard / SourceGuardian** bytecode (`encoded, not analyzable`).

`gzinflate` / `gzuncompress` / `gzdecode` / `bzdecompress` output is capped at 2 MiB. Incomplete streams are refused (no unbounded `flush()`).

PHP constant folding is **assigned-once per function**, matching the JS `assign_count` rule. A later `$a = 'strrev'` does not rewrite an earlier `$a('aGVsbG8=')`. Straight-line `$s .= ...` / JS `s += ...` chains fold; assignments inside `for` / `foreach` / `while` or `if` / `switch` do not. Variables touched by `global`, references, `extract`, `compact`, `parse_str`, or `foreach` are skipped.

Codecs that model PHP strings (`~`, XOR, `stripslashes`, `substr`, `strrev`, `ord`, `strtr`, `strtoupper`) treat values as **bytes** (latin-1). Characters above U+00FF are an error, not replaced with `?`. HTML entities that unescape outside latin-1 (`&rsquo;`, `&inodot;`) are left as entities so a rewrite cannot emit non-byte text. `scan_unresolved` and other AST walks encode the file the same way it was parsed (latin-1 for 8-bit PHP). `convert_uudecode` line-padding retries are marked **recovered**. `substr` past the end of the string follows the selected `--php-version` (empty string on PHP 8, `false` on PHP 5/7). Integer-looking floats stringify as PHP does (`6.0` → `6`). Shifts of 63 bits or more, and integers wider than 256 bits, are left unfolded.

Not included: running a JavaScript or PHP engine over HTTP. The optional Docker sandbox remains CLI-only.

## PHP sandbox (evalhook, no real internet)

Optional Docker lab for packed PHP. Each run **builds a throwaway image tag, starts a new container with `--network none`, `--read-only`, `--cap-drop ALL` plus the setup caps (`NET_ADMIN`, `NET_RAW`, `NET_BIND_SERVICE`, …), `--security-opt no-new-privileges`, `--memory 512m`, `--cpus 1`, `--pids-limit 128`**. Docker’s default seccomp profile stays enabled. If a `runsc` (gVisor) runtime is installed it is used. The sample is bind-mounted read-only. **Logs are not bind-mounted.** After the process exits, the host copies `/logs` with `docker cp` and **rejects symlinks** before reading or writing `domains.txt` / `deobfuscated.php`. The PHP sample runs as uid 65534 with capabilities dropped; dnsmasq, tcpdump, and the HTTP sink start first as root. Nothing from the run is committed back into an image.

`--php-version 8.3`, `7.4`, or `5.6` selects the Dockerfile. Observe mode defaults to **7.4** so string `assert`, `create_function`, and `preg_replace /e` still execute. 8.3 and 7.4 compile evalhook; 5.6 cannot (no `zend_string`) and is observe/stub-only.

`--sandbox-profile` sets the request the sample sees: `googlebot` (Googlebot UA), `google-referrer`, or `wp-cookie` (WordPress login cookies). WordPress function stubs are prepended. `sleep` / `usleep` / `nanosleep` are hooked to return immediately (LD_PRELOAD, PHP process only). `--keep-name` preserves the sample basename inside `/samples`. `--stage-file` is served by the sink instead of `OK`.

Inside the container:

- [php-eval-hook](https://github.com/extremecoders-re/php-eval-hook) dumps every `eval()` to `/logs/php` (path is hardcoded; `putenv('SANDBOX_LOGS')` cannot redirect it)
- `SANDBOX_MODE` / `SANDBOX_LOGS` are **not** in the PHP process environment
- dnsmasq answers **every** DNS name with `127.0.0.1` (no upstream resolvers)
- `ip route add local 0.0.0.0/0 dev lo` so literal IP C2s hit the sink instead of `ENETUNREACH`
- an HTTP/HTTPS sink returns **200 OK** (or `--stage-file`) and logs Host/URL/body
- a catch-all TCP logger (iptables REDIRECT) records miners, SMTP, and reverse-shell ports
- a **sandbox CA** is generated at start and trusted by PHP `curl` / OpenSSL so HTTPS still completes
- tcpdump writes `traffic.pcap` on loopback
- every eval dump is analysed as its own report layer (IOCs are merged)
- an HTTP/HTTPS sink returns **200 OK** and logs Host/URL/body
- a **sandbox CA** is generated at start and trusted by PHP `curl` / OpenSSL so HTTPS still completes
- tcpdump writes `traffic.pcap` on loopback

| Mode | Behavior |
| --- | --- |
| `dump` | Log eval payloads and **do not** execute them |
| `observe` | Log eval payloads **and** let the script run (requests hit the fake sink) |

Logs land in `./sandbox-logs/<timestamp-id>/` (`domains.txt`, `http.jsonl`, `dns.log`, `eval-*.php`, `deobfuscated.php`, `indicators.json`, `report.json`, `traffic.pcap`). Stdout is the static cleanup of the last eval dump (or the original file if none). Classification still uses the **original** file for surface signatures.

Requires Docker. The sample never gets a route to the public internet (`--network none`). That is still **malware execution inside the container** in `observe` mode — only use samples you intend to analyze.

### Supply chain (sandbox image)

- **evalhook** is **vendored** at a pinned commit under [`sandbox/php/vendor/php-eval-hook/`](sandbox/php/vendor/php-eval-hook/). The image **does not** `git clone` at build time. See [`sandbox/php/vendor/SOURCES.md`](sandbox/php/vendor/SOURCES.md) for the GitHub URL, commit, and archive SHA-256.
- **PHP** is not stored in git. The Dockerfile uses `php:8.3-cli-bookworm@sha256:…` so the tag cannot drift. Docker still **pulls that digest once** if you do not already have it.
- Extra Debian packages (`dnsmasq`, `python3-cryptography`, …) are still installed from apt on the first uncached build; they are not copied into this repo.

## Tests

```bash
pytest
```

CI runs the same suite, including the PHP differential probes in `tests/test_decode_fidelity.py` when `php` is on PATH, and Hypothesis property tests when the extra is installed (`pip install -e '.[dev]'`).

## License

Evilbox is **dual-licensed**:

- **[GPL-3.0](LICENSE.GPL-3.0)** (copyleft) — personal use, research, education, and any use where you follow the GPL (including sharing source of derivatives).
- **[Commercial](LICENSE.COMMERCIAL)** (paid) — proprietary or closed-source products, paid services, and for-profit use without GPL obligations. You need a written agreement and payment from the copyright holder (Krasimir Konov). Contact via [the GitHub repo](https://github.com/KrasimirSec/evilbox).

See [LICENSE](LICENSE) for how the two paths work. Vendored php-eval-hook stays MIT.

This is not legal advice.
