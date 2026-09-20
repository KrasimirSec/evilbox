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
| `--max-passes N` | Unwrap/fold iterations (default: 8) |
| `--sandbox dump\|observe` | Isolated PHP Docker lab (JS files stay on the static path) |
| `--logs-dir PATH` | Sandbox log root (default: `EVILBOX_LOGS` or `./sandbox-logs`) |
| `--timeout N` | Sandbox PHP timeout in seconds (default: 15) |
| `serve` | Local web UI + JSON API for paste/upload decoding |

If the input is a directory, Evilbox walks `.js` / `.php` files, writes `*.clean.*` plus `*.report.json`, and a `clusters.json` map of similar inner-layer hashes.

`-o clean.js` also writes `clean.iocs.json` and `clean.report.json` unless `--report` is set.

Exit status `1` means the result still does not parse cleanly; the best-effort output is still written. Missing files, permission problems, and other failures print a short `error:` line (exit `2`) instead of a traceback. Set `EVILBOX_DEBUG=1` if you need the full stack.

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

The web path is **static only**: samples stay in memory for that request, are not written to disk, and are not executed. The PHP Docker sandbox (`--sandbox dump|observe`) stays CLI-only. Default limits are 2 MiB and 20 seconds (`EVILBOX_WEB_MAX_BYTES`, `EVILBOX_WEB_TIMEOUT`).

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

These are static (and sandbox-augmented) rules, not AV family names. Treat scores as hints and read the evidence.

## Reports

JSON schema id: `evilbox.report.v1`. Fields include:

- **sample** — path, language, SHA-256 of the original file, SHA-256 of the inner layer, `cluster_sha256` (whitespace-normalized inner code for clustering)
- **packer** — hints such as `eval+base64`, `fromCharCode`, `preg_replace/e`
- **layers** — original → unwrap passes → inner (sandbox eval dumps are their own layer)
- **roles** / **capabilities** — with evidence snippets
- **indicators** — URLs, domains, IPs, emails, files, paths, registry, APIs
- **indicators_by_layer** — the same IOCs tagged with the layer they appeared in
- **surface_signatures** — YARA-oriented needles from the **original** file only
- **sandbox** — present when `--sandbox` was used (log dir, DNS hosts, HTTP, eval dump names)

`--html` is the same data as a simple HTML page.

## Surface signatures

Inner decoded strings are **not** used for signature suggestions. A web scanner sees the packed file, not the unpacked payload.

From the original layer only, Evilbox collects:

- Decoder wrappers (`eval(base64_decode(…`, `String.fromCharCode(…`, `preg_replace` with `/e`, …)
- Long packed strings, including base64 blobs (a distinctive substring, not the full dump)
- Stable variable and function names that are not `_0x…` junk
- Distinctive comments

Each item has `kind`, `value`, a `yara` needle, and a short `why`.

## Unpacking

Still static: no JS/PHP engine.

- Unescape string literals (`\xNN`, `\uNNNN`, octal, HTML entities)
- Concatenate adjacent string literals (`+` in JS, `.` in PHP)
- Fold simple numeric/boolean constants (`1+2`, `!0`) and JS bitwise ops
- JS: `eval(atob(...))`, `unescape` / `decodeURIComponent`, `String.fromCharCode(...)` when arguments are literals; fold `name[i]` on constant arrays
- PHP: `eval` / `assert` / `create_function` / `preg_replace /e` / `include`/`require` of decoded payloads
- PHP: `base64_decode`, `gzinflate` / `gzuncompress` / `gzdecode`, `str_rot13`, `hex2bin`, `pack('H*', ...)`, string XOR, repeating-key `xor` / `rc4` when both arguments are constants, `chr` / `strtr` / `str_repeat`, `$arr[i]` folding
- Rename `_0x...` junk identifiers (and PHP `$` hex names of that form)

Not included: control-flow flattening, VM/dispatcher unpackers, or running a JavaScript engine.

## PHP sandbox (evalhook, no real internet)

Optional Docker lab for packed PHP. Each run **builds a throwaway image tag, starts a new container with `--network none`, then deletes the container and image tag**. The sample is mounted read-only. Nothing from the run is committed back into an image.

Inside the container:

- [php-eval-hook](https://github.com/extremecoders-re/php-eval-hook) dumps every `eval()`
- dnsmasq answers **every** DNS name with `127.0.0.1` (no upstream resolvers)
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

## License

Evilbox is **dual-licensed**:

- **[GPL-3.0](LICENSE.GPL-3.0)** (copyleft) — personal use, research, education, and any use where you follow the GPL (including sharing source of derivatives).
- **[Commercial](LICENSE.COMMERCIAL)** (paid) — proprietary or closed-source products, paid services, and for-profit use without GPL obligations. You need a written agreement and payment from the copyright holder (Krasimir Konov). Contact via [the GitHub repo](https://github.com/KrasimirSec/evilbox).

See [LICENSE](LICENSE) for how the two paths work. Vendored php-eval-hook stays MIT.

This is not legal advice.
