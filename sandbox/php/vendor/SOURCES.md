# Pinned sandbox sources

Do **not** `git clone` evalhook at build time. The extension in this directory is a snapshot of a known commit.

## php-eval-hook

| Field | Value |
| --- | --- |
| Upstream | https://github.com/extremecoders-re/php-eval-hook |
| Commit | `25e4e2a9b84b4f4c45f3d2dfa35121ed7938b889` (2023-10-13, merge of anti-evasion) |
| Archive | `https://github.com/extremecoders-re/php-eval-hook/archive/25e4e2a9b84b4f4c45f3d2dfa35121ed7938b889.tar.gz` |
| SHA-256 | `1a92f6ede3d97d9d5dff90ebad60bbd80625c0eabb42044e95cef13c2f52872d` |
| License | MIT (see `php-eval-hook/LICENSE`) |

Verify a re-download:

```bash
curl -fsSL -o /tmp/evalhook.tar.gz \
  https://github.com/extremecoders-re/php-eval-hook/archive/25e4e2a9b84b4f4c45f3d2dfa35121ed7938b889.tar.gz
shasum -a 256 /tmp/evalhook.tar.gz
# must match SHA256SUMS
```

## PHP base image

The official PHP runtime is **not** stored in git (hundreds of MB per arch). The Dockerfile pins a **digest** so `php:8.3-cli-bookworm` cannot silently move to another image:

`php:8.3-cli-bookworm@sha256:177529735599a8244b2c903522f029839dce1c2ac4be122fdc00ada4b45a20e4`

That index includes linux/amd64 and linux/arm64 (PHP 8.3.33). Docker Hub still has to **pull this digest once** if it is not already on the machine. Later builds use the local copy.

PHP 7.4 and 5.6 labs use the frozen upstream tags `php:7.4-cli-bullseye` (`Dockerfile.7.4`) and `php:5.6-cli` (`Dockerfile.5.6`). Both tags are multi-arch (amd64 + arm64). 7.4 still builds evalhook (PHP 7 `compile_string` ABI). 5.6 cannot: evalhook needs `zend_string`. That image still applies request profiles, WordPress stubs, and the sleep hook.

Debian 11 (bullseye) and older live security mirrors 404 after LTS. `debian-archive.sh` rewrites apt sources to `archive.debian.org` and disables `Valid-Until` so `apt-get install` works on Linux and on Docker Desktop for macOS. Bookworm (PHP 8.3) still uses the live mirrors, with apt retries.

To bump either pin: update this file, replace `vendor/php-eval-hook/` (and SHA256SUMS), and change the `FROM` digest in the Dockerfile after reviewing the new sources.
