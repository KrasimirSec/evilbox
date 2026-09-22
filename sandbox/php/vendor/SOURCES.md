# Pinned sandbox sources

Do **not** `git clone` evalhook at build time. The extension in this directory is a snapshot of a known commit, compiled into the offline rootfs tarballs.

## php-eval-hook

| Field | Value |
| --- | --- |
| Upstream | https://github.com/extremecoders-re/php-eval-hook |
| Commit | `25e4e2a9b84b4f4c45f3d2dfa35121ed7938b889` (2023-10-13, merge of anti-evasion) |
| Archive | `https://github.com/extremecoders-re/php-eval-hook/archive/25e4e2a9b84b4f4c45f3d2dfa35121ed7938b889.tar.gz` |
| SHA-256 | `1a92f6ede3d97d9d5dff90ebad60bbd80625c0eabb42044e95cef13c2f52872d` |
| License | MIT (see `php-eval-hook/LICENSE`) |

`php-eval-hook/evalhook.c` includes a PHP 7.4 `zend_compile_string(zval *, char *)` hook. Upstream's `#else` branch used the PHP 8 `zend_string` prototype, which does not match 7.4.

Verify a re-download of the upstream snapshot:

```bash
curl -fsSL -o /tmp/evalhook.tar.gz \
  https://github.com/extremecoders-re/php-eval-hook/archive/25e4e2a9b84b4f4c45f3d2dfa35121ed7938b889.tar.gz
shasum -a 256 /tmp/evalhook.tar.gz
# must match SHA256SUMS (php-eval-hook archive line)
```

## Offline PHP rootfs (8.3 and 7.4)

`docker build --network=none` ADDs a pre-built Alpine rootfs. Nothing is pulled from Docker Hub, php.net, or apk mirrors.

| Tarball | PHP | Arch | Upstream image manifest |
| --- | --- | --- | --- |
| `rootfs/php-8.3.33-cli-alpine-linux-amd64.tar.gz` | 8.3.33 | linux/amd64 | `php:8.3.33-cli-alpine` `sha256:6443da203cc731224936b7e842971f0067a596d60839144650ca5c11a2f3c98f` |
| `rootfs/php-8.3.33-cli-alpine-linux-arm64.tar.gz` | 8.3.33 | linux/arm64 | `php:8.3.33-cli-alpine` `sha256:989d2bdaa98bcebcecd07604a1afd9c6659d4b874ab874b75e849a622399c872` |
| `rootfs/php-7.4.33-cli-alpine-linux-amd64.tar.gz` | 7.4.33 | linux/amd64 | `php:7.4.33-cli-alpine` `sha256:1e1b3bb4ee1bcb039f559adb9a3fae391c87205ba239b619cdc239b78b7f2557` |
| `rootfs/php-7.4.33-cli-alpine-linux-arm64.tar.gz` | 7.4.33 | linux/arm64 | `php:7.4.33-cli-alpine` `sha256:dbce323a8fd856cbd383920374bf9815c2f6503746ceb12e86ca3ec07545160a` |

Each archive is the official CLI image plus Alpine packages (`python3`, `dnsmasq`, `tcpdump`, `iproute2`, `iptables`, `util-linux`, `ca-certificates`, `coreutils`, `openssl`, …) and precompiled `evalhook.so` + `nosleep.so`. SHA-256 digests are in `SHA256SUMS`.

Refresh (needs network, not used by `docker build`):

```bash
python3 sandbox/php/vendor/pack-rootfs.py
```

## PHP 5.6

`Dockerfile.5.6` still uses `FROM php:5.6-cli` and archived Debian packages. It is not offline. evalhook cannot compile there (`zend_string`). Prefer 8.3 or 7.4.

To bump the 8.3/7.4 pins: update this file, re-run `pack-rootfs.py`, replace `vendor/php-eval-hook/` if the evalhook commit changes, and confirm SHA256SUMS.
