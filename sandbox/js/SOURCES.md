# JavaScript browser sandbox

The image installs Debian `chromium` at **build** time. Chromium is hundreds of MB and is **not** stored in git (GitHub’s 100 MiB file cap). The first `evilbox *.js --sandbox observe` therefore needs network once; later runs reuse `evilbox-js-sandbox:<hash>`.

PHP 8.3/7.4 remain fully offline (`sandbox/php/vendor/rootfs/`).

| Piece | Source |
| --- | --- |
| Base | `debian:bookworm-slim` |
| Browser | Debian `chromium` (bookworm) |
| Sink / DNS / pcap | same scripts as the PHP lab (`php/sink.py`, `dnsmasq.conf`, …) |

The visit is a real Chromium document: HTTPS origin on the spoofed host, Google-style referrer click-through, `navigator.webdriver` hidden. The sample still has **no route off the box** (`docker run --network none`); call-home hits the sink.
