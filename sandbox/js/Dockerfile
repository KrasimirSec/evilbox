# JavaScript browser sandbox. First build installs Chromium from Debian
# (too large to vendor in git). Later runs reuse the tagged image.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    CHROME_BIN=/usr/bin/chromium

RUN printf 'Acquire::Retries "5";\n' > /etc/apt/apt.conf.d/99retries \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        chromium \
        chromium-common \
        fonts-dejavu-core \
        fonts-liberation \
        dnsmasq \
        iproute2 \
        iptables \
        openssl \
        python3 \
        tcpdump \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY php/sink.py php/tcp_logger.py php/collect_domains.py php/dnsmasq.conf /opt/sandbox/
COPY js/entrypoint.sh js/visit.py js/front.py js/wrap.py js/stealth.js js/hook.js js/site.css /opt/sandbox/
RUN chmod +x /opt/sandbox/entrypoint.sh /opt/sandbox/visit.py /opt/sandbox/front.py \
        /opt/sandbox/sink.py /opt/sandbox/tcp_logger.py /opt/sandbox/collect_domains.py \
    && mkdir -p /logs /samples /tmp/ca /run /tmp/chrome

ENTRYPOINT ["/opt/sandbox/entrypoint.sh"]
