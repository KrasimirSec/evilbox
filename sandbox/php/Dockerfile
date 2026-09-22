# Offline PHP 8.3.33 CLI sandbox. Every byte comes from this build context.
# `docker build --network=none` works. Do not FROM a registry image or apt-get.
FROM scratch
ARG TARGETARCH=amd64
ADD vendor/rootfs/php-8.3.33-cli-alpine-linux-${TARGETARCH}.tar.gz /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PHP_INI_DIR=/usr/local/etc/php \
    PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d
COPY php-sandbox.ini /usr/local/etc/php/conf.d/zz-sandbox.ini
COPY entrypoint.sh prepend.php wp-stubs.php sink.py collect_domains.py tcp_logger.py dnsmasq.conf /opt/sandbox/
RUN chmod +x /opt/sandbox/entrypoint.sh /opt/sandbox/sink.py /opt/sandbox/collect_domains.py /opt/sandbox/tcp_logger.py \
    && mkdir -p /logs /samples /tmp/ca /run
ENTRYPOINT ["/opt/sandbox/entrypoint.sh"]
