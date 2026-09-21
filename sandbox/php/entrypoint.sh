#!/bin/bash
set -u
LOGS=/logs
mkdir -p "$LOGS/php" /tmp/ca /run
chmod 755 "$LOGS" 2>/dev/null || true
chmod 1777 "$LOGS/php" /tmp /run 2>/dev/null || true

MODE="${SANDBOX_MODE:-dump}"
printf '%s\n' "$MODE" > "$LOGS/mode"
chmod 644 "$LOGS/mode"

cleanup() {
  kill $(jobs -p) 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

# Any destination IP hits loopback so literal C2s reach the sink.
ip route add local 0.0.0.0/0 dev lo 2>>"$LOGS/setup.log" || true

python3 /opt/sandbox/sink.py --init-ca --ca-dir /tmp/ca
cp /tmp/ca/ca.crt /usr/local/share/ca-certificates/sandbox-ca.crt 2>>"$LOGS/setup.log" || true
update-ca-certificates >/dev/null 2>>"$LOGS/setup.log" || true
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

printf 'nameserver 127.0.0.1\noptions ndots:0\n' > /etc/resolv.conf

dnsmasq --conf-file=/opt/sandbox/dnsmasq.conf 2>>"$LOGS/setup.log" || true
python3 /opt/sandbox/sink.py --serve --ca-dir /tmp/ca >>"$LOGS/sink.log" 2>&1 &
python3 /opt/sandbox/tcp_logger.py >>"$LOGS/tcp-logger.log" 2>&1 &
tcpdump -i lo -w "$LOGS/traffic.pcap" >/dev/null 2>>"$LOGS/setup.log" &

# Redirect miner / SMTP / reverse-shell ports to the catch-all logger.
if command -v iptables >/dev/null 2>&1; then
  iptables -t nat -A OUTPUT -p tcp --dport 80 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp --dport 443 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp --dport 53 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp --dport 9999 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 9999 2>>"$LOGS/setup.log" || true
fi

for _ in 1 2 3 4 5 6 7 8 9 10; do
  python3 -c "import socket; s=socket.create_connection(('127.0.0.1',80),1); s.close()" 2>/dev/null && break
  sleep 0.2
done

SAMPLE="${1:-${SANDBOX_SAMPLE:-/samples/sample.php}}"
TIMEOUT="${SANDBOX_TIMEOUT:-15}"
echo "mode=${MODE} timeout=${TIMEOUT}s sample=${SAMPLE}" >>"$LOGS/setup.log"

PHP_UID=65534
chown -R "$PHP_UID:$PHP_UID" "$LOGS/php" 2>>"$LOGS/setup.log" || true

# Privileged helpers stay up. The sample runs unprivileged with no caps and
# without SANDBOX_* in its environment (putenv cannot redirect dumps).
run_php() {
  env -u SANDBOX_MODE -u SANDBOX_LOGS -u SANDBOX_TIMEOUT -u SANDBOX_PROFILE -u SANDBOX_PHP_VERSION \
    LD_PRELOAD=/opt/sandbox/nosleep.so \
    timeout --kill-after=3s "${TIMEOUT}s" php "$SAMPLE"
}

if command -v setpriv >/dev/null 2>&1; then
  setpriv --reuid="$PHP_UID" --regid="$PHP_UID" --clear-groups --nnp \
    --inh-caps=-all --bounding-set=-all \
    env -u SANDBOX_MODE -u SANDBOX_LOGS -u SANDBOX_TIMEOUT -u SANDBOX_PROFILE -u SANDBOX_PHP_VERSION \
    LD_PRELOAD=/opt/sandbox/nosleep.so \
    timeout --kill-after=3s "${TIMEOUT}s" php "$SAMPLE" \
    >"$LOGS/php.stdout.log" 2>"$LOGS/php.stderr.log" || true
else
  runuser -u nobody -- env -u SANDBOX_MODE -u SANDBOX_LOGS \
    LD_PRELOAD=/opt/sandbox/nosleep.so \
    timeout --kill-after=3s "${TIMEOUT}s" php "$SAMPLE" \
    >"$LOGS/php.stdout.log" 2>"$LOGS/php.stderr.log" || true
fi

python3 /opt/sandbox/collect_domains.py || true
