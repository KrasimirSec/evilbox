#!/bin/bash
set -u
LOGS="${SANDBOX_LOGS:-/logs}"
mkdir -p "$LOGS" /tmp/ca
export SANDBOX_LOGS="$LOGS"

cleanup() {
  kill $(jobs -p) 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

python3 /opt/sandbox/sink.py --init-ca --ca-dir /tmp/ca
cp /tmp/ca/ca.crt /usr/local/share/ca-certificates/sandbox-ca.crt
update-ca-certificates >/dev/null 2>>"$LOGS/setup.log" || true
# Also trust the CA for this process tree (PHP curl / openssl).
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

printf 'nameserver 127.0.0.1\noptions ndots:0\n' > /etc/resolv.conf

dnsmasq --conf-file=/opt/sandbox/dnsmasq.conf 2>>"$LOGS/setup.log" || true
python3 /opt/sandbox/sink.py --serve --ca-dir /tmp/ca >>"$LOGS/sink.log" 2>&1 &
tcpdump -i lo -w "$LOGS/traffic.pcap" >/dev/null 2>>"$LOGS/setup.log" &

# Wait until the sink answers on :80
for _ in 1 2 3 4 5 6 7 8 9 10; do
  python3 -c "import socket; s=socket.create_connection(('127.0.0.1',80),1); s.close()" 2>/dev/null && break
  sleep 0.2
done

SAMPLE="${1:-/samples/sample.php}"
TIMEOUT="${SANDBOX_TIMEOUT:-15}"
echo "mode=${SANDBOX_MODE:-dump} timeout=${TIMEOUT}s sample=${SAMPLE}" >>"$LOGS/setup.log"

timeout --kill-after=3s "${TIMEOUT}s" \
  env LD_PRELOAD=/opt/sandbox/nosleep.so php "$SAMPLE" \
  >"$LOGS/php.stdout.log" 2>"$LOGS/php.stderr.log" || true

python3 /opt/sandbox/collect_domains.py || true
