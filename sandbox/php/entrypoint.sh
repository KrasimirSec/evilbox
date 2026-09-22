#!/bin/sh
set -u
LOGS=/logs
mkdir -p "$LOGS/php" /tmp/ca /run
chmod 755 "$LOGS" 2>/dev/null || true
chmod 1777 "$LOGS/php" /tmp /run 2>/dev/null || true

MODE="${SANDBOX_MODE:-dump}"
printf '%s\n' "$MODE" > "$LOGS/mode"
chmod 644 "$LOGS/mode"

SINK_PID=""
TCP_PID=""
DUMP_PID=""
cleanup() {
  if [ -n "$SINK_PID" ]; then kill "$SINK_PID" 2>/dev/null || true; fi
  if [ -n "$TCP_PID" ]; then kill "$TCP_PID" 2>/dev/null || true; fi
  if [ -n "$DUMP_PID" ]; then kill "$DUMP_PID" 2>/dev/null || true; fi
  wait 2>/dev/null || true
}
trap cleanup EXIT

# Any destination IP hits loopback so literal C2s reach the sink.
ip route add local 0.0.0.0/0 dev lo 2>>"$LOGS/setup.log" || true

python3 /opt/sandbox/sink.py --init-ca --ca-dir /tmp/ca
# Root filesystem is read-only at run time; keep the trust bundle on tmpfs.
SYSTEM_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
if [ ! -f "$SYSTEM_BUNDLE" ]; then
  SYSTEM_BUNDLE="/etc/ssl/cert.pem"
fi
if [ -f "$SYSTEM_BUNDLE" ]; then
  cat "$SYSTEM_BUNDLE" /tmp/ca/ca.crt > /tmp/ca/bundle.crt 2>>"$LOGS/setup.log" || cp /tmp/ca/ca.crt /tmp/ca/bundle.crt
else
  cp /tmp/ca/ca.crt /tmp/ca/bundle.crt
fi
export SSL_CERT_FILE=/tmp/ca/bundle.crt
export CURL_CA_BUNDLE=/tmp/ca/bundle.crt
export REQUESTS_CA_BUNDLE=/tmp/ca/bundle.crt

printf 'nameserver 127.0.0.1\noptions ndots:0\n' > /etc/resolv.conf 2>>"$LOGS/setup.log" || \
  printf 'nameserver 127.0.0.1\noptions ndots:0\n' > /tmp/resolv.conf

dnsmasq --conf-file=/opt/sandbox/dnsmasq.conf 2>>"$LOGS/setup.log" || true
python3 /opt/sandbox/sink.py --serve --ca-dir /tmp/ca >>"$LOGS/sink.log" 2>&1 &
SINK_PID=$!
python3 /opt/sandbox/tcp_logger.py >>"$LOGS/tcp-logger.log" 2>&1 &
TCP_PID=$!
tcpdump -i lo -w "$LOGS/traffic.pcap" >/dev/null 2>>"$LOGS/setup.log" &
DUMP_PID=$!

# Redirect miner / SMTP / reverse-shell ports to the catch-all logger.
if command -v iptables >/dev/null 2>&1; then
  iptables -t nat -A OUTPUT -p tcp --dport 80 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp --dport 443 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp --dport 53 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp --dport 9999 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 9999 2>>"$LOGS/setup.log" || true
fi

i=0
while [ "$i" -lt 10 ]; do
  python3 -c "import socket; s=socket.create_connection(('127.0.0.1',80),1); s.close()" 2>/dev/null && break
  i=$((i + 1))
  sleep 0.2
done

SAMPLE="${1:-${SANDBOX_SAMPLE:-/samples/sample.php}}"
TIMEOUT="${SANDBOX_TIMEOUT:-15}"
echo "mode=${MODE} timeout=${TIMEOUT}s sample=${SAMPLE}" >>"$LOGS/setup.log"

PHP_UID=65534
chown -R "$PHP_UID:$PHP_UID" "$LOGS/php" 2>>"$LOGS/setup.log" || true

# Privileged helpers stay up. The sample runs unprivileged with no caps and
# without SANDBOX_* in its environment (putenv cannot redirect dumps).
if command -v setpriv >/dev/null 2>&1; then
  setpriv --reuid="$PHP_UID" --regid="$PHP_UID" --clear-groups --nnp \
    --inh-caps=-all --bounding-set=-all \
    env -u SANDBOX_MODE -u SANDBOX_LOGS -u SANDBOX_TIMEOUT -u SANDBOX_PROFILE -u SANDBOX_PHP_VERSION \
    LD_PRELOAD=/opt/sandbox/nosleep.so \
    SSL_CERT_FILE=/tmp/ca/bundle.crt CURL_CA_BUNDLE=/tmp/ca/bundle.crt \
    timeout -k 3 "$TIMEOUT" php "$SAMPLE" \
    >"$LOGS/php.stdout.log" 2>"$LOGS/php.stderr.log" || true
else
  env -u SANDBOX_MODE -u SANDBOX_LOGS -u SANDBOX_TIMEOUT -u SANDBOX_PROFILE -u SANDBOX_PHP_VERSION \
    LD_PRELOAD=/opt/sandbox/nosleep.so \
    SSL_CERT_FILE=/tmp/ca/bundle.crt CURL_CA_BUNDLE=/tmp/ca/bundle.crt \
    timeout -k 3 "$TIMEOUT" php "$SAMPLE" \
    >"$LOGS/php.stdout.log" 2>"$LOGS/php.stderr.log" || true
fi

python3 /opt/sandbox/collect_domains.py || true
