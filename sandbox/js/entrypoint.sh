#!/bin/sh
set -u
LOGS=/logs
mkdir -p "$LOGS/php" "$LOGS/downloads" /tmp/ca /tmp/chrome /run
chmod 755 "$LOGS" 2>/dev/null || true
chmod 1777 "$LOGS/php" "$LOGS/downloads" /tmp /run /tmp/chrome 2>/dev/null || true

MODE="${SANDBOX_MODE:-observe}"
printf '%s\n' "$MODE" > "$LOGS/mode"
chmod 644 "$LOGS/mode"

FRONT_PID=""
TCP_PID=""
DUMP_PID=""
cleanup() {
  if [ -n "$FRONT_PID" ]; then kill "$FRONT_PID" 2>/dev/null || true; fi
  if [ -n "$TCP_PID" ]; then kill "$TCP_PID" 2>/dev/null || true; fi
  if [ -n "$DUMP_PID" ]; then kill "$DUMP_PID" 2>/dev/null || true; fi
  wait 2>/dev/null || true
}
trap cleanup EXIT

ip route add local 0.0.0.0/0 dev lo 2>>"$LOGS/setup.log" || true
ip -6 route add local ::/0 dev lo 2>>"$LOGS/setup.log" || true
export HOME=/tmp
export XDG_CONFIG_HOME=/tmp
export XDG_CACHE_HOME=/tmp

python3 /opt/sandbox/front.py --init-ca --ca-dir /tmp/ca
SYSTEM_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
if [ -f "$SYSTEM_BUNDLE" ]; then
  cat "$SYSTEM_BUNDLE" /tmp/ca/ca.crt > /tmp/ca/bundle.crt 2>>"$LOGS/setup.log" || cp /tmp/ca/ca.crt /tmp/ca/bundle.crt
else
  cp /tmp/ca/ca.crt /tmp/ca/bundle.crt
fi
export SSL_CERT_FILE=/tmp/ca/bundle.crt
export CURL_CA_BUNDLE=/tmp/ca/bundle.crt

printf 'nameserver 127.0.0.1\noptions ndots:0\n' > /etc/resolv.conf 2>>"$LOGS/setup.log" || true

dnsmasq --conf-file=/opt/sandbox/dnsmasq.conf 2>>"$LOGS/setup.log" || true
python3 /opt/sandbox/front.py --serve --ca-dir /tmp/ca >>"$LOGS/sink.log" 2>&1 &
FRONT_PID=$!
python3 /opt/sandbox/tcp_logger.py >>"$LOGS/tcp-logger.log" 2>&1 &
TCP_PID=$!
tcpdump -i lo -w "$LOGS/traffic.pcap" >/dev/null 2>>"$LOGS/setup.log" &
DUMP_PID=$!

if command -v iptables >/dev/null 2>&1; then
  iptables -t nat -A OUTPUT -p tcp --dport 80 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp --dport 443 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp --dport 53 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp --dport 9222 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp --dport 9999 -j RETURN 2>>"$LOGS/setup.log" || true
  iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 9999 2>>"$LOGS/setup.log" || true
fi

i=0
while [ "$i" -lt 25 ]; do
  python3 -c "import socket; s=socket.create_connection(('127.0.0.1',443),1); s.close()" 2>/dev/null && break
  i=$((i + 1))
  sleep 0.2
done

echo "mode=${MODE} timeout=${SANDBOX_TIMEOUT:-20}s host=${SANDBOX_HOST:-} sample=${SANDBOX_SAMPLE:-}" >>"$LOGS/setup.log"

python3 /opt/sandbox/visit.py >>"$LOGS/visit.log" 2>&1 || true

python3 /opt/sandbox/collect_domains.py || true
