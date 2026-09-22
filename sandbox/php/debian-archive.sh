#!/bin/sh
# Debian 11 (bullseye) and older are on archive.debian.org after LTS.
# Live deb.debian.org/debian-security still serves InRelease but 404s the
# .deb files (amd64 Linux and arm64 Docker Desktop on macOS).
set -eu

rewrite() {
  _file=$1
  [ -f "$_file" ] || return 0
  sed -i \
    -e 's|https://deb.debian.org/debian|http://archive.debian.org/debian|g' \
    -e 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g' \
    -e 's|https://security.debian.org|http://archive.debian.org/debian-security|g' \
    -e 's|http://security.debian.org|http://archive.debian.org/debian-security|g' \
    -e 's|https://cdn-aws.deb.debian.org/debian|http://archive.debian.org/debian|g' \
    -e 's|http://cdn-aws.deb.debian.org/debian|http://archive.debian.org/debian|g' \
    "$_file"
}

rewrite /etc/apt/sources.list
if [ -d /etc/apt/sources.list.d ]; then
  for _file in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    rewrite "$_file"
  done
fi

mkdir -p /etc/apt/apt.conf.d
cat > /etc/apt/apt.conf.d/99archive <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
EOF
