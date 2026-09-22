#!/bin/sh
# Point EOL Debian at archive.debian.org main only.
# Live security mirrors 404 .debs after LTS. archive.debian.org has no
# bullseye-security suite (only up through buster), so security lines are dropped.
set -eu

. /etc/os-release
codename=${VERSION_CODENAME:-}
if [ -z "$codename" ]; then
  case ${VERSION_ID:-} in
    11*) codename=bullseye ;;
    9*)  codename=stretch ;;
    8*)  codename=jessie ;;
    *)   codename=stretch ;;
  esac
fi

printf 'deb http://archive.debian.org/debian %s main\n' "$codename" > /etc/apt/sources.list
rm -rf /etc/apt/sources.list.d
mkdir -p /etc/apt/apt.conf.d
cat > /etc/apt/apt.conf.d/99archive <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
EOF
