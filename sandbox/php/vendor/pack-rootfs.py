#!/usr/bin/env python3
"""Rebuild the offline PHP sandbox rootfs tarballs.

Downloads official php-cli-alpine image layers (amd64 + arm64 for 8.3.33 and
7.4.33), installs a local Alpine package set, compiles evalhook + nosleep,
and writes gzip tarballs under vendor/rootfs/. Docker builds then ADD those
archives and never contact a registry or package mirror.

This script is the *refresh* path. It needs network. The tarballs it produces
are what `docker build --network=none` consumes.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOTFS_DIR = SCRIPT_DIR / "rootfs"
CACHE = Path(os.environ.get("EVILBOX_VENDOR_CACHE", "/tmp/evilbox-vendor-cache"))
EVALHOOK_SRC = SCRIPT_DIR / "php-eval-hook"
SLEEP_HOOK = SCRIPT_DIR.parent / "sleep_hook.c"

# Manifest digests inspected from Docker Hub on 2026-09-22.
IMAGES = {
    "8.3": {
        "php_version": "8.3.33",
        "upstream": "php:8.3.33-cli-alpine",
        "amd64": "sha256:6443da203cc731224936b7e842971f0067a596d60839144650ca5c11a2f3c98f",
        "arm64": "sha256:989d2bdaa98bcebcecd07604a1afd9c6659d4b874ab874b75e849a622399c872",
    },
    "7.4": {
        "php_version": "7.4.33",
        "upstream": "php:7.4.33-cli-alpine",
        "amd64": "sha256:1e1b3bb4ee1bcb039f559adb9a3fae391c87205ba239b619cdc239b78b7f2557",
        "arm64": "sha256:dbce323a8fd856cbd383920374bf9815c2f6503746ceb12e86ca3ec07545160a",
    },
}

RUNTIME_APKS = [
    "python3",
    "openssl",
    "dnsmasq",
    "tcpdump",
    "iproute2",
    "iptables",
    "util-linux",
    "ca-certificates",
    "libcap2",
    "coreutils",
    "bash",
    "curl",
    "libcurl",
    "libzip",
    "zlib",
]

ALPINE_ARCH = {"amd64": "x86_64", "arm64": "aarch64"}
DOCKER_ARCH_HEADER = {
    "amd64": "linux/amd64",
    "arm64": "linux/arm64",
}


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def http_get(url: str, headers: dict[str, str] | None = None, retries: int = 5) -> bytes:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            time.sleep(2 ** attempt)
    raise RuntimeError(f"GET failed {url}: {last}") from last


def docker_token() -> str:
    body = http_get(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/php:pull"
    )
    return json.loads(body)["token"]


def docker_json(url: str, token: str, accept: str) -> dict:
    body = http_get(url, {"Authorization": f"Bearer {token}", "Accept": accept})
    return json.loads(body)


def docker_blob(digest: str, token: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and dest.stat().st_size > 0:
        return dest
    url = f"https://registry-1.docker.io/v2/library/php/blobs/{digest}"
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/octet-stream",
        },
    )
    with urllib.request.urlopen(req, timeout=300) as resp, tmp.open("wb") as out:
        shutil.copyfileobj(resp, out, length=1024 * 1024)
    tmp.replace(dest)
    return dest


def _safe_join(root: Path, name: str) -> Path:
    rel = name.lstrip("/").lstrip("./")
    dest = (root / rel).resolve()
    if dest != root.resolve() and root.resolve() not in dest.parents:
        raise RuntimeError(f"refusing path escape: {name}")
    return dest


def apply_layer(root: Path, blob: Path) -> None:
    """Apply a Docker layer tarball, honoring overlay whiteouts.

    Opaque/file whiteouts apply to *lower* layers only. Files in this layer
    that sit next to a whiteout marker must be kept.
    """
    with tarfile.open(blob, mode="r:*") as tf:
        for member in tf.getmembers():
            name = member.name.lstrip("./")
            base = Path(name).name
            parent = _safe_join(root, str(Path(name).parent))
            if base == ".wh..wh..opq":
                if parent.is_dir():
                    for child in list(parent.iterdir()):
                        if child.is_dir() and not child.is_symlink():
                            shutil.rmtree(child, ignore_errors=True)
                        else:
                            child.unlink(missing_ok=True)
            elif base.startswith(".wh."):
                target = parent / base[4:]
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink(missing_ok=True)
    run(
        [
            "tar",
            "--overwrite",
            "--no-same-owner",
            "--no-same-permissions",
            "-xf",
            str(blob),
            "-C",
            str(root),
        ],
        quiet=True,
    )
    # Drop marker files; do not delete siblings extracted from this layer.
    for path in sorted(root.rglob("*"), reverse=True):
        if path.name.startswith(".wh."):
            path.unlink(missing_ok=True)


def parse_os_release(root: Path) -> str:
    text = (root / "etc" / "os-release").read_text(encoding="utf-8")
    data = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v.strip().strip('"')
    ver = data.get("VERSION_ID") or ""
    parts = ver.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    raise RuntimeError(f"cannot parse Alpine version from {data}")


def parse_apkindex(blob: bytes) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    raw = gzip.decompress(blob) if blob[:2] == b"\x1f\x8b" else blob
    # APKINDEX.tar.gz contains APKINDEX file
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            member = tf.extractfile("APKINDEX")
            if member is None:
                raise RuntimeError("APKINDEX missing")
            raw = member.read()
    except tarfile.TarError:
        pass
    packages: dict[str, dict[str, str]] = {}
    provides: dict[str, str] = {}
    rec: dict[str, str] = {}

    def commit() -> None:
        if not rec:
            return
        name = rec.get("P")
        if not name:
            rec.clear()
            return
        packages[name] = dict(rec)
        provides[name] = name
        for item in rec.get("p", "").split():
            provides[item.split("=", 1)[0]] = name
        rec.clear()

    for line in raw.decode("utf-8", "replace").splitlines():
        if not line:
            commit()
            continue
        rec[line[0]] = line[2:] if line[1:2] == ":" else line
    commit()
    return packages, provides


def load_indexes(branch: str, apk_arch: str) -> tuple[dict[str, dict[str, str]], dict[str, str], dict[str, str]]:
    packages: dict[str, dict[str, str]] = {}
    provides: dict[str, str] = {}
    origin: dict[str, str] = {}
    for repo in ("main", "community"):
        url = f"https://dl-cdn.alpinelinux.org/alpine/v{branch}/{repo}/{apk_arch}/APKINDEX.tar.gz"
        blob = http_get(url)
        pkgs, prov = parse_apkindex(blob)
        for name, rec in pkgs.items():
            packages[name] = rec
            origin[name] = repo
        provides.update(prov)
    return packages, provides, origin


def resolve_apks(
    names: list[str],
    packages: dict[str, dict[str, str]],
    provides: dict[str, str],
) -> list[str]:
    needed: list[str] = []
    seen: set[str] = set()

    def add(dep: str) -> None:
        dep = dep.strip()
        if not dep or dep.startswith("!"):
            return
        for sep in (">=", "<=", ">", "<", "=", "~"):
            if sep in dep:
                dep = dep.split(sep, 1)[0]
                break
        if dep.startswith("so:") or dep.startswith("pc:") or dep.startswith("cmd:"):
            pkg = provides.get(dep)
            if pkg:
                add(pkg)
            return
        pkg = provides.get(dep, dep)
        if pkg in seen:
            return
        if pkg not in packages:
            log(f"  skip unresolved dep {dep}")
            return
        seen.add(pkg)
        rec = packages[pkg]
        for item in rec.get("D", "").split():
            add(item)
        needed.append(pkg)

    for name in names:
        add(name)
    return needed


def download_apk(branch: str, repo: str, apk_arch: str, rec: dict[str, str], dest_dir: Path) -> Path:
    filename = f"{rec['P']}-{rec['V']}.apk"
    url = f"https://dl-cdn.alpinelinux.org/alpine/v{branch}/{repo}/{apk_arch}/{filename}"
    dest = dest_dir / filename
    if dest.is_file() and dest.stat().st_size > 0:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".part")
    tmp.write_bytes(http_get(url))
    tmp.replace(dest)
    return dest


def extract_apk(apk_path: Path, root: Path) -> None:
        run(
            [
                "tar",
                "--overwrite",
                "--no-same-owner",
                "--no-same-permissions",
                "-xzf",
                str(apk_path),
                "-C",
                str(root),
            ],
            quiet=True,
            stderr=subprocess.DEVNULL,
        )


def musl_linker(root: Path, arch: str) -> Path:
    name = "ld-musl-x86_64.so.1" if arch == "amd64" else "ld-musl-aarch64.so.1"
    path = root / "lib" / name
    if not path.is_file():
        raise RuntimeError(f"missing musl linker {path}")
    return path


def run(cmd: list[str], *, quiet: bool = False, **kwargs) -> subprocess.CompletedProcess[str]:
    if not quiet:
        log("+ " + " ".join(cmd))
    kwargs.setdefault("check", True)
    kwargs.setdefault("text", True)
    return subprocess.run(cmd, **kwargs)


def verify_php(root: Path) -> None:
    php = root / "usr" / "local" / "bin" / "php"
    python = root / "usr" / "bin" / "python3"
    nosleep = root / "opt" / "sandbox" / "nosleep.so"
    hooks = list((root / "usr" / "local" / "lib" / "php" / "extensions").rglob("evalhook.so"))
    for path in (php, python, nosleep):
        if not path.is_file():
            raise RuntimeError(f"missing {path}")
    if not hooks:
        raise RuntimeError("evalhook.so missing")
    linker = musl_linker(root, "amd64")
    libpath = ":".join(
        [
            str(root / "lib"),
            str(root / "usr" / "lib"),
            str(root / "usr" / "local" / "lib"),
        ]
    )
    proc = subprocess.run(
        [
            str(linker),
            "--library-path",
            libpath,
            str(php),
            "-n",
            "-d",
            f"extension={hooks[0]}",
            "-m",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    log((proc.stdout or "")[-500:] + (proc.stderr or "")[-500:])
    if proc.returncode != 0 or "evalhook" not in (proc.stdout + proc.stderr).lower():
        raise RuntimeError("vendored php failed to load evalhook")
    log("  php -m includes evalhook")


def compile_evalhook_zig(root: Path, arch: str, zig: Path) -> None:
    target = "x86_64-linux-musl" if arch == "amd64" else "aarch64-linux-musl"
    inc = root / "usr" / "local" / "include" / "php"
    if not (inc / "php.h").is_file() and not (inc / "main" / "php.h").is_file():
        raise RuntimeError(f"PHP headers missing under {inc}")
    ext_root = root / "usr" / "local" / "lib" / "php" / "extensions"
    candidates = list(ext_root.glob("no-debug-non-zts-*"))
    cfg = root / "usr" / "local" / "bin" / "php-config"
    if cfg.is_file():
        text = cfg.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if "extension_dir=" in line.replace(" ", ""):
                raw = line.split("=", 1)[-1].strip().strip("'\"")
                if raw.startswith("/"):
                    mapped = root / raw.lstrip("/")
                    candidates = [mapped]
                    mapped.mkdir(parents=True, exist_ok=True)
                    break
    if not candidates:
        candidates = [ext_root / "no-debug-non-zts-vendored"]
        candidates[0].mkdir(parents=True, exist_ok=True)
    dest = candidates[0] / "evalhook.so"
    cmd = [
        str(zig),
        "cc",
        "-target",
        target,
        "-shared",
        "-fPIC",
        "-O2",
        "-DHAVE_CONFIG_H",
        "-DCOMPILE_DL_EVALHOOK",
        f"-I{inc}",
        f"-I{inc / 'main'}",
        f"-I{inc / 'Zend'}",
        f"-I{inc / 'TSRM'}",
        "-o",
        str(dest),
        str(EVALHOOK_SRC / "evalhook.c"),
    ]
    run(cmd)
    log(f"  wrote {dest} ({dest.stat().st_size} bytes)")


def compile_nosleep(root: Path, arch: str, zig: Path) -> None:
    dest = root / "opt" / "sandbox"
    dest.mkdir(parents=True, exist_ok=True)
    src_in = dest / "sleep_hook.c"
    shutil.copy2(SLEEP_HOOK, src_in)
    so = dest / "nosleep.so"
    target = "x86_64-linux-musl" if arch == "amd64" else "aarch64-linux-musl"
    run([str(zig), "cc", "-target", target, "-shared", "-fPIC", "-O2", "-o", str(so), str(src_in)])


def enable_evalhook(root: Path) -> None:
    conf_dir = root / "usr" / "local" / "etc" / "php" / "conf.d"
    conf_dir.mkdir(parents=True, exist_ok=True)
    (conf_dir / "docker-php-ext-evalhook.ini").write_text("extension=evalhook.so\n", encoding="utf-8")
    mods = list((root / "usr" / "local" / "lib" / "php" / "extensions").rglob("evalhook.so"))
    if not mods:
        raise RuntimeError("evalhook.so was not installed")
    log(f"  evalhook.so -> {mods[0]}")


def strip_build_files(root: Path) -> None:
    run(["sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(root)], check=False, quiet=True)
    for rel in (
        "usr/src",
        "usr/local/include",
        "usr/include",
        "var/cache/apk",
        "root/.ash_history",
        "usr/lib/gcc",
        "usr/libexec/gcc",
    ):
        path = root / rel
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
    for path in root.glob("usr/lib/lib*.a"):
        path.unlink(missing_ok=True)
    for rel in (
        "usr/bin/gcc",
        "usr/bin/g++",
        "usr/bin/cc",
        "usr/bin/c++",
        "usr/bin/phpize",
        "usr/bin/php-config",
        "usr/local/bin/phpize",
        "usr/local/bin/php-config",
        "usr/local/bin/docker-php-ext-install",
        "usr/local/bin/docker-php-ext-configure",
        "usr/local/bin/docker-php-ext-enable",
        "usr/local/bin/docker-php-source",
    ):
        (root / rel).unlink(missing_ok=True)


def write_tarball(root: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    log(f"  packing {dest.name}")
    run(
        [
            "tar",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--sort=name",
            "-czf",
            str(tmp),
            "-C",
            str(root),
            ".",
        ]
    )
    tmp.replace(dest)
    log(f"  {dest.name} {dest.stat().st_size / 1e6:.1f} MB sha256={sha256_file(dest)}")


def find_zig() -> Path | None:
    env = os.environ.get("ZIG")
    if env:
        return Path(env)
    which = shutil.which("zig")
    if which:
        return Path(which)
    cached = CACHE / "zig" / "zig"
    if cached.is_file():
        return cached
    return None


def fetch_zig() -> Path:
    existing = find_zig()
    if existing:
        return existing
    index = json.loads(http_get("https://ziglang.org/download/index.json"))
    ver = "0.15.2" if "0.15.2" in index else next(v for v in index if v[0].isdigit())
    rec = index[ver]["x86_64-linux"]
    url = rec["tarball"]
    name = Path(url).name.replace(".tar.xz", "")
    archive = CACHE / Path(url).name
    if not archive.is_file():
        log(f"downloading {url}")
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_bytes(http_get(url))
        got = sha256_file(archive)
        expect = rec.get("shasum")
        if expect and got != expect:
            archive.unlink()
            raise RuntimeError(f"zig sha256 mismatch: {got} != {expect}")
    dest_dir = CACHE / name
    zig = dest_dir / "zig"
    if not zig.is_file():
        run(["tar", "-xJf", str(archive), "-C", str(CACHE)])
    if not zig.is_file():
        raise RuntimeError("zig download did not unpack a zig binary")
    return zig


def php_image_layers(token: str, manifest_digest: str) -> list[str]:
    man = docker_json(
        f"https://registry-1.docker.io/v2/library/php/manifests/{manifest_digest}",
        token,
        "application/vnd.oci.image.manifest.v1+json, "
        "application/vnd.docker.distribution.manifest.v2+json",
    )
    return [layer["digest"] for layer in man.get("layers", [])]


def build_one(php_key: str, arch: str, token: str, zig: Path) -> Path:
    meta = IMAGES[php_key]
    digest = meta[arch]
    work = CACHE / "rootfs" / f"php-{meta['php_version']}-{arch}"
    if work.exists():
        for extra in (work / "proc", work / "dev"):
            run(["sudo", "umount", str(extra)], check=False, quiet=True)
        run(["sudo", "rm", "-rf", str(work)])
    work.mkdir(parents=True)
    log(f"==> {meta['upstream']} {arch}")
    layers = php_image_layers(token, digest)
    log(f"  {len(layers)} layers")
    blob_dir = CACHE / "blobs"
    for layer in layers:
        hexdigest = layer.split(":", 1)[-1]
        blob = blob_dir / hexdigest
        if not blob.is_file():
            log(f"  blob {hexdigest[:12]}")
            docker_blob(layer, token, blob)
        apply_layer(work, blob)
    branch = parse_os_release(work)
    apk_arch = ALPINE_ARCH[arch]
    log(f"  alpine v{branch} {apk_arch}")
    packages, provides, origin = load_indexes(branch, apk_arch)
    # libcap2 vs libcap: Alpine renamed. Accept either.
    runtime = []
    for name in RUNTIME_APKS:
        if name in packages or name in provides:
            runtime.append(name)
        elif name == "libcap2" and "libcap" in packages:
            runtime.append("libcap")
        else:
            log(f"  warning: package {name} not in index")
    wanted = runtime
    resolved = resolve_apks(wanted, packages, provides)
    apk_dir = CACHE / "apks" / f"v{branch}" / apk_arch
    log(f"  installing {len(resolved)} apks")
    for name in resolved:
        rec = packages[name]
        repo = origin[name]
        apk = download_apk(branch, repo, apk_arch, rec, apk_dir)
        extract_apk(apk, work)
    compile_evalhook_zig(work, arch, zig)
    compile_nosleep(work, arch, zig)
    enable_evalhook(work)
    strip_build_files(work)
    if arch == "amd64":
        verify_php(work)
    # Make sure sandbox dirs exist.
    for rel in ("opt/sandbox", "logs", "samples", "tmp/ca", "run"):
        (work / rel).mkdir(parents=True, exist_ok=True)
    dest = ROOTFS_DIR / f"php-{meta['php_version']}-cli-alpine-linux-{arch}.tar.gz"
    write_tarball(work, dest)
    return dest


def main() -> int:
    CACHE.mkdir(parents=True, exist_ok=True)
    ROOTFS_DIR.mkdir(parents=True, exist_ok=True)
    token = docker_token()
    zig = fetch_zig()
    log(f"zig: {zig}")
    built: list[Path] = []
    for php_key in ("8.3", "7.4"):
        for arch in ("amd64", "arm64"):
            built.append(build_one(php_key, arch, token, zig))
    sums = SCRIPT_DIR / "SHA256SUMS"
    existing = sums.read_text(encoding="utf-8") if sums.is_file() else ""
    lines = [
        line
        for line in existing.splitlines()
        if line.strip() and "rootfs/php-" not in line and "cli-alpine-linux-" not in line
    ]
    for path in built:
        lines.append(f"{sha256_file(path)}  rootfs/{path.name}")
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log("done:")
    for path in built:
        log(f"  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
