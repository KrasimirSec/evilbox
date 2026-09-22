"""Legitimate-looking shop/marketing page that loads the sample as production JS."""

from __future__ import annotations

from html import escape


def brand_from_host(host: str) -> str:
    host = (host or "www.shop-assets.net").split(":")[0].lower()
    parts = [p for p in host.split(".") if p and p not in {"www", "cdn", "static", "assets", "img"}]
    if not parts:
        return "Store"
    name = parts[0] if len(parts) == 1 else (parts[-2] if len(parts) > 1 else parts[0])
    return name.replace("-", " ").title() or "Store"


def wrap_html(*, host: str, script_src: str = "/assets/app.min.js") -> str:
    brand = brand_from_host(host)
    h = escape(host)
    b = escape(brand)
    src = escape(script_src)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{b} — Official Site</title>
<meta name="description" content="Shop {b} online. Free shipping on orders over $50.">
<meta property="og:title" content="{b}">
<meta property="og:url" content="https://{h}/">
<link rel="icon" href="/favicon.ico">
<link rel="stylesheet" href="/assets/site.css">
</head>
<body>
<header class="top">
  <div class="wrap">
    <a class="logo" href="/">{b}</a>
    <nav>
      <a href="/collections/new">New</a>
      <a href="/collections/sale">Sale</a>
      <a href="/account/login">Account</a>
      <a href="/cart">Cart (0)</a>
    </nav>
  </div>
</header>
<main class="wrap">
  <section class="hero">
    <h1>New season, same {b}.</h1>
    <p>Hand-picked drops, member prices, and two-day shipping.</p>
    <a class="btn" href="/collections/new">Shop now</a>
  </section>
  <section class="grid" id="catalog">
    <article><h2>Everyday tee</h2><p>$24</p></article>
    <article><h2>Canvas tote</h2><p>$18</p></article>
    <article><h2>Runner</h2><p>$86</p></article>
  </section>
</main>
<footer class="wrap">
  <p>© {b}. Help · Privacy · Terms</p>
  <p class="fine">Prices in USD. {h}</p>
</footer>
<script src="{src}"></script>
</body>
</html>
"""


def google_serp_html(*, target_url: str, brand: str) -> str:
    url = escape(target_url)
    b = escape(brand)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{b} - Google Search</title>
<style>
body{{font-family:Arial,sans-serif;margin:0;background:#fff;color:#202124}}
#searchform{{padding:18px 24px;border-bottom:1px solid #ebebeb}}
input{{width:520px;padding:8px 12px;border:1px solid #dfe1e5;border-radius:24px}}
#rso{{max-width:652px;padding:20px 24px}}
.g h3{{margin:0;font-size:20px}}
.g a{{color:#1a0dab;text-decoration:none}}
.g cite{{color:#006621;font-size:14px}}
</style>
</head>
<body>
<form id="searchform"><input name="q" value="{b}" readonly></form>
<div id="rso">
  <div class="g">
    <cite>{url}</cite>
    <h3><a id="result" href="{url}">{b} — Official Site</a></h3>
    <p>Shop {b} online. Free shipping on orders over $50.</p>
  </div>
</div>
</body>
</html>
"""
