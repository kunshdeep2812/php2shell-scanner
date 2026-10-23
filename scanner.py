#!/usr/bin/env python3
"""php2shell-scanner: technology fingerprinting + PHP2Shell exposure triage.

Covers CVE-2026-109618 / CVE-2026-109619 (GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp).
Fixed upstream in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 (2026-10-21); 7.4-8.1 only got source
backports; the vulnerable code goes back to 5.4.0.

What it does
  * Fingerprints each target from headers (including redirect hops), cookies, HTML, meta tags,
    script URLs, inline scripts and error pages, using ~70 built-in signatures plus the
    Wappalyzer-format database from projectdiscovery/wappalyzergo (~7,600 technologies,
    downloaded once and cached).
  * Proves PHP even when the version is hidden: PHP-FPM 404s, .php vs .txt 404 differential,
    PHPSESSID, PHP-only apps, exposed phpinfo()/composer files, the pre-5.5 easter-egg logo.
  * Assesses the PHP version: upstream releases against the fixed-version table, Ubuntu package
    builds exactly against USN-8948-1/-2 (dpkg version comparison), and RPM/Debian/sury builds
    with backport awareness.
  * Optional active patch oracle (off by default): one ~300-byte multipart POST that counts the
    session warnings PHP prints (3/3 = unpatched, 2/3 = patched). Conclusive only when
    display_errors=On. It does not trigger the memory-safety bugs.

What it does NOT do
  * Send the vulnerability triggers or anything that corrupts memory, shapes the heap or
    exhausts memory. Version-based verdicts are exposure assessments, not proof.
  * Follow redirects to hosts outside the target (or your scope list).

Only scan assets you are authorized to test (for example in-scope bug bounty targets).

Usage
  python3 scanner.py                       # local web GUI at http://127.0.0.1:8765
  python3 scanner.py --cli -f targets.txt --scope scope.txt --deep --authorized --csv out.csv
  python3 scanner.py --update-fingerprints # refresh the cached fingerprint database
"""
import argparse
import concurrent.futures
import csv
import gzip
import hashlib
import hmac
import html.parser
import io
import ipaddress
import json
import os
import random
import re
import secrets
import socket
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings
import webbrowser
import zlib
from collections import namedtuple
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UA = "Mozilla/5.0 (compatible; php2shell-triage/2.0)"
MAX_BODY = 600_000
MAX_MATCH = 300_000  # bytes of HTML / inline JS fed to the fingerprint regexes
MAX_TARGETS = 5000

# First fixed upstream release per branch (PHP security release, 2026-10-21).
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
# Affected branches without an official release (PHP published source backports only).
BACKPORT_ONLY = {(7, 4), (8, 0), (8, 1)}
EARLIEST_AFFECTED = (5, 4)

# Ubuntu archive builds always carry the package revision in PHP_VERSION (e.g. 8.1.2-1ubuntu2.14),
# so they can be compared exactly. (upstream prefix, first fixed package version, release)
UBUNTU_FIXED = [
    ("8.5.9", "8.5.9-0ubuntu2.1", "26.10", "USN-8948-1"),
    ("8.5.4", "8.5.4-0ubuntu1.5", "26.04 LTS", "USN-8948-1"),
    ("8.3.6", "8.3.6-0ubuntu0.24.04.13", "24.04 LTS", "USN-8948-1"),
    ("8.1.2", "8.1.2-1ubuntu2.28", "22.04 LTS", "USN-8948-1"),
    ("7.4.3", "7.4.3-4ubuntu2.29+esm5", "20.04 LTS (ESM, Ubuntu Pro)", "USN-8948-2"),
    ("7.2.24", "7.2.24-0ubuntu0.18.04.17+esm14", "18.04 LTS (ESM, Ubuntu Pro)", "USN-8948-2"),
    ("7.0.33", "7.0.33-0ubuntu0.16.04.16+esm22", "16.04 LTS (ESM, Legacy)", "USN-8948-2"),
    ("5.5.9", "5.5.9+dfsg-1ubuntu4.29+esm18", "14.04 LTS (ESM, Legacy)", "USN-8948-2"),
]

# Probable OS (and its archive PHP branch) from distro-tagged web server banners. Hints only.
OS_HINTS = [
    (r"Apache/2\.4\.41 \(Ubuntu\)", "Ubuntu 20.04", "7.4"),
    (r"Apache/2\.4\.52 \(Ubuntu\)", "Ubuntu 22.04", "8.1"),
    (r"Apache/2\.4\.58 \(Ubuntu\)", "Ubuntu 24.04", "8.3"),
    (r"nginx/1\.18\.0 \(Ubuntu\)", "Ubuntu 20.04 or 22.04", "7.4 or 8.1"),
    (r"nginx/1\.24\.0 \(Ubuntu\)", "Ubuntu 24.04", "8.3"),
]

STATUSES = ["VULNERABLE", "LIKELY_VULNERABLE", "UNKNOWN", "INDETERMINATE", "PATCHED", "NOT_PHP", "ERROR"]

# Usual HTTP(S) ports, for --ports web (hosting panels, dev servers, admin consoles, alt ports).
COMMON_WEB_PORTS = [80, 81, 443, 591, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 4443, 5000, 7001, 7080, 8000, 8008,
                    8080, 8081, 8088, 8090, 8181, 8443, 8880, 8888, 9000, 9080, 9443, 10000]

# Server-side stacks that are positive evidence of "not PHP" when no PHP signal was found.
NON_PHP_STACKS = {"microsoft asp.net", "express", "java", "ruby on rails", "ruby", "django", "flask", "python", "node.js",
                  "next.js", "nuxt.js", "nuxt", "gatsby", "apache tomcat", "jetty", "gunicorn", "werkzeug", "kestrel",
                  "go", "vercel", "netlify", "github pages", "hugo", "jekyll", "phoenix", "spring", "simplehttp"}
RISK_ORDER = {s: i for i, s in enumerate(STATUSES)}

FP_BASE = "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/main/"
FP_FILES = ("fingerprints_data.json", "categories_data.json")
FP_DIR = os.environ.get("PHP2SHELL_FP_DIR") or os.path.join(os.path.expanduser("~"), ".cache", "php2shell-scanner")
# Fingerprint categories that run in the visitor's browser or on a third party: an "implies PHP"
# from these says nothing about the scanned host.
CLIENT_SIDE_CATS = {"Analytics", "Tag managers", "Advertising", "Widgets", "JavaScript libraries",
                    "JavaScript frameworks", "Font scripts", "Live chat", "Marketing automation",
                    "Cookie compliance", "RUM", "A/B Testing", "Customer data platform", "Retargeting",
                    "Affiliate programs", "Surveys", "Feedback widgets", "Video players", "Maps", "CDN",
                    "Payment processors", "Social logins", "Accessibility", "Personalisation"}


# --------------------------------------------------------------- version compare

def _dpkg_order(ch):
    if not ch or ch.isdigit():
        return 0
    if ch.isalpha():
        return ord(ch)
    return -1 if ch == "~" else ord(ch) + 256


def _verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i] if i < len(a) else "")
            bc = _dpkg_order(b[j] if j < len(b) else "")
            if ac != bc:
                return ac - bc
            i, j = i + 1, j + 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            first_diff = first_diff or ord(a[i]) - ord(b[j])
            i, j = i + 1, j + 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def dpkg_compare(a, b):
    """Compare two Debian package versions like dpkg --compare-versions (<0, 0, >0)."""
    def split(v):
        epoch, _, rest = v.rpartition(":") if ":" in v else ("0", "", v)
        upstream, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return int(epoch or 0), upstream, rev
    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# --------------------------------------------------------------------- HTTP

class Resp:
    __slots__ = ("url", "status", "headers", "cookies", "body", "error", "hops", "blocked")

    def __init__(self, url, status=0, headers=None, cookies=None, body="", error=None):
        self.url, self.status, self.headers = url, status, headers or {}
        self.cookies, self.body, self.error = cookies or [], body, error
        self.hops, self.blocked = [], None


def make_ssl_context(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    return ctx


def _split_headers(msg):
    hdrs = {}
    for k, v in msg.items():
        k = k.lower()
        if k != "set-cookie":
            hdrs[k] = hdrs[k] + " | " + v if k in hdrs else v
    return hdrs, msg.get_all("Set-Cookie") or []


def _decode(raw, msg):
    enc = (msg.get("Content-Encoding") or "").lower()
    try:
        if enc == "gzip":
            raw = gzip.decompress(raw)
        elif enc == "deflate":
            raw = zlib.decompress(raw)
    except Exception:
        pass
    return raw.decode("utf-8", errors="replace")


class _ScopedRedirects(urllib.request.HTTPRedirectHandler):
    """Follows redirects only to allowed hosts and keeps every hop's headers."""

    def __init__(self, allow):
        super().__init__()
        self.allow, self.hops, self.blocked = allow, [], None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        hdrs, cookies = _split_headers(headers)
        self.hops.append(Resp(req.full_url, code, hdrs, cookies))
        if not self.allow(urllib.parse.urlsplit(newurl).hostname or ""):
            self.blocked = newurl
            return None  # urllib then raises HTTPError carrying the 3xx response
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, timeout, ctx, allow, method="GET", data=None, headers=None):
    hdrs = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    redirects = _ScopedRedirects(allow)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), redirects)
    try:
        with opener.open(req, timeout=timeout) as r:
            resp = _build(r, r.status, r.geturl())
    except urllib.error.HTTPError as e:
        resp = _build(e, e.code, e.geturl() or url)
    except Exception as e:  # DNS, connect, TLS, timeout, ...
        resp = Resp(url, 0, error=f"{type(e).__name__}: {getattr(e, 'reason', e)}")
    resp.hops, resp.blocked = redirects.hops, redirects.blocked
    return resp


def _build(r, status, url):
    hdrs, cookies = _split_headers(r.headers)
    try:
        raw = r.read(MAX_BODY)
    except Exception:
        raw = b""
    return Resp(url, status, hdrs, cookies, _decode(raw, r.headers))


# -------------------------------------------------------------------- scope

def parse_scope(lines):
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        try:
            out.append(str(ipaddress.ip_network(line, strict=False)))  # 10.0.0.5 or 192.168.1.0/24
            continue
        except ValueError:
            pass
        line = re.sub(r"^[a-z]+://", "", line).split("/", 1)[0].rsplit(":", 1)[0] if not line.startswith("[") else line
        if line:
            out.append(line.rstrip("."))
    return out


def in_scope(host, scope):
    """No scope list = everything allowed. '*.example.com' covers subdomains, not the apex; CIDRs match IPs."""
    if not scope:
        return True
    host = host.lower().rstrip(".").strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    for s in scope:
        if "/" in s:
            if ip is not None and ip in ipaddress.ip_network(s):
                return True
        elif host.endswith(s[1:]) if s.startswith("*.") else host == s:
            return True
    return False


def host_variants(host):
    host = host.lower()
    return {host, host[4:] if host.startswith("www.") else "www." + host}


# --------------------------------------------------------------- HTML parsing

class PageParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta, self.assets, self.script_srcs, self.inline_js = {}, [], [], []
        self.title, self._tag, self._js_len = "", None, 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            name = (a.get("name") or a.get("property") or a.get("http-equiv") or "").lower()
            if name and "content" in a:
                self.meta.setdefault(name, a["content"])
        elif tag == "script" and a.get("src"):
            self.script_srcs.append(a["src"])
        if tag in ("title", "script"):
            self._tag = tag
        for key in ("src", "href", "action"):
            if a.get(key) and len(self.assets) < 800:
                self.assets.append(a[key])

    def handle_endtag(self, tag):
        if tag == self._tag:
            self._tag = None

    def handle_data(self, data):
        if self._tag == "title" and len(self.title) < 200:
            self.title += data.strip()
        elif self._tag == "script" and self._js_len < MAX_MATCH:
            self.inline_js.append(data)
            self._js_len += len(data)


def parse_page(body):
    p = PageParser()
    try:
        p.feed(body)
    except Exception:
        pass
    return p


# --------------------------------------------------------- built-in signatures

SIGS = []


def sig(name, cat, rules, php=False):
    compiled = [(k, re.compile(p, re.I | re.S)) for k, p in rules]
    SIGS.append({"name": name, "cat": cat, "php": php, "rules": compiled})


# Rule kinds: header:<name>  cookie  html  err (error pages)  meta:<name>  asset  probe:<path>
# These complement the Wappalyzer database with probe- and error-page-based checks it lacks.

# Web servers and proxies
sig("Nginx", "Web servers", [("header:server", r"nginx(?:/(?P<v>\d[\d.]*))?"), ("err", r"<center>nginx/(?P<v>\d[\d.]*)")])
sig("Apache HTTP Server", "Web servers", [("header:server", r"\bApache(?!-Coyote)(?:/(?P<v>\d[\d.]*))?"),
                                          ("err", r"<address>Apache/(?P<v>\d[\d.]*)")])
sig("LiteSpeed", "Web servers", [("header:server", r"LiteSpeed"), ("header:x-litespeed-cache", r"."),
                                 ("header:x-turbo-charged-by", r"LiteSpeed")])
sig("OpenResty", "Web servers", [("header:server", r"openresty(?:/(?P<v>\d[\d.]*))?")])
sig("IIS", "Web servers", [("header:server", r"Microsoft-IIS/(?P<v>\d[\d.]*)")])
sig("Caddy", "Web servers", [("header:server", r"\bCaddy\b")])
sig("lighttpd", "Web servers", [("header:server", r"lighttpd(?:/(?P<v>\d[\d.]*))?")])
sig("Apache Tomcat", "Web servers", [("header:server", r"Apache-Coyote|Tomcat"), ("err", r"Apache Tomcat/(?P<v>\d[\d.]*)")])
sig("Jetty", "Web servers", [("header:server", r"Jetty(?:\((?P<v>[\d.]+)\))?")])
sig("gunicorn", "Web servers", [("header:server", r"gunicorn(?:/(?P<v>\d[\d.]*))?")])
sig("Werkzeug", "Web servers", [("header:server", r"Werkzeug(?:/(?P<v>\d[\d.]*))?")])

# Non-PHP runtimes
sig("Microsoft ASP.NET", "Web frameworks", [("header:x-aspnet-version", r"(?P<v>\d[\d.]*)"), ("header:x-powered-by", r"ASP\.NET"),
                                            ("cookie", r"^ASP\.NET_SessionId$"), ("html", r"__VIEWSTATE")])
sig("Express", "Web frameworks", [("header:x-powered-by", r"\bExpress\b")])
sig("Java", "Programming languages", [("cookie", r"^JSESSIONID$")])
sig("Ruby on Rails", "Web frameworks", [("meta:csrf-param", r"^authenticity_token$"), ("header:server", r"Phusion_Passenger")])
sig("Django", "Web frameworks", [("cookie", r"^csrftoken$"), ("html", r"csrfmiddlewaretoken")])

# PHP software (php=True: its presence proves PHP on this host even when the version is hidden)
sig("WordPress", "CMS", [
    ("meta:generator", r"WordPress\s*(?P<v>\d[\d.]*)?"), ("html", r"/wp-(?:content|includes)/"),
    ("header:link", r"api\.w\.org"), ("header:x-pingback", r"xmlrpc\.php"), ("cookie", r"^wordpress_|^wp-settings"),
    ("probe:/wp-login.php", r"user_login|wp-submit"), ("probe:/wp-json/", r'"namespaces"'),
    ("probe:/xmlrpc.php", r"XML-RPC server accepts POST"), ("probe:/readme.html", r"<title>WordPress[^<]*ReadMe")], php=True)
sig("WooCommerce", "Ecommerce", [("html", r"woocommerce-(?:page|js|no-js)|/plugins/woocommerce/"), ("cookie", r"^woocommerce_")], php=True)
sig("Drupal", "CMS", [
    ("meta:generator", r"Drupal\s*(?P<v>\d[\d.]*)?"), ("header:x-generator", r"Drupal\s*(?P<v>\d[\d.]*)?"),
    ("header:x-drupal-cache", r"."), ("html", r"/sites/(?:default|all)/(?:files|modules|themes)/|Drupal\.settings"),
    ("probe:/CHANGELOG.txt", r"^\s*Drupal\s+(?P<v>\d[\d.]*)")], php=True)
sig("Joomla", "CMS", [("meta:generator", r"Joomla!?\s*(?P<v>\d[\d.]*)?"), ("html", r"/media/jui/|/media/system/js/core\.js"),
                      ("probe:/administrator/", r"com_login|joomla")], php=True)
sig("Magento", "Ecommerce", [("cookie", r"^mage-cache-sessid$"), ("html", r"Mage\.Cookies|/static/version\d+/|mage/cookies")], php=True)
sig("PrestaShop", "Ecommerce", [("meta:generator", r"PrestaShop"), ("html", r"var prestashop\s*=|/modules/ps_")], php=True)
sig("OpenCart", "Ecommerce", [("html", r"catalog/view/(?:theme|javascript)/"), ("cookie", r"^OCSESSID$")], php=True)
sig("TYPO3 CMS", "CMS", [("meta:generator", r"TYPO3"), ("html", r"typo3conf/|typo3temp/")], php=True)
sig("MediaWiki", "Wikis", [("meta:generator", r"MediaWiki\s*(?P<v>\d[\d.]*)?"), ("html", r"/load\.php\?[^\"']*modules=")], php=True)
sig("phpBB", "Message boards", [("cookie", r"^phpbb3?_"), ("html", r"styles/prosilver/|Powered by <a[^>]+phpbb\.com")], php=True)
sig("vBulletin", "Message boards", [("meta:generator", r"vBulletin\s*(?P<v>\d[\d.]*)?"), ("cookie", r"^bb(?:lastvisit|sessionhash)$")], php=True)
sig("Moodle", "LMS", [("cookie", r"^MoodleSession"), ("html", r"/theme/yui_combo\.php|M\.cfg\s*=")], php=True)
sig("Laravel", "Web frameworks", [("cookie", r"^laravel_session$")], php=True)
sig("Symfony", "Web frameworks", [("header:x-debug-token", r"."), ("header:x-symfony-cache", r".")], php=True)
sig("CodeIgniter", "Web frameworks", [("cookie", r"^ci_session$"), ("err", r"CodeIgniter")], php=True)
sig("CakePHP", "Web frameworks", [("cookie", r"^CAKEPHP$")], php=True)
sig("Yii", "Web frameworks", [("cookie", r"^YII_CSRF_TOKEN$"), ("meta:csrf-param", r"^_csrf")], php=True)
sig("ThinkPHP", "Web frameworks", [("header:x-powered-by", r"ThinkPHP")], php=True)
sig("Craft CMS", "CMS", [("header:x-powered-by", r"Craft CMS"), ("cookie", r"^CraftSessionId$")], php=True)
sig("Concrete CMS", "CMS", [("meta:generator", r"concrete5|Concrete CMS\s*(?P<v>\d[\d.]*)?")], php=True)
sig("Roundcube", "Webmail", [("cookie", r"^roundcube_sessid$"), ("html", r"rcmloginuser|rcube_webmail")], php=True)
sig("phpMyAdmin", "Database managers", [("cookie", r"^phpMyAdmin$|^pma_lang$"), ("html", r"<title>phpMyAdmin|phpmyadmin\.css")], php=True)
sig("Nextcloud", "Document management", [("cookie", r"^oc_sessionPassphrase$|^nc_sameSiteCookie"),
                                         ("probe:/status.php", r'"versionstring":"(?P<v>[\d.]+)".*?"productname":"(?:Nextcloud|ownCloud)')], php=True)
sig("cPanel", "Hosting panels", [("cookie", r"^cprelogin$|^cpsession$"), ("header:server", r"cpsrvd")], php=True)
sig("Plesk", "Hosting panels", [("header:x-powered-by-plesk", r"."), ("header:x-powered-by", r"PleskLin|PleskWin")], php=True)

# CDN, WAF and hosting
sig("Cloudflare", "CDN", [("header:server", r"cloudflare"), ("header:cf-ray", r"."), ("cookie", r"^__cf_bm$|^cf_clearance$")])
sig("Akamai", "CDN", [("header:server", r"AkamaiGHost|AkamaiNetStorage"), ("header:x-akamai-transformed", r"."), ("cookie", r"^ak_bmsc$|^bm_sz$")])
sig("Fastly", "CDN", [("header:x-fastly-request-id", r"."), ("header:x-served-by", r"cache-")])
sig("Amazon CloudFront", "CDN", [("header:via", r"CloudFront"), ("header:x-amz-cf-id", r".")])
sig("Sucuri", "Security", [("header:x-sucuri-id", r"."), ("header:server", r"Sucuri")])
sig("Imperva", "Security", [("header:x-iinfo", r"."), ("cookie", r"^visid_incap_|^incap_ses_")])
sig("Varnish", "Caching", [("header:x-varnish", r"."), ("header:via", r"varnish")])
sig("Vercel", "PaaS", [("header:server", r"Vercel"), ("header:x-vercel-id", r".")])
sig("Netlify", "PaaS", [("header:server", r"Netlify"), ("header:x-nf-request-id", r".")])
sig("WP Engine", "PaaS", [("header:x-powered-by", r"WP Engine"), ("header:wpe-backend", r".")])
sig("Kinsta", "PaaS", [("header:x-kinsta-cache", r".")])
sig("Pantheon", "PaaS", [("header:x-pantheon-styx-hostname", r".")])

PHPINFO_PATHS = ["/phpinfo.php", "/info.php"]
EASTER_EGG = "/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"  # PHP logo, served by PHP <= 5.4 with expose_php=On
CREDITS_EGG = "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"  # PHP credits page, same old versions
COMPOSER_PATHS = ["/composer.json", "/composer.lock"]
# Pages that usually start a session, so they set PHPSESSID or send X-Powered-By even when the home page doesn't.
SESSION_PATHS = ["/login", "/admin/", "/user/login", "/account", "/signin", "/my-account/", "/cart"]
DEEP_PATHS = sorted({k[6:] for s in SIGS for k, _ in s["rules"] if k.startswith("probe:")}
                    | set(PHPINFO_PATHS) | set(COMPOSER_PATHS) | set(SESSION_PATHS)
                    | {"/index.php", EASTER_EGG, CREDITS_EGG})


# -------------------------------------------------------- Wappalyzer database

Pat = namedtuple("Pat", "rx version conf anchor")


def literal_anchor(p):
    """A lowercase literal every match must contain (cheap prefilter), or None."""
    runs, cur, i, n, depth = [], "", 0, len(p), 0
    while i < n:
        c = p[i]
        if c == "\\":
            nx = p[i + 1] if i + 1 < n else ""
            i += 2
            if depth or not nx or nx.isalnum():
                if not depth:
                    runs.append(cur)
                    cur = ""
                continue
            cur += nx
            continue
        if c == "[":
            j = i + 1
            if j < n and p[j] == "^":
                j += 1
            if j < n and p[j] == "]":
                j += 1
            while j < n and p[j] != "]":
                j += 2 if p[j] == "\\" else 1
            i = j + 1
            if not depth:
                runs.append(cur)
                cur = ""
            continue
        if c == "(":
            if not depth:
                runs.append(cur)
                cur = ""
            depth += 1
            i += 1
            continue
        if c == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth:
            i += 1
            continue
        if c == "|":
            return None
        if c in "?*{":
            runs.append(cur[:-1])  # the previous character is optional
            cur = ""
            if c == "{":
                j = p.find("}", i)
                i = n if j == -1 else j + 1
            else:
                i += 1
            continue
        if c in ".^$+":
            runs.append(cur)
            cur = ""
            i += 1
            continue
        cur += c
        i += 1
    runs.append(cur)
    best = max(runs, key=len)
    return best.lower() if len(best) >= 3 else None


def _bound_quantifiers(p):
    """Rewrite + and * to {1,250} / {0,250} (as wappalyzergo does) to limit regex backtracking."""
    out, i, n, in_cls = [], 0, len(p), False
    while i < n:
        c = p[i]
        if c == "\\" and i + 1 < n:
            out.append(p[i:i + 2])
            i += 2
            continue
        if in_cls:
            in_cls = c != "]"
        elif c == "[":
            in_cls = True
            out.append(c)
            i += 1
            for lead in "^]":
                if i < n and p[i] == lead:
                    out.append(lead)
                    i += 1
            continue
        elif c in "+*" and out and out[-1][-1] not in "+*?}(|":
            out.append("{1,250}" if c == "+" else "{0,250}")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def parse_pattern(s, whole_word=False):
    parts = (s or "").split("\\;")
    regex, version, conf = parts[0], None, 100
    for tag in parts[1:]:
        k, _, v = tag.partition(":")
        if k == "version":
            version = v
        elif k == "confidence":
            conf = int(v) if v.isdigit() else 100
    if not regex:
        return Pat(None, version, conf, None)
    if whole_word and re.fullmatch(r"[A-Za-z0-9-]+", regex):
        # Bare-word header patterns must not match inside other words ("bun" in "1ubuntu2").
        regex = rf"(?<![a-z0-9]){regex}(?![a-z0-9])"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for candidate in (_bound_quantifiers(regex), regex):
            try:
                return Pat(re.compile(candidate, re.I), version, conf, literal_anchor(regex))
            except (re.error, RecursionError, OverflowError):
                continue
    return None


def resolve_version(template, m):
    if not template:
        return None
    v = template
    for i, g in enumerate(m.groups(), 1):
        v = v.replace(f"\\{i}", g or "")
    if "?" in v:
        cond, _, rest = v.partition("?")
        yes, _, no = rest.partition(":")
        v = yes if cond else no
    v = v.strip()
    return v if v and len(v) < 40 else None


def _pat_match(p, text, text_l):
    if p.rx is None:
        return True, None
    if p.anchor and p.anchor not in text_l:
        return False, None
    m = p.rx.search(text)
    return (True, resolve_version(p.version, m)) if m else (False, None)


class FingerprintDB:
    def __init__(self, directory=FP_DIR):
        self.dir, self.apps, self.lock = directory, [], threading.Lock()
        self.ready, self.error, self.updated, self.loading = False, None, None, False

    def status(self):
        return {"ready": self.ready, "apps": len(self.apps), "updated": self.updated, "error": self.error,
                "loading": self.loading, "dir": self.dir}

    def ensure(self, allow_download=True):
        with self.lock:
            if self.ready:
                return
            self.loading = True
            try:
                if not all(os.path.exists(os.path.join(self.dir, f)) for f in FP_FILES):
                    if not allow_download:
                        raise FileNotFoundError(f"no fingerprint database in {self.dir} (run --update-fingerprints)")
                    self._download()
                self._load()
            except Exception as e:
                self.error = f"{type(e).__name__}: {e}"
            finally:
                self.loading = False

    def update(self):
        with self.lock:
            self.loading = True
            try:
                self._download()
                self.ready = False
                self._load()
                self.error = None
            except Exception as e:
                self.error = f"{type(e).__name__}: {e}"
            finally:
                self.loading = False

    def _download(self):
        os.makedirs(self.dir, exist_ok=True)
        ctx = ssl.create_default_context()
        for name in FP_FILES:
            req = urllib.request.Request(FP_BASE + name, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
                data = r.read()
            json.loads(data)  # refuse to cache anything that is not JSON
            tmp = os.path.join(self.dir, name + ".tmp")
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, os.path.join(self.dir, name))

    def _load(self):
        with open(os.path.join(self.dir, "fingerprints_data.json"), encoding="utf-8") as f:
            raw = json.load(f)["apps"]
        with open(os.path.join(self.dir, "categories_data.json"), encoding="utf-8") as f:
            cats = {int(k): v.get("name", k) for k, v in json.load(f).items()}

        def pats(values, whole_word=False):
            out = []
            for v in values if isinstance(values, list) else [values]:
                p = parse_pattern(v, whole_word)
                if p:
                    out.append(p)
            return out

        apps = {}
        for name, a in raw.items():
            entry = {"name": name, "cats": [cats.get(c, str(c)) for c in a.get("cats", [])],
                     "headers": [(k.lower(), p) for k, v in (a.get("headers") or {}).items() for p in pats(v, True)],
                     "cookies": [(k.lower(), p) for k, v in (a.get("cookies") or {}).items() for p in pats(v)],
                     "meta": [(k.lower(), p) for k, v in (a.get("meta") or {}).items() for p in (pats(v) or [Pat(None, None, 100, None)])],
                     "html": pats(a.get("html") or []), "scripts": pats(a.get("scripts") or []),
                     "scriptSrc": pats(a.get("scriptSrc") or []), "implies": []}
            for imp in a.get("implies") or []:
                n, _, tags = imp.partition("\\;")
                m = re.search(r"confidence:(\d+)", tags)
                entry["implies"].append((n, int(m.group(1)) if m else 100))
            if any(entry[k] for k in ("headers", "cookies", "meta", "html", "scripts", "scriptSrc")) or entry["implies"]:
                apps[name] = entry

        def implies_php(name, seen):
            if name == "PHP":
                return True
            seen.add(name)
            return any(n not in seen and n in apps and implies_php(n, seen) or n == "PHP" for n, _ in apps[name]["implies"])

        for name, e in apps.items():
            e["php"] = implies_php(name, set()) and not (set(e["cats"]) & CLIENT_SIDE_CATS)
        self.by_name = apps
        self.apps = [e for e in apps.values() if any(e[k] for k in ("headers", "cookies", "meta", "html", "scripts", "scriptSrc"))]
        self.updated = time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(os.path.join(self.dir, "fingerprints_data.json"))))
        self.ready, self.error = True, None

    def detect(self, ctx):
        if not self.ready:
            return []
        body = ctx.home.body[:MAX_MATCH] if ctx.home else ""
        js = "\n".join(ctx.page.inline_js)[:MAX_MATCH]
        texts = {"html": (body, body.lower()), "scripts": (js, js.lower())}
        srcs = ctx.page.script_srcs[:200]
        srcs_l = "\n".join(srcs).lower()
        headers = dict(ctx.headers)
        if ctx.raw_cookies:
            headers["set-cookie"] = " | ".join(ctx.raw_cookies)
        cookies = {k.lower(): v for k, v in ctx.cookies.items()}
        meta = ctx.page.meta

        found = {}
        for app in self.apps:
            conf, version, ev = 0, None, []

            def hit(label, ok_ver):
                nonlocal conf, version
                ok, ver = ok_ver
                if ok:
                    ev.append(label)
                    version = version or ver
                return ok

            for name, p in app["headers"]:
                if name in headers and hit(f"header {name}", _pat_match(p, headers[name], headers[name].lower())):
                    conf += p.conf
            for name, p in app["cookies"]:
                if name in cookies and hit(f"cookie {name}", _pat_match(p, cookies[name], cookies[name].lower())):
                    conf += p.conf
            for name, p in app["meta"]:
                if name in meta and hit(f"meta {name}", _pat_match(p, meta[name], meta[name].lower())):
                    conf += p.conf
            for kind in ("html", "scripts"):
                text, text_l = texts[kind]
                for p in app[kind]:
                    if text and hit(kind, _pat_match(p, text, text_l)):
                        conf += p.conf
                        break
            for p in app["scriptSrc"]:
                if p.anchor and p.anchor not in srcs_l:
                    continue
                if any(hit("script src", _pat_match(p, s, s.lower())) for s in srcs):
                    conf += p.conf
                    break
            if ev:
                found[app["name"]] = {"name": app["name"], "category": ", ".join(app["cats"]) or "-", "version": version,
                                      "confidence": min(100, conf), "evidence": [f"[db] {e}" for e in dict.fromkeys(ev)][:6],
                                      "php_implied": app["php"]}
        # Resolve "implies" transitively (e.g. WordPress -> PHP, MySQL).
        queue = list(found)
        while queue:
            parent = found[queue.pop()]
            for n, c in self.by_name.get(parent["name"], {}).get("implies", []):
                if n not in found:
                    e = self.by_name.get(n, {"cats": [], "php": n == "PHP"})
                    found[n] = {"name": n, "category": ", ".join(e["cats"]) or "-", "version": None,
                                "confidence": min(parent["confidence"], c), "evidence": [f"[db] implied by {parent['name']}"],
                                "php_implied": False, "implied": True}
                    queue.append(n)
        return list(found.values())


FPDB = FingerprintDB()


# ----------------------------------------------------------------- analysis

ERR_BANNER_RX = re.compile(r"<address>([^<]{3,160}?) Server at|<center>((?:nginx|openresty)/[^<]{1,60})</center>", re.I)


class Ctx:
    """Everything observed about one target, merged across all responses and redirect hops."""

    def __init__(self, host, rnd, home, err, errphp, errtxt, probes):
        self.host, self.rnd = host, rnd
        self.home, self.err, self.errphp, self.errtxt, self.probes = home, err, errphp, errtxt, probes
        self.headers, self.cookies, self.raw_cookies = {}, {}, []
        responses = [home, err, errphp, errtxt] + list(probes.values())
        for r in [h for r in responses if r for h in r.hops] + responses:
            if not r or not r.status:
                continue
            for k, v in r.headers.items():
                if k not in self.headers:
                    self.headers[k] = v
                elif v not in self.headers[k]:
                    self.headers[k] += " | " + v
            for c in r.cookies:
                self.raw_cookies.append(c)
                n, _, v = c.split(";", 1)[0].partition("=")
                if n.strip():
                    self.cookies.setdefault(n.strip(), v.strip())
        self.cookie_names = list(self.cookies)
        self.page = parse_page(home.body) if home.body else PageParser()
        self.err_body = "\n".join(r.body for r in (err, errphp, errtxt) if r and r.body)
        banners = [self.headers.get("server", "")]
        for m in ERR_BANNER_RX.finditer(self.err_body):
            banners.append((m.group(1) or m.group(2)).strip())
        self.server_banner = " | ".join(b for b in dict.fromkeys(banners) if b)


def _rule_targets(kind, ctx):
    if kind == "html":
        return [ctx.home.body]
    if kind == "err":
        return [ctx.err_body]
    if kind == "cookie":
        return ctx.cookie_names
    if kind == "asset":
        return ctx.page.assets
    if kind.startswith("header:"):
        v = ctx.headers.get(kind[7:])
        return [v] if v is not None else []
    if kind.startswith("meta:"):
        v = ctx.page.meta.get(kind[5:])
        return [v] if v is not None else []
    if kind.startswith("probe:"):
        r = ctx.probes.get(kind[6:])
        return [r.body] if r and r.status and r.status < 500 else []
    return []


def detect_builtin(ctx):
    found = []
    for s in SIGS:
        hits, version = [], None
        for kind, rx in s["rules"]:
            for text in _rule_targets(kind, ctx):
                m = rx.search(text or "")
                if m:
                    hits.append(f"{kind} ~ {m.group(0)[:60]!r}")
                    version = version or (m.groupdict().get("v") if rx.groupindex else None)
                    break
        if hits:
            found.append({"name": s["name"], "category": s["cat"], "version": version,
                          "confidence": min(100, 55 + 20 * (len(hits) - 1)), "evidence": hits, "php_implied": s["php"]})
    return found


def merge_techs(*lists):
    merged = {}
    for lst in lists:
        for t in lst:
            key = t["name"].lower()
            if key not in merged:
                merged[key] = dict(t)
                continue
            m = merged[key]
            if m.get("implied") and not t.get("implied"):
                m["implied"] = False
                m["confidence"] = t["confidence"]
            else:
                m["confidence"] = max(m["confidence"], t["confidence"])
            m["version"] = m["version"] or t["version"]
            m["php_implied"] = m["php_implied"] or t["php_implied"]
            m["evidence"] = list(dict.fromkeys(m["evidence"] + t["evidence"]))[:8]
    return sorted(merged.values(), key=lambda t: (-t["confidence"], t["name"]))


PHP_VER_RX = re.compile(r"\bPHP/(\d+(?:\.\d+){0,2}[^\s;,)|]*)", re.I)
PHPINFO_VER_RXS = [re.compile(p, re.I | re.S) for p in (
    r'<h1 class="p">PHP Version (\d+\.\d+\.\d+[^<\s]*)',
    r'PHP Version\s*</td>\s*<td class="v">\s*(\d+\.\d+\.\d+[^<\s]*)',
    r'PHP Version\s+(\d+\.\d+\.\d+\S*)')]
DISTRO_SERVER_RX = re.compile(r"\((Ubuntu|Debian|CentOS|Red Hat[^)]*|Fedora|AlmaLinux|Rocky[^)]*|Amazon[^)]*|CloudLinux|SUSE|openSUSE)\)", re.I)


def _404_differs(a, b, rnd):
    if not (a and b and a.status and b.status):
        return False
    if a.status != b.status:
        return True
    na = a.body.replace(rnd + ".php", "").replace(rnd, "")
    nb = b.body.replace(rnd + ".txt", "").replace(rnd, "")
    return abs(len(na) - len(nb)) > max(64, 0.2 * max(len(na), len(nb)))


def analyze_php(ctx, techs):
    """Return the PHP fingerprint: detection confidence, version, SAPI/OS hints, evidence, findings."""
    evidence, findings = [], []
    version = source = None
    conf, ancient = 0, False

    sources = [("x-powered-by header", ctx.headers.get("x-powered-by", "")), ("server header", ctx.headers.get("server", "")),
               ("error-page server signature", ctx.server_banner)]
    for label, val in sources:
        m = PHP_VER_RX.search(val)
        if m:
            version, source, conf = m.group(1), label, 95
            evidence.append(f"{label}: PHP/{m.group(1)}")
            findings.append(f"PHP version disclosed via {label} (set expose_php=Off)")
            break
    if not version and re.search(r"\bPHP\b", ctx.headers.get("x-powered-by", ""), re.I):
        conf = max(conf, 90)
        evidence.append("x-powered-by mentions PHP (no version)")

    for path in PHPINFO_PATHS:
        r = ctx.probes.get(path)
        if r and r.status == 200 and re.search(r"phpinfo\(\)|<h1 class=\"p\">PHP Version", r.body):
            conf = 99
            findings.append(f"phpinfo() page publicly exposed at {path}")
            evidence.append(f"phpinfo() at {path}")
            for rx in PHPINFO_VER_RXS:
                m = rx.search(r.body)
                if m:
                    if not version:
                        version, source = m.group(1), f"phpinfo() at {path}"
                    break
            break

    egg = ctx.probes.get(EASTER_EGG)
    if egg and egg.status == 200 and egg.headers.get("content-type", "").lower().startswith("image/"):
        conf, ancient = max(conf, 95), True
        evidence.append("PHP easter-egg logo served (PHP <= 5.4 with expose_php=On)")
    credits = ctx.probes.get(CREDITS_EGG)
    if credits and credits.status == 200 and re.search(r"PHP Credits|Zend Engine|PHP Group", credits.body):
        conf = max(conf, 90)
        evidence.append("PHP credits page reachable (expose_php=On)")
        cm = re.search(r"PHP\s*Version\s*(?:</?[^>]*>)?\s*(\d+\.\d+\.\d+[^\s<\"']*)", credits.body, re.I)
        if cm and not version:
            version, source = cm.group(1), "expose_php credits page"

    # PHP-FPM answers a missing script with exactly "File not found." as the whole body; other servers
    # (e.g. Python's http.server) use the phrase inside a larger error page.
    fpm = bool(ctx.errphp and ctx.errphp.status == 404 and
               re.fullmatch(r"\s*(?:File not found\.|Primary script unknown)\s*", ctx.errphp.body or ""))
    if fpm:
        conf = max(conf, 95)
        evidence.append("random .php path returned the PHP-FPM 'File not found.' response")
    elif _404_differs(ctx.errphp, ctx.errtxt, ctx.rnd):
        conf = max(conf, 60)
        evidence.append("404 for a random .php path differs from .txt (a PHP handler is likely configured)")

    if "PHPSESSID" in ctx.cookies:
        conf = max(conf, 80)
        evidence.append("PHPSESSID cookie")

    for path in COMPOSER_PATHS:
        r = ctx.probes.get(path)
        if r and r.status == 200 and re.search(r'^\s*\{.*"(?:require|packages)"\s*:', r.body or "", re.S):
            conf = max(conf, 70)
            findings.append(f"{path} publicly accessible (dependency disclosure)")
            evidence.append(f"Composer manifest at {path}")

    implied = [t["name"] for t in techs if t.get("php_implied") and not t.get("implied")]
    if implied:
        conf = max(conf, 75)
        evidence.append("PHP software detected: " + ", ".join(implied[:5]))

    php_links = []
    for a in ctx.page.assets:
        u = urllib.parse.urlsplit(a)
        if re.search(r"\.php$", u.path or "") and (not u.netloc or (u.hostname or "").lower() in host_variants(ctx.host)):
            php_links.append(a)
    if php_links:
        conf = max(conf, 55)
        evidence.append(f"{len(php_links)} same-site link(s) to .php URLs")

    banner = ctx.server_banner
    distro = None
    m = DISTRO_SERVER_RX.search(banner)
    if m:
        distro = m.group(1)
    os_hint = next((f"{os_name} (archive PHP {branch})" for rx, os_name, branch in OS_HINTS if re.search(rx, banner)), None)

    sapi = None
    if conf >= 55:
        low = banner.lower()
        if re.search(r"apache[^|]*php/", low):
            sapi = "mod_php (Apache module) - highest-risk SAPI per the PHP advisory"
        elif fpm:
            sapi = "PHP-FPM"
        elif "litespeed" in low or any(t["name"] == "LiteSpeed" for t in techs):
            sapi = "LiteSpeed (LSAPI)"
        elif "apache" in low:
            sapi = "Apache - mod_php or PHP-FPM (not distinguishable remotely)"
        elif "nginx" in low or "openresty" in low:
            sapi = "nginx -> PHP-FPM/FastCGI (typical)"

    # Positive evidence of a non-PHP server-side stack: lets us say INDETERMINATE (banner stripped,
    # could still be PHP) vs NOT_PHP (something else is clearly serving this) when no PHP signal is found.
    non_php = sorted({t["name"] for t in techs if t["name"].lower() in NON_PHP_STACKS})

    return {"detected": conf >= 55, "confidence": conf, "version": version, "version_source": source, "ancient": ancient,
            "sapi": sapi, "distro": distro, "os_hint": os_hint, "server_banner": banner or None, "non_php": non_php,
            "evidence": evidence, "findings": findings, "oracle": None}


def classify_build(version, banner):
    v = version.lower()
    if "sury" in v:
        return "sury"
    if "ubuntu" in v:
        return "ubuntu"
    if re.search(r"[~+]deb\d+|\+b\d+$", v):
        return "debian"
    if re.search(r"\.el\d|\.amzn|\.fc\d|\.module", v):
        return "rpm"
    m = DISTRO_SERVER_RX.search(banner or "")
    if m:
        name = m.group(1).lower()
        if name in ("ubuntu", "debian"):
            # Debian/Ubuntu archive PHP always carries a revision suffix (8.1.2-1ubuntu2.14, 8.2.20-1~deb12u1).
            # A plain version behind a Debian/Ubuntu-tagged Apache is an upstream build, e.g. the official
            # Docker php images, so the upstream version comparison is authoritative.
            return "upstream-on-" + name
        return "rpm-host"  # RHEL-family PHP reports a plain version while carrying backports
    return "upstream"


def _verdict(status, label, note, basis, confidence):
    return {"status": status, "label": label, "note": note, "basis": basis, "confidence": confidence}


def _assess_ubuntu(version):
    upstream = version.split("-", 1)[0]
    for up, fixed, release, usn in UBUNTU_FIXED:
        if upstream == up or upstream.startswith(up + "+"):
            if dpkg_compare(version, fixed) >= 0:
                return _verdict("PATCHED", f"Ubuntu {release} build fixed", f"Package {version} >= {fixed} ({usn}).",
                                "ubuntu package", "high")
            extra = " ESM fixes need Ubuntu Pro." if "ESM" in release else ""
            return _verdict("VULNERABLE", f"Ubuntu {release} build unpatched",
                            f"Package {version} < {fixed} ({usn}). Upgrade with apt.{extra}", "ubuntu package", "high")
    return None


def assess_php(php):
    """Map a PHP fingerprint onto a PHP2Shell verdict."""
    # The active patch oracle is behavioral and version-independent, so it is checked first - it can
    # settle a host even when fingerprinting alone could not identify PHP.
    oracle = php.get("oracle") or {}
    if oracle.get("result") == "vulnerable":
        return _verdict("VULNERABLE", "Actively confirmed unpatched (patch oracle 3/3)",
                        f"Behavioral check at {oracle['path']}: all three session warnings printed, which only an "
                        "unpatched build does. Patch now. (No exploit was run - this reads the patch state, it does "
                        "not confirm end-to-end RCE.)", "patch oracle", "high")
    if oracle.get("result") == "patched":
        return _verdict("PATCHED", "Actively confirmed patched (patch oracle 2/3)",
                        f"Behavioral check at {oracle['path']}: only two of three session warnings printed, as on "
                        "fixed builds.", "patch oracle", "medium")

    if not php["detected"]:
        non_php = php.get("non_php") or []
        if non_php:
            return _verdict("NOT_PHP", "Non-PHP stack", "No PHP found; this host appears to run "
                            + ", ".join(non_php) + " (PHP could still sit behind it).", "fingerprint", "medium")
        if php.get("oracle"):
            return _verdict("INDETERMINATE", "No PHP evidence", "Nothing identified the stack and the active --oracle "
                            "check was inconclusive (no session warnings came back, so display_errors is probably Off). "
                            "Confirm on the host: php -v, the package manager, or --phpinfo.", "fingerprint", "low")
        return _verdict("INDETERMINATE", "No PHP evidence", "Nothing identified the stack: no PHP signal, but no "
                        "other stack either (the banner may be stripped). Re-check on the host, or try --oracle.",
                        "fingerprint", "low")

    v = php["version"]
    hint = f" OS hint: {php['os_hint']}." if php.get("os_hint") else ""
    if not v:
        if php.get("ancient"):
            return _verdict("UNKNOWN", "PHP <= 5.4 (easter egg)", "Ancient, unsupported PHP; 5.4.x is in the affected range."
                            + hint, "fingerprint", "medium")
        return _verdict("UNKNOWN", "PHP, version hidden", "PHP is in use but the version is not disclosed. Treat as exposed "
                        "until confirmed on the host (php -v / package manager) or with the patch oracle." + hint, "fingerprint", "low")

    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    if not m or m.group(2) is None:
        return _verdict("UNKNOWN", f"Major-only version ({v})", "Cannot assess from a major version alone." + hint, "version", "low")
    build = classify_build(v, php.get("server_banner"))
    if build == "ubuntu":
        res = _assess_ubuntu(v)
        if res:
            return res
    mm = (int(m.group(1)), int(m.group(2)))
    patch = int(m.group(3)) if m.group(3) else None
    rpm_like = build in ("rpm", "rpm-host")
    backport = (" The vendor may have backported the fix without changing the version string; check the package "
                "changelog (rpm -q --changelog php / dpkg -l 'php*').")

    if mm > (8, 5):
        return _verdict("UNKNOWN", f"Newer branch ({v})", "Newer than every branch named in the advisory; confirm with the vendor.",
                        "version", "low")
    if mm < EARLIEST_AFFECTED:
        return _verdict("UNKNOWN", f"Pre-5.4 ({v})", "Older than the earliest affected code (5.4.0) but long unsupported.",
                        "version", "medium")
    if mm in FIXED:
        fixed = FIXED[mm]
        fixed_s = ".".join(map(str, fixed))
        if patch is None:
            return _verdict("UNKNOWN", f"Branch only ({v})", f"Branch {v} is fixed from {fixed_s}; the patch level is not disclosed.",
                            "version", "low")
        if (mm[0], mm[1], patch) >= fixed:
            return _verdict("PATCHED", f"Fixed ({v})", f"{v} >= {fixed_s}, the first fixed {mm[0]}.{mm[1]} release.", "version", "high")
        note = f"PHP {v} is older than {fixed_s}, the first fixed {mm[0]}.{mm[1]} release."
        if build == "ubuntu":
            return _verdict("VULNERABLE", "Ubuntu build, release not in USN-8948",
                            note + " This Ubuntu release got no fix (likely end-of-life).", "version", "medium")
        if rpm_like:
            return _verdict("LIKELY_VULNERABLE", "Affected version (backport possible)", note + backport, "version", "medium")
        return _verdict("VULNERABLE", "Affected version", note, "version", "high" if build.startswith("upstream") or build in ("sury", "debian") else "medium")

    # 5.4 - 8.1: affected, no official release.
    eol = mm not in BACKPORT_ONLY
    note = (f"PHP {mm[0]}.{mm[1]} is end-of-life and affected; there is no upstream fix." if eol else
            f"PHP {mm[0]}.{mm[1]} is affected and has no official fixed release (source backports only).")
    if build == "ubuntu":
        return _verdict("VULNERABLE", "Ubuntu build, release not in USN-8948", note + " No Ubuntu fix covers this build.",
                        "version", "medium")
    if build == "sury" or rpm_like or build == "debian":
        return _verdict("LIKELY_VULNERABLE", "EOL branch (vendor backport possible)",
                        note + (" deb.sury.org shipped backports for old branches; check the build date." if build == "sury"
                                else backport), "version", "medium")
    return _verdict("VULNERABLE", "EOL / unfixed branch", note, "version", "high")


# --------------------------------------------------------------- patch oracle

ORACLE_WARNINGS = ("Session ID is too long or contains illegal characters", "Failed to read session data",
                   "Failed to write session data (")


BLOCK_STATUSES = (403, 406, 429, 451)
EVIDENCE_HEADERS = ("server", "x-powered-by", "content-type", "date", "via", "cf-ray", "x-sucuri-id", "x-iinfo", "x-amz-cf-id")


def _excerpt(body, needle, width=70):
    i = body.find(needle)
    if i < 0:
        return None
    return re.sub(r"\s+", " ", body[max(0, i - width): i + len(needle) + width]).strip()[:260]


def _attempt_record(url, headers, body, r):
    """Reproducible record of one oracle request/response. The response body is reduced to hashes and
    excerpts around the matched warnings, so a report does not carry the target's page content."""
    text = r.body or ""
    found = [w in text for w in ORACLE_WARNINGS]
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "request": {"method": "POST", "url": url, "headers": dict(headers), "body": body.decode("ascii", "replace"),
                    "body_bytes": len(body)},
        "response": {"status": r.status or None, "error": r.error,
                     "headers": {k: v for k, v in r.headers.items() if k in EVIDENCE_HEADERS},
                     "body_bytes": len(text.encode("utf-8", "replace")),
                     "body_sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
                     "warnings_found": found,
                     "warning_excerpts": [e for w in ORACLE_WARNINGS for e in [_excerpt(text, w)] if e]},
    }


def _reachability(status, found):
    """Attack-surface context only. 'blocked' means an edge/WAF rejected the request: the exploitation path is
    obstructed, which is NOT the same as patched."""
    if not status:
        return "error"
    if any(found):
        return "executed"  # PHP processed the multipart session path and showed its warnings
    if status in BLOCK_STATUSES:
        return "blocked"
    return "reachable"


REACH_TEXT = {
    "executed": "multipart session upload-progress path reached PHP and was processed",
    "reachable": "multipart POST was accepted (not blocked) but PHP printed no session warnings",
    "blocked": "multipart POST was rejected at the edge/WAF - exploitation path obstructed, NOT the same as patched",
    "error": "no HTTP response to the multipart POST",
}


def session_oracle(base, ctx, techs, opts, ssl_ctx):
    """One small multipart POST with an invalid session id. Needs display_errors=On to be conclusive."""
    cands = []
    home_path = urllib.parse.urlsplit(ctx.home.url).path or "/"
    if PHP_VER_RX.search(ctx.home.headers.get("x-powered-by", "")) or "PHPSESSID" in ctx.cookies or home_path.endswith(".php"):
        cands.append(home_path)
    r = ctx.probes.get("/index.php")
    if r and r.status == 200:
        cands.append("/index.php")
    if any(t["name"] == "WordPress" for t in techs):
        cands.append("/wp-login.php")
    cands = list(dict.fromkeys(cands or ["/"]))[:2]

    boundary = "----p2s" + "".join(random.choices(string.ascii_letters + string.digits, k=16))
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\np2s\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"p2s.txt\"\r\n"
            f"Content-Type: text/plain\r\n\r\nx\r\n--{boundary}--\r\n").encode()
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}", "Cookie": "PHPSESSID=_"}
    last = {"result": "inconclusive", "path": cands[0], "hits": 0, "errors_visible": False,
            "detail": "no session warnings returned - the server likely has display_errors=Off (production "
                      "default), so this behavioral check cannot see the signal. Confirm on the host instead."}
    attempts = []
    final = None
    for path in cands:
        url = base + path
        r = fetch(url, opts["timeout"], ssl_ctx, lambda h: False, method="POST", data=body, headers=headers)
        rec = _attempt_record(url, headers, body, r)
        rec["reachability"] = _reachability(r.status, rec["response"]["warnings_found"])
        attempts.append(rec)
        hits = rec["response"]["warnings_found"]
        # The first warning fires only when PHP actually starts the session and shows errors to the client.
        if all(hits):
            final = {"result": "vulnerable", "path": path, "hits": 3, "errors_visible": True,
                     "detail": "all 3 session warnings printed - this build lacks the fix (session upload-progress "
                               "path is reachable and errors are visible)"}
        elif hits[0] and hits[1]:
            final = {"result": "patched", "path": path, "hits": 2, "errors_visible": True,
                     "detail": "only 2 of 3 session warnings printed, as on fixed builds (the third write path was removed)"}
        elif any(hits):
            last = {"result": "inconclusive", "path": path, "hits": sum(hits), "errors_visible": hits[0],
                    "detail": f"{sum(hits)}/3 warnings in an unexpected pattern - cannot grade safely; confirm on the host"}
        if final:
            break
    out = final or last
    # Overall reachability: the strongest outcome across the attempts.
    rank = ["executed", "reachable", "blocked", "error"]
    out["reachability"] = min((a["reachability"] for a in attempts), key=rank.index) if attempts else "error"
    out["reachability_detail"] = REACH_TEXT[out["reachability"]]
    out["evidence"] = attempts
    return out


# ---------------------------------------------------- offline grading (no network)

def _php_stub(version, **extra):
    base = {"detected": True, "confidence": 100, "version": version, "version_source": None, "ancient": False,
            "sapi": None, "distro": None, "os_hint": None, "server_banner": None, "non_php": [],
            "evidence": [], "findings": [], "oracle": None}
    base.update(extra)
    return base


def grade_version(vstr):
    """Verdict from a PHP version string alone, e.g. from an internal inventory or login banner."""
    m = re.search(r"\d+\.\d+(?:\.\d+)?\S*", vstr or "")
    v = m.group(0) if m else None
    result = {"target": f"PHP {vstr}", "mode": "version", "php": _php_stub(v), "technologies": [], "notes": []}
    result["assessment"] = assess_php(_php_stub(v)) if v else _verdict(
        "UNKNOWN", "Unparsable", f"Could not read a PHP version from {vstr!r}.", "version", "low")
    return result


PHPINFO_SAPI_RX = re.compile(r"Server API\s*(?:=>|</td><td[^>]*>)\s*([A-Za-z0-9 ./_-]+)", re.I)
PHPINFO_INI_RX = re.compile(r"(session\.upload_progress\.enabled|memory_limit|post_max_size)\s*(?:=>|</td><td[^>]*>)\s*"
                            r"([^<\r\n]+?)\s*(?:=>|</td>|[\r\n])", re.I)


def grade_phpinfo(path):
    """Grade a saved phpinfo() dump. Confirms the version and whether the interim mitigations are set."""
    result = {"target": os.path.basename(path), "mode": "phpinfo", "php": None, "technologies": [], "notes": []}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read(4_000_000)
    except OSError as e:
        result["assessment"] = _verdict("ERROR", "Unreadable", str(e), "-", "-")
        return result
    vm = next((m for rx in PHPINFO_VER_RXS for m in [rx.search(text)] if m), None)
    sm = PHPINFO_SAPI_RX.search(text)
    ini = {k.lower(): v.strip() for k, v in PHPINFO_INI_RX.findall(text)}
    php = _php_stub(vm.group(1) if vm else None, version_source=f"phpinfo() dump {os.path.basename(path)}",
                    sapi=(sm.group(1).strip() if sm else None))
    php["findings"] = [f"{k} = {v}" for k, v in ini.items()]
    result["php"] = php
    if not vm:
        result["assessment"] = _verdict("UNKNOWN", "No version", "No 'PHP Version' line in the dump.", "phpinfo", "low")
        return result
    a = assess_php(php)
    # On an unpatched build, note the interim mitigations the dump reveals (not a fix, but useful context).
    upe = ini.get("session.upload_progress.enabled", "").lower()
    if a["status"] in ("VULNERABLE", "LIKELY_VULNERABLE") and upe in ("0", "off", "false", ""):
        if upe:
            a = dict(a, note=a["note"] + " Note: session.upload_progress.enabled is Off (partial mitigation, not a fix).")
    result["assessment"] = a
    return result


# ------------------------------------------------------- scanning a target

def split_target(raw):
    """Return (scheme_or_None, host, port_or_None) or None for blank/comment lines."""
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    has_scheme = "://" in raw
    u = urllib.parse.urlsplit(raw if has_scheme else "//" + raw)
    if not u.hostname:
        return None
    try:
        port = u.port
    except ValueError:
        return None
    return (u.scheme.lower() if has_scheme else None), u.hostname, port


def origin(url):
    u = urllib.parse.urlsplit(url)
    return f"{u.scheme}://{u.netloc}"


def tcp_open(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _error(result, label, msg, started):
    result["error"] = msg
    result["assessment"] = _verdict("ERROR", label, msg, "-", "-")
    result["seconds"] = round(time.time() - started, 2)
    return result


def scan_target(raw, opts):
    started = time.time()
    parts = split_target(raw)
    result = {"target": raw.strip(), "final_url": None, "ip": None, "http_status": None, "title": None, "server": None,
              "technologies": [], "php": None, "assessment": None, "notes": [], "error": None, "seconds": 0}
    if not parts:
        return _error(result, "Invalid target", "Invalid target", started)
    scheme, host, port = parts
    scope = opts.get("scope") or []
    if host.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_.:\-]+", host):
        return _error(result, "Invalid target", f"{host!r} is not a valid host name or address", started)
    if not in_scope(host, scope):
        return _error(result, "Out of scope", "Host is not in the scope list; it was not contacted.", started)
    try:
        result["ip"] = socket.getaddrinfo(host, port or 443, proto=socket.IPPROTO_TCP)[0][4][0]
    except (socket.gaierror, UnicodeError) as e:
        return _error(result, "DNS failure", f"DNS resolution failed: {e}", started)

    variants = host_variants(host)
    allow = (lambda h: h.lower() in variants or (bool(scope) and in_scope(h, scope)))
    ssl_ctx = make_ssl_context(opts["verify_tls"])
    hostport = (f"[{host}]" if ":" in host else host) + (f":{port}" if port else "")
    if scheme:
        cands = [(scheme, port or (443 if scheme == "https" else 80))]
    else:
        cands = [("https", port or 443), ("http", port or 80)]
    # Quick TCP check so dead IPs in a range fail in seconds instead of two full HTTP timeouts.
    open_ports = {p: tcp_open(host, p, min(3.0, opts["timeout"])) for p in dict.fromkeys(p for _, p in cands)}
    if not any(open_ports.values()):
        return _error(result, "No web server", "No open web port (" + ", ".join(map(str, open_ports)) + ")", started)
    bases = [f"{s}://{hostport}" for s, p in cands if open_ports[p]]
    home = None
    for b in bases:
        home = fetch(b + "/", opts["timeout"], ssl_ctx, allow)
        if home.status:
            break
    if not home or not home.status:
        return _error(result, "Unreachable", home.error if home else "No response", started)
    if home.blocked:
        result["notes"].append(f"Redirects off-scope to {home.blocked} (not followed)")

    base = origin(home.url)
    rnd = "p2s" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

    def get(path):
        if opts["delay"]:
            time.sleep(opts["delay"])
        return fetch(base + path, opts["timeout"], ssl_ctx, allow)

    err, errphp, errtxt = get(f"/{rnd}"), get(f"/{rnd}.php"), get(f"/{rnd}.txt")
    probes = {path: get(path) for path in DEEP_PATHS} if opts["deep"] else {}

    ctx = Ctx(host, rnd, home, err, errphp, errtxt, probes)
    techs = merge_techs(detect_builtin(ctx), FPDB.detect(ctx))
    php = analyze_php(ctx, techs)
    # Run the opt-in active oracle on PHP hosts AND on hosts nothing could identify (the hidden-version case
    # this check exists for); skip only hosts positively identified as a non-PHP stack.
    if opts.get("oracle") and (php["detected"] or not php["non_php"]):
        o = php["oracle"] = session_oracle(base, ctx, techs, opts, ssl_ctx)
        php["evidence"].append(f"patch oracle ({o['result']}): {o['detail']}")
        php["evidence"].append(f"attack surface ({o['reachability']}): {o['reachability_detail']}")
        if o["reachability"] == "blocked":
            result["notes"].append("The multipart POST was blocked at the edge/WAF. That obstructs this path but does "
                                   "NOT mean the PHP behind it is patched; the version-based verdict still stands.")
        if o["result"] in ("vulnerable", "patched"):
            # The oracle reached PHP and read its patch state, so PHP is confirmed here.
            php["detected"] = True
            php["confidence"] = max(php["confidence"], 90)
            # Behavior outranks the banner. If they disagree, say so: it usually means a spoofed or proxy-added
            # version header, or a stale/rebuilt image behind the one that was inspected.
            by_version = assess_php(dict(php, oracle=None))["status"]
            behaviour = "VULNERABLE" if o["result"] == "vulnerable" else "PATCHED"
            if php["version"] and {by_version, behaviour} == {"PATCHED", "VULNERABLE"}:
                result["notes"].append(
                    f"The disclosed version (PHP {php['version']}) says {by_version} but the behavioral check says "
                    f"{behaviour}. The behavioral result is used. The version header may be spoofed, set by a proxy, "
                    "or belong to a different backend than the one answering.")
        elif o["result"] == "inconclusive":
            result["notes"].append("Active patch oracle inconclusive: " + o["detail"])
        if o.get("errors_visible"):
            php["findings"].append("Server returns PHP errors to clients (display_errors=On) - a hardening issue of its own.")
    if php["detected"]:
        existing = next((t for t in techs if t["name"] == "PHP"), None)
        if existing:
            existing.update(version=php["version"] or existing["version"], implied=False,
                            confidence=max(existing["confidence"], php["confidence"]))
        else:
            techs.insert(0, {"name": "PHP", "category": "Programming languages", "version": php["version"],
                             "confidence": php["confidence"], "evidence": php["evidence"][:4], "php_implied": False})
    else:
        techs = [t for t in techs if t["name"] != "PHP"]

    result.update({"final_url": home.url, "http_status": home.status, "title": ctx.page.title[:120] or None,
                   "server": ctx.server_banner or None, "technologies": techs, "php": php, "assessment": assess_php(php),
                   "seconds": round(time.time() - started, 2)})
    return result


# ------------------------------------------------------------------ export

def results_to_csv(results):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["target", "final_url", "ip", "http_status", "verdict", "basis", "confidence", "php_version",
                "php_version_source", "php_sapi_hint", "distro", "os_hint", "server", "findings", "technologies", "note",
                "oracle_result", "multipart_surface"])
    for r in results:
        php, a = r.get("php") or {}, r.get("assessment") or {}
        techs = "; ".join(f"{t['name']} {t['version']}" if t.get("version") else t["name"] for t in r.get("technologies", []))
        w.writerow([r["target"], r.get("final_url"), r.get("ip"), r.get("http_status"), a.get("status"), a.get("basis"),
                    a.get("confidence"), php.get("version"), php.get("version_source"), php.get("sapi"), php.get("distro"),
                    php.get("os_hint"), r.get("server"), "; ".join(php.get("findings") or []), techs,
                    a.get("note") or r.get("error"), (php.get("oracle") or {}).get("result"),
                    (php.get("oracle") or {}).get("reachability")])
    return buf.getvalue()


def _curl_for(rec):
    req = rec["request"]
    body = req["body"].replace("\\", "\\\\").replace("'", "\\'").replace("\r", "\\r").replace("\n", "\\n")
    hdrs = " ".join(f"-H '{k}: {v}'" for k, v in req["headers"].items())
    return f"curl -sk -X POST {hdrs} --data-binary $'{body}' '{req['url']}'"


def evidence_report(results):
    """Markdown proof-of-finding for every host where the active oracle ran (attach it to a bug report)."""
    rows = [r for r in results if (r.get("php") or {}).get("oracle", {}) and r["php"]["oracle"].get("evidence")]
    out = ["# PHP2Shell patch-state evidence", "",
           f"Generated {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())} by php2shell-scanner. "
           "CVE-2026-109618 / CVE-2026-109619.", "",
           "> **What this is:** the exact harmless request the scanner sent and the part of the response that shows "
           "the patch state. It reads how PHP handles one malformed session upload; **no exploit was run, no memory "
           "corruption was triggered and nothing was written to the target.** It is evidence of patch state and "
           "attack-surface reachability, not a proof of code execution.", ""]
    if not rows:
        out += ["_No host ran the active oracle. Re-run with `--oracle` to collect request/response evidence._", ""]
    for r in rows:
        php, a, o = r["php"], r["assessment"], r["php"]["oracle"]
        out += [f"## {r['target']}", "",
                f"- **Verdict:** {a['status']} - {a['label']}",
                f"- **Basis / confidence:** {a.get('basis')} / {a.get('confidence')}",
                f"- **Oracle result:** {o['result']} - {o['detail']}",
                f"- **Attack surface:** {o['reachability']} - {o['reachability_detail']}",
                f"- **PHP build:** {php.get('version') or 'not disclosed'}"
                + (f" (from {php['version_source']})" if php.get("version_source") else ""),
                f"- **Server:** {r.get('server') or 'n/a'}" + (f"; OS hint: {php['os_hint']}" if php.get("os_hint") else ""),
                f"- **Resolved IP:** {r.get('ip') or 'n/a'}", ""]
        if a.get("note"):
            out += [f"**Assessment:** {a['note']}", ""]
        for n in r.get("notes") or []:
            out += [f"> Note: {n}", ""]
        for i, rec in enumerate(o["evidence"], 1):
            resp = rec["response"]
            out += [f"### Attempt {i} - `{rec['request']['url']}` ({rec['timestamp']})", "",
                    f"- Reachability: **{rec['reachability']}**",
                    f"- Response: HTTP {resp['status'] or 'no response'}"
                    + (f" ({resp['error']})" if resp.get("error") else "") + f", {resp['body_bytes']} bytes, "
                    f"body sha256 `{resp['body_sha256'][:16]}...`",
                    "- Session warnings seen: " + ", ".join(
                        f"{'yes' if f else 'no'} ({w[:38]}...)" for f, w in zip(resp["warnings_found"], ORACLE_WARNINGS)), ""]
            if resp["headers"]:
                out += ["Response headers (selected):", "", "```"] + [f"{k}: {v}" for k, v in resp["headers"].items()] + ["```", ""]
            if resp["warning_excerpts"]:
                out += ["Response excerpts around the warnings:", "", "```"] + resp["warning_excerpts"] + ["```", ""]
            out += ["Request sent (reproduce with):", "", "```bash", _curl_for(rec), "```", ""]
        out += ["How to read it: all three session warnings = unpatched build; two of three = patched (the fix removes "
                "the third write path); none = inconclusive (display_errors is probably Off).", ""]
    return "\n".join(out)


def assets_summary(results):
    """One 'host|tcp|port,port' line per host that answered, ports sorted (a live-asset inventory)."""
    hosts = {}
    for r in results:
        if (r.get("assessment") or {}).get("status") in (None, "ERROR"):
            continue
        parts = split_target(r.get("final_url") or r["target"])
        if not parts:
            continue
        _, host, port = parts
        u = urllib.parse.urlsplit(r.get("final_url") or "")
        port = port or u.port or (443 if u.scheme == "https" else 80 if u.scheme == "http" else None)
        if port:
            hosts.setdefault(host, set()).add(port)
    return "".join(f"{h}|tcp|{','.join(map(str, sorted(ps)))}\n" for h, ps in sorted(hosts.items()))


# -------------------------------------------------------------------- jobs

class Job:
    def __init__(self, targets, opts):
        self.id = uuid.uuid4().hex[:12]
        self.targets, self.opts = targets, opts
        self.results, self.finished = [], False
        self.lock, self.stop = threading.Lock(), threading.Event()

    def _one(self, t):
        if self.stop.is_set():
            return
        try:
            res = scan_target(t, self.opts)
        except Exception as e:  # never let one target kill the job
            res = _error({"target": t, "technologies": [], "php": None, "notes": []}, "Scan error",
                         f"{type(e).__name__}: {e}", time.time())
        with self.lock:
            self.results.append(res)

    def run(self):
        if not self.opts.get("offline"):
            FPDB.ensure()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.opts["threads"]) as ex:
            list(ex.map(self._one, self.targets))
        self.finished = True


JOBS = {}


def parse_ports(value):
    items = value if isinstance(value, (list, tuple)) else re.split(r"[\s,]+", str(value or ""))
    out = []
    for x in map(str, items):
        x = x.strip()
        if not x:
            continue
        if x.lower() == "web":  # the common-web-ports preset
            out.extend(COMMON_WEB_PORTS)
            continue
        if not x.isdigit() or not 0 < int(x) < 65536:
            raise ValueError(f"Invalid port: {x}")
        out.append(int(x))
    return list(dict.fromkeys(out))[:40]


def _with_ports(host, ports):
    h = f"[{host}]" if ":" in host else host
    return [f"{h}:{p}" for p in ports] if ports else [h]


def expand_target(tok, ports=()):
    """Expand a CIDR range into its hosts, and bare hosts/IPs into host:port for each port given."""
    if "://" in tok:
        return [tok]
    if "/" in tok:
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            net = None
        if net is not None:
            if net.num_addresses * max(1, len(ports)) > MAX_TARGETS + 2:
                raise ValueError(f"{tok} is too large (max {MAX_TARGETS} targets per scan)")
            hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
            return [t for h in hosts for t in _with_ports(h, ports)]
    parts = split_target(tok)
    if parts and parts[2] is None and ports:
        return _with_ports(parts[1], ports)
    return [tok]


def clean_targets(raw_list, ports=()):
    seen, out = set(), []
    lines = [ln for item in raw_list for ln in str(item).splitlines() if not ln.lstrip().startswith("#")]
    for line in lines:
        for tok in re.split(r"[\s,]+", line):
            for t in expand_target(tok, ports) if tok else []:
                if split_target(t) and t not in seen:
                    seen.add(t)
                    out.append(t)
                    if len(out) > MAX_TARGETS:
                        raise ValueError(f"Too many targets after expansion (max {MAX_TARGETS})")
    return out


def clamp(v, lo, hi, default):
    try:
        return max(lo, min(hi, float(v)))
    except (TypeError, ValueError):
        return default


def start_job(body):
    targets = clean_targets(body.get("targets", []), parse_ports(body.get("ports")))
    if not targets:
        raise ValueError("No valid targets")
    scope_in = body.get("scope") or []
    opts = {"deep": bool(body.get("deep")), "verify_tls": bool(body.get("verify_tls")), "oracle": bool(body.get("oracle")),
            "offline": bool(body.get("offline")), "scope": parse_scope(scope_in if isinstance(scope_in, list) else str(scope_in).splitlines()),
            "threads": int(clamp(body.get("threads"), 1, 50, 10)), "timeout": clamp(body.get("timeout"), 2, 60, 10),
            "delay": clamp(body.get("delay"), 0, 5, 0)}
    job = Job(targets, opts)
    JOBS[job.id] = job
    threading.Thread(target=job.run, daemon=True).start()
    return job


# ------------------------------------------------------------------ web UI

HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHP2Shell Scanner</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2025;--mut:#667085;--line:#e3e6eb;--acc:#2f5bea;--red:#c62828;--org:#d9660b;--amb:#a16207;--grn:#18794e;--gry:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;--fg:#e6e8ec;--mut:#9aa3b2;--line:#2a2f38;--acc:#6f90ff;--red:#ff6b6b;--org:#ffa04d;--amb:#e5b84b;--grn:#4cc38a;--gry:#8b93a1}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{padding:18px 24px;border-bottom:1px solid var(--line);background:var(--card)}header h1{margin:0;font-size:18px}header p{margin:4px 0 0;color:var(--mut)}
main{display:grid;grid-template-columns:360px 1fr;gap:16px;padding:16px 24px;align-items:start}
@media(max-width:900px){main{grid-template-columns:1fr;padding:16px}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;min-width:0}
label{display:block;font-weight:600;margin:10px 0 4px}textarea,input[type=number]{width:100%;border:1px solid var(--line);border-radius:8px;padding:8px;background:var(--bg);color:var(--fg);font:13px ui-monospace,Menlo,monospace}
textarea{height:180px;resize:vertical}#scope{height:70px}.row{display:flex;gap:10px}.row>div{flex:1}.chk{display:flex;gap:8px;align-items:flex-start;font-weight:400;margin:8px 0}
.chk input{margin-top:3px}button{border:1px solid var(--line);background:var(--card);color:var(--fg);padding:8px 12px;border-radius:8px;cursor:pointer;font:inherit}
button.primary{background:var(--acc);border-color:var(--acc);color:#fff;font-weight:600}button:disabled{opacity:.5;cursor:not-allowed}
.btns{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;align-items:center}.hint{color:var(--mut);font-size:12px;font-weight:400}
.fp{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-top:12px;padding-top:10px;border-top:1px solid var(--line)}
.bar{height:6px;background:var(--line);border-radius:3px;overflow:hidden;margin:8px 0}.bar>i{display:block;height:100%;width:0;background:var(--acc);transition:width .3s}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}.chip{padding:3px 10px;border:1px solid var(--line);border-radius:999px;cursor:pointer;background:var(--card);font-size:12px}
.chip.on{border-color:var(--acc);color:var(--acc);font-weight:600}.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.03em}tr.r{cursor:pointer}tr.r:hover{background:var(--bg)}
.badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700;color:#fff;white-space:nowrap}
.VULNERABLE{background:var(--red)}.LIKELY_VULNERABLE{background:var(--org)}.UNKNOWN{background:var(--amb)}.INDETERMINATE{background:var(--amb)}.PATCHED{background:var(--grn)}.NOT_PHP,.ERROR{background:var(--gry)}
.tag{display:inline-block;margin:1px 4px 1px 0;padding:1px 7px;border-radius:6px;background:var(--bg);border:1px solid var(--line);font-size:12px}
.det td{background:var(--bg)}.det pre{margin:0;white-space:pre-wrap;word-break:break-word;font:12px ui-monospace,Menlo,monospace}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}.empty{color:var(--mut);padding:30px;text-align:center}.sub{display:block;color:var(--mut);font-size:11px;margin-top:3px}
</style></head><body>
<header><h1>PHP2Shell Scanner</h1>
<p>Technology fingerprinting + triage for CVE-2026-109618 / CVE-2026-109619. Never sends the exploit triggers.</p></header>
<main>
<section class="card">
  <label for="targets">Targets <span class="hint">(hosts, URLs, IPs or CIDR ranges; one per line or comma-separated)</span></label>
  <textarea id="targets" placeholder="example.com&#10;https://app.example.com&#10;192.168.1.20&#10;192.168.1.0/24" spellcheck="false"></textarea>
  <div class="btns"><button id="load">Load file…</button><input id="file" type="file" accept=".txt,.csv" hidden><span class="hint" id="count"></span></div>
  <label for="ports">Ports <span class="hint">(optional; applied to targets without a port, e.g. 80,443,8080,8443)</span></label>
  <input id="ports" type="text" placeholder="default: 443 then 80" spellcheck="false" style="width:100%;border:1px solid var(--line);border-radius:8px;padding:8px;background:var(--bg);color:var(--fg);font:13px ui-monospace,Menlo,monospace">
  <label for="scope">Scope allowlist <span class="hint">(optional; *.example.com = subdomains only; CIDRs allowed)</span></label>
  <textarea id="scope" placeholder="example.com&#10;*.example.com&#10;192.168.1.0/24" spellcheck="false"></textarea>
  <div class="row"><div><label for="threads">Threads</label><input id="threads" type="number" min="1" max="50" value="10"></div>
  <div><label for="timeout">Timeout (s)</label><input id="timeout" type="number" min="2" max="60" value="10"></div>
  <div><label for="delay">Delay (s)</label><input id="delay" type="number" min="0" max="5" step="0.1" value="0"></div></div>
  <label class="chk"><input type="checkbox" id="deep" checked><span>Deep probes <span class="hint">(21 extra GETs per host: wp-login, wp-json, status.php, phpinfo.php, composer.json, /login…)</span></span></label>
  <label class="chk"><input type="checkbox" id="oracle"><span>Active patch oracle <span class="hint">(1-2 small multipart POSTs per host; conclusive only with display_errors=On)</span></span></label>
  <label class="chk"><input type="checkbox" id="verify"><span>Verify TLS certificates</span></label>
  <label class="chk"><input type="checkbox" id="auth"><span><b>I am authorized to test these targets</b> <span class="hint">(in scope of my bug bounty program or engagement)</span></span></label>
  <div class="btns"><button class="primary" id="start">Start scan</button><button id="stop" disabled>Stop</button></div>
  <div class="fp"><span class="hint" id="fp">Fingerprint database: checking…</span><button id="fpup">Update</button></div>
</section>
<section class="card">
  <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
    <b id="prog">No scan yet</b>
    <span><button id="csv" disabled>Export CSV</button> <button id="json" disabled>Export JSON</button> <button id="md" disabled title="Request/response proof from the active oracle, for bug reports">Export evidence</button></span></div>
  <div class="bar"><i id="barfill"></i></div>
  <div class="chips" id="chips"></div>
  <div id="out" class="tw"><div class="empty">Add targets and start a scan.</div></div>
</section>
</main>
<script>
const $=s=>document.querySelector(s);
const ORDER=['VULNERABLE','LIKELY_VULNERABLE','UNKNOWN','INDETERMINATE','PATCHED','NOT_PHP','ERROR'];
let jobId=null,timer=null,results=[],seen=0,total=0,filter='ALL',open=new Set();
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const lines=id=>$(id).value.split(/\r?\n/).filter(l=>!l.trim().startsWith('#'));
function parseTargets(){return lines('#targets').join(' ').split(/[\s,]+/).filter(Boolean)}
function updCount(){const t=parseTargets(),n=new Set(t).size,r=t.some(x=>/^[0-9a-f.:]+\/\d+$/i.test(x));$('#count').textContent=n?n+' entr'+(n>1?'ies':'y')+(r?' (ranges expand on scan)':''):''}
$('#targets').addEventListener('input',updCount);
$('#load').onclick=()=>$('#file').click();
$('#file').onchange=e=>{const f=e.target.files[0];if(!f)return;const r=new FileReader();r.onload=()=>{$('#targets').value=r.result;updCount()};r.readAsText(f)};
async function api(path,opt){const r=await fetch(path,opt);if(!r.ok)throw new Error((await r.json().catch(()=>({}))).error||r.statusText);return r.json()}
async function fpStatus(){
  try{const s=await api('/api/fp');
    $('#fp').textContent=s.loading?'Fingerprint database: loading…':s.ready?'Fingerprint database: '+s.apps.toLocaleString()+' technologies (updated '+s.updated+')':'Fingerprint database: '+(s.error?'unavailable - '+s.error:'downloads on first scan');
    $('#fpup').disabled=s.loading;if(s.loading)setTimeout(fpStatus,1500);
  }catch(e){$('#fp').textContent='Fingerprint database: status unavailable'}
}
$('#fpup').onclick=async()=>{await api('/api/fp/update',{method:'POST'}).catch(e=>alert(e.message));fpStatus()};
fpStatus();
$('#start').onclick=async()=>{
  if(!$('#auth').checked){alert('Confirm you are authorized to test these targets.');return}
  const targets=parseTargets();if(!targets.length){alert('Add at least one target.');return}
  try{
    const j=await api('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      targets,ports:$('#ports').value,scope:lines('#scope'),authorized:true,deep:$('#deep').checked,oracle:$('#oracle').checked,verify_tls:$('#verify').checked,
      threads:+$('#threads').value,timeout:+$('#timeout').value,delay:+$('#delay').value})});
    jobId=j.id;total=j.total;results=[];seen=0;open.clear();filter='ALL';
    $('#start').disabled=true;$('#stop').disabled=false;$('#csv').disabled=$('#json').disabled=$('#md').disabled=false;
    render();poll();setTimeout(fpStatus,800);
  }catch(e){alert(e.message)}
};
$('#stop').onclick=async()=>{if(jobId)await api('/api/stop/'+jobId,{method:'POST'}).catch(()=>{})};
$('#csv').onclick=()=>{location='/api/export/'+jobId+'.csv'};
$('#json').onclick=()=>{location='/api/export/'+jobId+'.json'};
$('#md').onclick=()=>{location='/api/export/'+jobId+'.md'};
async function poll(){
  clearTimeout(timer);
  try{
    const j=await api('/api/jobs/'+jobId+'?since='+seen);
    results.push(...j.results);seen+=j.results.length;total=j.total;render();
    if(j.finished){$('#start').disabled=false;$('#stop').disabled=true;fpStatus();return}
  }catch(e){}
  timer=setTimeout(poll,1000);
}
function techs(r){return (r.technologies||[]).filter(t=>!t.implied||t.name==='PHP').slice(0,10).map(t=>'<span class="tag" title="'+esc(t.category+' ('+t.confidence+'%)')+'">'+esc(t.name+(t.version?' '+t.version:''))+'</span>').join('')}
function detail(r){
  const p=r.php||{},a=r.assessment||{};
  let s='Verdict: '+(a.status||'')+' - '+(a.label||'')+'  [basis: '+(a.basis||'-')+', confidence: '+(a.confidence||'-')+']\n'+(a.note||r.error||'')+'\n\n';
  s+='Final URL: '+(r.final_url||'-')+'   IP: '+(r.ip||'-')+'   HTTP: '+(r.http_status||'-')+'   Title: '+(r.title||'-')+'\n';
  s+='Server: '+(r.server||'-')+'\n';(r.notes||[]).forEach(x=>s+='Note: '+x+'\n');
  if(p.detected){s+='\nPHP: '+(p.version||'version hidden')+(p.version_source?' (from '+p.version_source+')':'')+'  detection confidence '+p.confidence+'%\n';
    if(p.sapi)s+='SAPI hint: '+p.sapi+'\n';if(p.distro)s+='Distro: '+p.distro+'\n';if(p.os_hint)s+='OS hint: '+p.os_hint+'\n';
    (p.findings||[]).forEach(x=>s+='Finding: '+x+'\n');(p.evidence||[]).forEach(x=>s+='Evidence: '+x+'\n')}
  s+='\nTechnologies:\n';(r.technologies||[]).forEach(t=>{s+=' - '+t.name+(t.version?' '+t.version:'')+' ['+t.category+', '+t.confidence+'%]\n';(t.evidence||[]).forEach(e=>s+='     '+e+'\n')});
  return s;
}
function render(){
  const counts={};results.forEach(r=>{const k=(r.assessment||{}).status||'ERROR';counts[k]=(counts[k]||0)+1});
  $('#prog').textContent='Scanned '+results.length+' / '+total;
  $('#barfill').style.width=(total?100*results.length/total:0)+'%';
  $('#chips').innerHTML=['ALL',...ORDER].filter(k=>k==='ALL'||counts[k]).map(k=>'<span class="chip'+(filter===k?' on':'')+'" data-k="'+k+'">'+k.replace('_',' ')+' '+(k==='ALL'?results.length:counts[k])+'</span>').join('');
  document.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{filter=c.dataset.k;render()});
  const rows=results.filter(r=>filter==='ALL'||(r.assessment||{}).status===filter)
    .sort((a,b)=>ORDER.indexOf((a.assessment||{}).status)-ORDER.indexOf((b.assessment||{}).status));
  if(!rows.length){$('#out').innerHTML='<div class="empty">'+(results.length?'No results in this filter.':'Waiting for results…')+'</div>';return}
  $('#out').innerHTML='<table><thead><tr><th>Target</th><th>Verdict</th><th>PHP</th><th>Stack</th></tr></thead><tbody>'+rows.map(r=>{
    const a=r.assessment||{},p=r.php||{},k=esc(r.target),i=results.indexOf(r);
    return '<tr class="r" data-i="'+i+'"><td class="mono">'+k+'</td><td><span class="badge '+esc(a.status)+'">'+esc(a.status)+'</span><span class="sub">'+esc(a.basis||'')+(a.confidence&&a.confidence!=='-'?' · '+esc(a.confidence):'')+'</span></td><td class="mono">'+esc(p.version||(p.detected?'hidden':'-'))+'</td><td>'+(techs(r)||'<span class="hint">'+esc(r.error||'-')+'</span>')+'</td></tr>'
      +(open.has(i)?'<tr class="det"><td colspan="4"><pre>'+esc(detail(r))+'</pre></td></tr>':'');
  }).join('')+'</tbody></table>';
  document.querySelectorAll('tr.r').forEach(tr=>tr.onclick=()=>{const i=+tr.dataset.i;open.has(i)?open.delete(i):open.add(i);render()});
}
</script></body></html>
"""


NEED_TOKEN_PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access token needed</title><style>body{font:15px/1.5 -apple-system,sans-serif;max-width:520px;margin:15vh auto;padding:0 16px;color:#1c2025;background:#f6f7f9}
@media (prefers-color-scheme:dark){body{color:#e6e8ec;background:#0f1115}}</style></head>
<body><h2>Access token needed</h2><p>This scanner is shared on the local network. Open the full link printed in the
terminal where it was started (it ends with <code>?token=…</code>).</p></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "php2shell-scanner"
    token = None  # set in LAN mode: every request must carry it

    def log_message(self, *args):
        pass

    def _host_ok(self):
        if self.token is None:  # localhost-only mode: also blocks DNS rebinding
            return self.headers.get("Host", "").rsplit(":", 1)[0] in ("127.0.0.1", "localhost")
        m = re.search(r"(?:^|;\s*)p2s_token=([^;\s]+)", self.headers.get("Cookie", ""))
        return bool(m) and hmac.compare_digest(m.group(1), self.token)

    def _deny(self):
        if self.token is None:
            return self._json({"error": "bad host"}, 403)
        return self._send(401, NEED_TOKEN_PAGE, "text/html; charset=utf-8")

    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        given = urllib.parse.parse_qs(u.query).get("token", [""])[0]
        if self.token and u.path == "/" and given and hmac.compare_digest(given, self.token):
            # Swap the token in the link for a cookie, then drop it from the address bar.
            return self._send(302, "", "text/plain", {"Location": "/",
                              "Set-Cookie": f"p2s_token={self.token}; Path=/; HttpOnly; SameSite=Strict"})
        if not self._host_ok():
            return self._deny()
        if u.path == "/":
            return self._send(200, HTML, "text/html; charset=utf-8")
        if u.path == "/api/fp":
            return self._json(FPDB.status())
        m = re.fullmatch(r"/api/jobs/([0-9a-f]+)", u.path)
        if m and m.group(1) in JOBS:
            job = JOBS[m.group(1)]
            try:
                since = max(0, int(urllib.parse.parse_qs(u.query).get("since", ["0"])[0] or 0))
            except ValueError:
                since = 0
            with job.lock:
                new = job.results[since:]
            return self._json({"total": len(job.targets), "finished": job.finished, "results": new})
        m = re.fullmatch(r"/api/export/([0-9a-f]+)\.(csv|json|md)", u.path)
        if m and m.group(1) in JOBS:
            job = JOBS[m.group(1)]
            with job.lock:
                res = sorted(job.results, key=lambda r: RISK_ORDER.get((r.get("assessment") or {}).get("status"), 9))
            disp = {"Content-Disposition": f'attachment; filename="php2shell-scan-{job.id}.{m.group(2)}"'}
            if m.group(2) == "csv":
                return self._send(200, results_to_csv(res), "text/csv; charset=utf-8", disp)
            if m.group(2) == "md":
                return self._send(200, evidence_report(res), "text/markdown; charset=utf-8", disp)
            return self._send(200, json.dumps(res, indent=2), "application/json", disp)
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._host_ok():
            return self._deny()
        origin_hdr = self.headers.get("Origin")
        if origin_hdr and urllib.parse.urlsplit(origin_hdr).netloc != self.headers.get("Host"):
            return self._json({"error": "cross-origin request refused"}, 403)
        if self.path == "/api/scan":
            if "application/json" not in (self.headers.get("Content-Type") or ""):
                return self._json({"error": "expected JSON"}, 415)
            length = int(self.headers.get("Content-Length") or 0)
            if length > 2_000_000:
                return self._json({"error": "request too large"}, 413)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if not body.get("authorized"):
                    return self._json({"error": "Confirm you are authorized to test these targets."}, 400)
                job = start_job(body)
            except (ValueError, TypeError) as e:
                return self._json({"error": str(e)}, 400)
            return self._json({"id": job.id, "total": len(job.targets)})
        if self.path == "/api/fp/update":
            if not FPDB.loading:
                threading.Thread(target=FPDB.update, daemon=True).start()
            return self._json({"ok": True})
        m = re.fullmatch(r"/api/stop/([0-9a-f]+)", self.path)
        if m and m.group(1) in JOBS:
            JOBS[m.group(1)].stop.set()
            return self._json({"ok": True})
        self._json({"error": "not found"}, 404)


def lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))  # UDP connect sends nothing; it just picks the outgoing interface
            return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def serve(port, open_browser, offline, bind="127.0.0.1"):
    local_only = bind in ("127.0.0.1", "localhost")
    Handler.token = None if local_only else secrets.token_urlsafe(18)
    for p in range(port, port + 10):
        try:
            httpd = ThreadingHTTPServer((bind, p), Handler)
            break
        except OSError:
            continue
    else:
        sys.exit(f"No free port in {port}-{port + 9} on {bind}")
    threading.Thread(target=FPDB.ensure, kwargs={"allow_download": not offline}, daemon=True).start()
    query = f"?token={Handler.token}" if Handler.token else ""
    url = f"http://{'127.0.0.1' if bind == '0.0.0.0' else bind}:{p}/{query}"
    print(f"php2shell-scanner GUI: {url}  (Ctrl+C to quit)", flush=True)
    if not local_only:
        print(f"Local network link:    http://{lan_ip() if bind == '0.0.0.0' else bind}:{p}/{query}", flush=True)
        print("Anyone with this link can run scans from this machine. Share it only with people you trust.", flush=True)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()


# --------------------------------------------------------------------- CLI

def _emit_cli(res, args):
    res = sorted(res, key=lambda r: RISK_ORDER.get((r.get("assessment") or {}).get("status"), 9))
    for r in res:
        a, php = r["assessment"], r.get("php") or {}
        stack = ", ".join(t["name"] for t in r.get("technologies", []) if not t.get("implied"))[:70]
        ver = php.get("version") if php else None
        ver = ver or ("hidden" if php and php.get("detected") else "-")
        print(f"{a['status']:<18} {r['target']:<38} php={ver:<26} {a.get('basis', '-'):<15} {stack}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(res, f, indent=2)
    if args.csv:
        with open(args.csv, "w", newline="") as f:
            f.write(results_to_csv(res))
    if args.assets:
        with open(args.assets, "w") as f:
            f.write(assets_summary(res))
    if args.evidence:
        with open(args.evidence, "w") as f:
            f.write(evidence_report(res))
    return 2 if any((r.get("assessment") or {}).get("status") in ("VULNERABLE", "LIKELY_VULNERABLE") for r in res) else 0


def run_cli(args):
    # Offline grading modes send no traffic, so they need no authorization.
    if args.version_string:
        return _emit_cli([grade_version(args.version_string)], args)
    if args.phpinfo:
        return _emit_cli([grade_phpinfo(args.phpinfo)], args)

    if not args.authorized:
        sys.exit("Refusing to scan: pass --authorized to confirm you are allowed to test these targets.")
    raw = list(args.target)
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            raw += f.read().splitlines()
    scope = []
    if args.scope:
        with open(args.scope, encoding="utf-8", errors="replace") as f:
            scope = f.read().splitlines()
    FPDB.ensure(allow_download=not args.offline)
    if FPDB.error:
        print(f"warning: fingerprint database unavailable ({FPDB.error}); using built-in signatures only", file=sys.stderr)
    job = start_job({"targets": raw, "ports": args.ports, "scope": scope, "deep": args.deep, "oracle": args.oracle, "verify_tls": args.verify_tls,
                     "threads": args.threads, "timeout": args.timeout, "delay": args.delay, "offline": True})
    print(f"Scanning {len(job.targets)} target(s)...", file=sys.stderr)
    while not job.finished:
        time.sleep(0.5)
        print(f"\r  {len(job.results)}/{len(job.targets)}", end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)
    return _emit_cli(job.results, args)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cli", action="store_true", help="run headless instead of starting the GUI")
    ap.add_argument("-t", "--target", action="append", default=[], help="target host/URL/IP/CIDR (repeatable)")
    ap.add_argument("-f", "--file", help="file with one target per line")
    ap.add_argument("--ports", default="", help="ports for targets without one, e.g. 80,443,8080 or 'web' preset (default: 443 then 80)")
    ap.add_argument("--scope", help="scope allowlist file (example.com / *.example.com / 192.168.1.0/24 per line)")
    ap.add_argument("--authorized", action="store_true", help="confirm you are authorized to test the targets (CLI)")
    ap.add_argument("--deep", action="store_true", help="also fetch well-known paths (wp-json, status.php, phpinfo.php, ...)")
    ap.add_argument("--oracle", action="store_true", help="send the 1-request session-warning patch oracle to PHP hosts")
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--delay", type=float, default=0, help="seconds between requests to one host")
    ap.add_argument("--verify-tls", action="store_true")
    ap.add_argument("--json", help="write JSON results here")
    ap.add_argument("--csv", help="write CSV results here")
    ap.add_argument("--assets", help="write a host|tcp|ports live-asset inventory here")
    ap.add_argument("--evidence", help="write a Markdown evidence report (request/response of the --oracle check) here")
    ap.add_argument("--version-string", help="offline: grade a PHP version string (e.g. 8.3.12), no network")
    ap.add_argument("--phpinfo", help="offline: grade a saved phpinfo() HTML/text dump, no network")
    ap.add_argument("--offline", action="store_true", help="never download the fingerprint database")
    ap.add_argument("--update-fingerprints", action="store_true", help="download the latest fingerprint database and exit")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--lan", action="store_true", help="serve the GUI on the local network (token-protected)")
    ap.add_argument("--host", default="127.0.0.1", help="GUI bind address (default 127.0.0.1; --lan = 0.0.0.0)")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    if args.update_fingerprints:
        FPDB.update()
        s = FPDB.status()
        if s["error"]:
            sys.exit(f"error: {s['error']}")
        print(f"{s['apps']} technologies cached in {s['dir']}")
        return
    if args.cli or args.version_string or args.phpinfo:
        try:
            sys.exit(run_cli(args))
        except ValueError as e:  # bad port, oversized range, no valid targets
            sys.exit(f"error: {e}")
    serve(args.port, not args.no_browser, args.offline, "0.0.0.0" if args.lan else args.host)


if __name__ == "__main__":
    main()
