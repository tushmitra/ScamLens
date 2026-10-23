"""Static URL inspection for ScamLens.

Every check here is local string/hostname analysis. Nothing is fetched, resolved
or executed: no DNS lookups, no redirects followed, no page content loaded.
Indicators are heuristics, not proof of fraud; an unflagged URL is not "safe".

Public interface (unchanged from the notebook version):
    extract_urls(text) -> list[str]
    inspect_url(url)   -> {url, valid, hostname, flags, reasons, ...}
    check_message_urls(message) -> {url_count, urls, has_suspicious_url, reasons, disclaimer}

Differences from the notebook prototype, all covered by tests:
  * the registrable domain is computed with a small multi-part-suffix list, so a
    genuine host such as ``www.sbi.co.in`` is no longer read as "sbi in a subdomain";
  * brand matching uses hyphen-delimited tokens, not substrings
    (``responsibility.example.com`` does not contain the brand "sbi");
  * obfuscated numeric IP hosts (``http://3232235777/``) are flagged;
  * scheme-less links to shorteners or with a path on a common TLD
    (``bit.ly/x``, ``sbi-kyc.top/login``) are extracted, a frequent SMS-scam form.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import urlsplit

DISCLAIMER = (
    "Indicators are heuristic, not proof of fraud. "
    "An unflagged URL is not guaranteed safe."
)

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "rebrand.ly", "tiny.cc", "lnkd.in", "shorturl.at",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "work", "gq", "tk", "ml", "cf", "ga", "rest", "fit",
}

# Brands commonly impersonated in India-focused scam messages. A heuristic list.
BRANDS = {
    "google", "microsoft", "apple", "amazon", "paypal", "facebook", "instagram",
    "whatsapp", "netflix", "sbi", "hdfc", "hdfcbank", "icici", "icicibank",
    "axisbank", "onlinesbi", "irctc", "uidai", "paytm", "phonepe",
}

# Public suffixes made of two labels that matter for registrable-domain parsing.
MULTI_PART_SUFFIXES = {
    "co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "res.in", "edu.in",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.za", "com.sg", "com.my", "com.br", "co.jp",
}

# Used only to recognise scheme-less links such as "example.com/login".
COMMON_TLDS = {
    "com", "in", "net", "org", "info", "biz", "co", "io", "me", "xyz", "online",
    "site", "shop", "store", "club", "app", "link", "live", "icu", "vip",
} | SUSPICIOUS_TLDS

_URL_WITH_SCHEME = r"(?:https?://|www\.)[^\s<>\"']+"
_BARE_HOST = r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}"
URL_PATTERN = re.compile(
    rf"(?i)(?<![\w@./-])(?:{_URL_WITH_SCHEME}|{_BARE_HOST}/[^\s<>\"']*)"
)
_BARE_SHORTENER_PATTERN = re.compile(
    r"(?i)(?<![\w@./-])(?:" + "|".join(re.escape(h) for h in sorted(SHORTENERS)) + r")(?:/[^\s<>\"']*)?(?![\w.-])"
)

_NUMERIC_HOST = re.compile(r"(?i)(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}")
_MAX_URLS = 20


def _clean_url(url: str) -> str:
    """Strip trailing sentence punctuation without damaging balanced brackets."""
    url = url.strip()
    while url and url[-1] in ".,!?;:)]}":
        last = url[-1]
        if last == ")" and url.count("(") >= url.count(")"):
            break
        if last == "]" and url.count("[") >= url.count("]"):
            break
        if last == "}" and url.count("{") >= url.count("}"):
            break
        url = url[:-1]
    return url


def _normalize(url: str) -> str:
    if url.lower().startswith("www."):
        return "https://" + url
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", url):
        return "https://" + url
    return url


def _bare_host_is_plausible(candidate: str) -> bool:
    host = re.split(r"[/?#]", candidate, maxsplit=1)[0].lower()
    tld = host.rsplit(".", 1)[-1]
    if host in SHORTENERS:
        return True
    if ".".join(host.split(".")[-2:]) in MULTI_PART_SUFFIXES:
        return True
    return tld in COMMON_TLDS


def extract_urls(text: str) -> List[str]:
    """Extract URLs (http/https/www, plus scheme-less shortener or path links) without visiting them."""
    found: List[str] = []
    seen = set()
    candidates = [m.group(0) for m in URL_PATTERN.finditer(text or "")]
    candidates += [m.group(0) for m in _BARE_SHORTENER_PATTERN.finditer(text or "")]
    for raw in candidates:
        url = _clean_url(raw)
        if not url:
            continue
        has_scheme = bool(re.match(r"(?i)^(?:https?://|www\.)", url))
        if not has_scheme and not _bare_host_is_plausible(url):
            continue
        url = _normalize(url)
        if url not in seen:
            found.append(url)
            seen.add(url)
        if len(found) >= _MAX_URLS:
            break
    return found


def registrable_domain(hostname: str) -> str:
    """Best-effort registrable domain (eTLD+1) for an ASCII hostname."""
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _tokens(label: str) -> List[str]:
    return [t for t in label.split("-") if t]


def inspect_url(url: str) -> Dict[str, Any]:
    """Return static URL indicators. No network requests are made."""
    url = _normalize(_clean_url((url or "").strip()))

    flags: List[str] = []
    reasons: List[str] = []

    def add(flag: str, reason: str) -> None:
        if flag not in flags:
            flags.append(flag)
            reasons.append(reason)

    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"}:
            raise ValueError("Unsupported scheme")
        hostname = parts.hostname
        if not parts.netloc or not hostname:
            raise ValueError("Missing hostname")
        hostname = hostname.rstrip(".").lower()
        _ = parts.port  # validates malformed ports
    except (ValueError, UnicodeError):
        add("malformed_url", "The URL could not be parsed reliably.")
        return {"url": url, "valid": False, "hostname": None, "flags": flags, "reasons": reasons}

    if parts.username is not None or parts.password is not None:
        add("userinfo_present", "Text before the host may be used to make a URL misleading.")

    if parts.scheme.lower() != "https":
        add("not_https", "The URL does not use HTTPS.")

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = bool(_NUMERIC_HOST.fullmatch(hostname))  # decimal/hex/octal-style IP tricks
    if is_ip:
        add("ip_host", "The URL uses a raw or obfuscated IP address as its host.")

    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = hostname
        add("invalid_idn", "The hostname could not be normalized reliably.")

    if "xn--" in ascii_host:
        add("punycode_hostname", "The hostname uses punycode; verify it carefully.")

    labels = ascii_host.split(".")
    domain = ascii_host if is_ip else registrable_domain(ascii_host)
    domain_labels = domain.split(".")
    subdomain_labels = labels[: len(labels) - len(domain_labels)]

    if len(labels) >= 2 and labels[-1] in SUSPICIOUS_TLDS:
        add("uncommon_tld", "The hostname ends in a TLD on the review list.")

    if len(subdomain_labels) >= 3:
        add("many_subdomains", "The hostname has several subdomain levels.")

    if len(ascii_host) > 100:
        add("long_hostname", "The hostname is unusually long.")

    if hostname in SHORTENERS:
        add("url_shortener", "The URL uses a known shortening service.")

    if not is_ip and subdomain_labels:
        # Strong heuristic: a brand token in a subdomain while the registrable domain
        # is something else. Parsed against the registrable domain, not by substring.
        domain_core_tokens = {t for lab in domain_labels[:-1] for t in _tokens(lab)}
        for brand in sorted(BRANDS):
            if any(brand in _tokens(label) for label in subdomain_labels):
                if brand not in domain_core_tokens:
                    add("brand_in_subdomain", f"'{brand}' appears in a subdomain, not in the main domain.")
                    break

    if not is_ip and len(domain_labels) >= 2:
        # Weaker heuristic: brand hyphenated with other words in the main domain
        # (e.g. "sbi-kyc-update.com"). Real brand domains rarely look like this.
        toks = _tokens(domain_labels[0])  # first label of the registrable domain
        if len(toks) >= 2:
            for brand in sorted(BRANDS):
                if brand in toks:
                    add("brand_in_domain_label", f"'{brand}' is combined with other words in the domain name.")
                    break

    return {
        "url": url,
        "valid": True,
        "scheme": parts.scheme.lower(),
        "hostname": hostname,
        "registrable_domain": domain,
        "flags": flags,
        "reasons": reasons,
    }


def check_message_urls(message: str) -> Dict[str, Any]:
    """Inspect all extracted URLs and summarize warning indicators."""
    urls = [inspect_url(url) for url in extract_urls(message or "")]
    flagged = [item for item in urls if item["flags"]]

    reasons: List[str] = []
    if flagged:
        reasons.append(f"{len(flagged)} of {len(urls)} URL(s) have review indicators.")

    return {
        "url_count": len(urls),
        "urls": urls,
        "has_suspicious_url": bool(flagged),
        "reasons": reasons,
        "disclaimer": DISCLAIMER,
    }
