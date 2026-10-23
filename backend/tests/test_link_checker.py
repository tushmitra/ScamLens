from helpers import BACKEND  # noqa: F401  (sets sys.path)

from app.link_checker import check_message_urls, extract_urls, inspect_url, registrable_domain


def flags(url):
    return inspect_url(url)["flags"]


# ---- extraction -----------------------------------------------------------

def test_no_url():
    assert extract_urls("No link here at all.") == []
    assert check_message_urls("Hello")["url_count"] == 0
    assert check_message_urls("Hello")["has_suspicious_url"] is False


def test_trailing_punctuation_is_stripped_but_path_is_kept():
    assert extract_urls("Visit https://example.com/test.") == ["https://example.com/test"]
    assert extract_urls("See (https://example.com/a_(b)).") == ["https://example.com/a_(b)"]
    assert extract_urls("Go to https://example.com/path?x=1&y=2, now") == ["https://example.com/path?x=1&y=2"]


def test_multiple_and_duplicate_urls():
    found = extract_urls("Links: https://example.com and https://bit.ly/example and https://example.com")
    assert found == ["https://example.com", "https://bit.ly/example"]


def test_www_and_scheme_less_links():
    assert extract_urls("open www.example.in/page") == ["https://www.example.in/page"]
    assert extract_urls("Pay at bit.ly/Abc12 today") == ["https://bit.ly/Abc12"]
    assert extract_urls("verify at sbi-kyc.top/login") == ["https://sbi-kyc.top/login"]


def test_ordinary_text_is_not_mistaken_for_a_url():
    text = "Mail john@example.com/x, Rs.500/month, e.g. and/or this/that, file.pdf"
    assert extract_urls(text) == []


def test_url_count_is_capped():
    text = " ".join(f"https://h{i}.example.com" for i in range(60))
    assert len(extract_urls(text)) == 20


# ---- indicators -----------------------------------------------------------

def test_plain_https_url_has_no_flags():
    assert flags("https://example.com/account") == []


def test_not_https():
    assert "not_https" in flags("http://example.com")


def test_ip_hosts_including_obfuscated():
    assert "ip_host" in flags("http://192.0.2.10/login")
    assert "ip_host" in flags("https://[2001:db8::1]/x")
    assert "ip_host" in flags("http://3232235777/")  # decimal form of 192.168.1.1
    assert "ip_host" in flags("http://0xC0A80101/")


def test_userinfo_trick():
    assert "userinfo_present" in flags("https://trusted.example@evil.test/login")


def test_punycode_and_unicode_idn():
    assert "punycode_hostname" in flags("https://xn--pypal-4ve.com")
    assert "punycode_hostname" in flags("https://pаypal.com")  # Cyrillic a


def test_shortener_and_uncommon_tld():
    assert "url_shortener" in flags("https://bit.ly/x")
    assert "uncommon_tld" in flags("https://claim-prize.top/x")


def test_many_subdomains():
    assert "many_subdomains" in flags("https://a.b.c.d.example.com")
    assert "many_subdomains" not in flags("https://www.example.com")


def test_brand_in_subdomain():
    assert "brand_in_subdomain" in flags("https://paypal.evil.test/login")
    assert "brand_in_subdomain" in flags("https://paypal.com.evil.test")
    assert "brand_in_subdomain" in flags("https://sbi-secure.verify.example.org")


def test_genuine_brand_domains_are_not_flagged():
    assert flags("https://www.paypal.com/signin") == []
    assert flags("https://www.sbi.co.in/web/personal-banking") == []
    assert flags("https://paypal.co.uk") == []
    assert flags("https://netbanking.hdfcbank.com/login") == []


def test_brand_match_is_token_based_not_substring():
    assert "brand_in_subdomain" not in flags("https://responsibility.example.com")  # contains 'sbi'
    assert "brand_in_subdomain" not in flags("https://pineapple.example.com")  # contains 'apple'


def test_brand_hyphenated_in_domain_is_a_weak_flag():
    assert "brand_in_domain_label" in flags("https://sbi-kyc-update.com/x")


def test_malformed_urls_do_not_raise():
    for bad in ["http://", "https://exa mple.com:99999999", "ftp://example.com", "https://:80", ""]:
        result = inspect_url(bad)
        assert result["flags"] or result["valid"], bad
    assert inspect_url("ftp://example.com")["valid"] is False


def test_every_flag_has_a_reason():
    result = inspect_url("http://user@192.0.2.1.top/x")
    assert len(result["flags"]) == len(result["reasons"]) >= 2


def test_message_level_summary():
    result = check_message_urls("Your account needs verification: https://bit.ly/example")
    assert result["url_count"] == 1
    assert result["has_suspicious_url"] is True
    assert "not guaranteed safe" in result["disclaimer"]


def test_registrable_domain():
    assert registrable_domain("www.sbi.co.in") == "sbi.co.in"
    assert registrable_domain("a.b.example.com") == "example.com"
    assert registrable_domain("example.com") == "example.com"
    assert registrable_domain("localhost") == "localhost"


def test_checker_makes_no_network_calls():
    import socket

    original = socket.socket.connect

    def forbidden(*args, **kwargs):
        raise AssertionError("link checker attempted a network connection")

    socket.socket.connect = forbidden
    try:
        check_message_urls("https://example.com http://192.0.2.1 https://bit.ly/x https://xn--pypal-4ve.com")
    finally:
        socket.socket.connect = original
