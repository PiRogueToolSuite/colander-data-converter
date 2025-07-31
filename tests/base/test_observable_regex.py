import json
import os
import re

import pytest

# Load observable types
JSON_PATH = os.path.join(os.path.dirname(__file__), "../../colander_data_converter/data/types/observable_types.json")
with open(JSON_PATH) as f:
    TYPES = json.load(f)


def get_regex_types():
    return [t for t in TYPES if t.get("regex")]


@pytest.mark.parametrize("type_obj", get_regex_types())
def test_regex_valid(type_obj):
    regex = type_obj["regex"]
    short_name = type_obj["short_name"]
    pattern = re.compile(regex, re.IGNORECASE)

    valid_cases = {
        "IPV4": ["192.168.1.1", "0.0.0.0", "255.255.255.255", "8.8.8.8", "127.0.0.1"],
        "IPV6": [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "fe80::1ff:fe23:4567:890a",
            "::1",
            "2001:db8::",
            "2001:db8:0:0:0:0:2:1",
            "2001:db8::2:1",
            "::ffff:192.0.2.128",
            "::",
        ],
        "MAC": ["00:1A:2B:3C:4D:5E", "00-1A-2B-3C-4D-5E", "aa:bb:cc:dd:ee:ff", "FF:FF:FF:FF:FF:FF"],
        "DOMAIN": ["example.com", "sub.example.com", "xn--d1acufc.xd", "test-domain.co.uk", "a.com"],
        "EMAIL": ["user@example.com", "user.name+tag@sub.domain.co.uk", "USER@EXAMPLE.COM", "test123@test-domain.com"],
        "PHONE": ["+1-800-555-1234", "+44 20 7946 0958", "(800) 555-1234", "800.555.1234", "+1 800 555 1234"],
        "URL": [
            "http://example.com",
            "https://example.com:8080/path",
            "ftp://ftp.example.com/resource",
            "https://sub.domain.com/path/to/resource?param=value",
        ],
        "URI": ["mailto:user@example.com", "urn:isbn:0451450523", "http://example.com", "custom-scheme:foo/bar"],
        "MD5": [
            "d41d8cd98f00b204e9800998ecf8427e",
            "D41D8CD98F00B204E9800998ECF8427E",
            "ffffffffffffffffffffffffffffffff",
        ],
        "SHA1": [
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
            "ffffffffffffffffffffffffffffffffffffffff",
        ],
        "SHA256": [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ],
        "CIDR": ["192.168.1.0/24", "10.0.0.0/8", "0.0.0.0/0", "255.255.255.255/32"],
        "PATH": [
            "/usr/bin/python",
            "C:\\Windows\\System32\\cmd.exe",
            "folder/file.txt",
            "\\\\server\\share\\file.txt",
            "/a",
            "C:\\a",
        ],
        "CVE": ["CVE-2021-1234", "CVE-1999-0001", "CVE-0000-0000"],
        "ASN": ["AS12345", "AS1", "AS999999"],
    }

    for value in valid_cases.get(short_name, []):
        assert pattern.match(value), f"{short_name} should match {value}"


@pytest.mark.parametrize("type_obj", get_regex_types())
def test_regex_invalid(type_obj):
    regex = type_obj["regex"]
    short_name = type_obj["short_name"]
    pattern = re.compile(regex, re.IGNORECASE)

    invalid_cases = {
        "IPV4": ["256.256.256.256", "192.168.1", "192.168.1.1.1", "192.168.1.01", "192.168.1.256"],
        "IPV6": [
            "2001:db8:::1",
            "2001:db8:85a3::8a2e:370:7334:1234b",
            "12345::1",
            "gggg:db8::1",
            "2001:db8:85a3::8a2e:370g:7334",
        ],
        "MAC": ["00:1A:2B:3C:4D", "00:1A:2B:3C:4D:5E:6F", "001A:2B:3C:4D:5E", "gg:1A:2B:3C:4D:5E"],
        "DOMAIN": ["-example.com", "example-.com", "example", "ex..com", "example.c", ".example.com", "example.com."],
        "EMAIL": ["userexample.com", "user@.com", "@example.com", "user@com", "user@", "user@example."],
        "PHONE": ["abc-def-ghij", "++1-800-555-1234", "+", "()"],
        "URL": ["htp://example.com", "http:/example.com", "http://", "://example.com"],
        "URI": ["1http://example.com", "://example.com", "http", ""],
        "MD5": [
            "d41d8cd98f00b204e9800998ecf8427",
            "g41d8cd98f00b204e9800998ecf8427e",
            "d41d8cd98f00b204e9800998ecf8427e1",
        ],
        "SHA1": [
            "da39a3ee5e6b4b0d3255bfef95601890afd8070",
            "ga39a3ee5e6b4b0d3255bfef95601890afd80709",
            "da39a3ee5e6b4b0d3255bfef95601890afd807091",
        ],
        "SHA256": [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
            "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8551",
        ],
        "CIDR": ["192.168.1.0/33", "192.168.1.0", "192.168.1.0/-1", "256.256.256.256/24"],
        "PATH": ["", "C:WindowsSystem32cmd.exe", "C:\\\\\\file.txt", "/", "C:\\"],
        "CVE": ["CVE-21-1234", "CVE-2021-123", "CVE-2021-", "CVE-abcd-1234"],
        "ASN": ["AS", "ASabc", "12345", "AS-123"],
    }

    for value in invalid_cases.get(short_name, []):
        assert not pattern.match(value), f"{short_name} should not match {value}"


@pytest.mark.parametrize("type_obj", get_regex_types())
def test_regex_edge_cases(type_obj):
    regex = type_obj["regex"]
    short_name = type_obj["short_name"]
    pattern = re.compile(regex, re.IGNORECASE)

    edge_cases = {
        "IPV4": ["0.0.0.0", "255.255.255.255", "1.2.3.4"],
        "IPV6": ["::", "fe80::"],
        "MAC": ["ff:ff:ff:ff:ff:ff", "FF:FF:FF:FF:FF:FF"],
        "DOMAIN": ["a.com", "abc-def.com"],
        "EMAIL": ["a@b.co", "a.b+c@d.com"],
        "PHONE": ["+123", "123"],
        "URL": ["https://sub.domain.com", "ftp://host"],
        "URI": ["custom-scheme:foo/bar"],
        "MD5": ["ffffffffffffffffffffffffffffffff"],
        "COMMUNITY_ID": ["a" * 20, "a" * 30],
        "SHA1": ["f" * 40],
        "SHA256": ["f" * 64],
        "PEHASH": ["a" * 16, "a" * 32],
        "IMPHASH": ["a" * 32],
        "DEXOFUZZY": ["a" * 20, "a" * 30],
        "CIDR": ["0.0.0.0/0", "255.255.255.255/32"],
        "PATH": ["/a", "C:\\a"],
        "CVE": ["CVE-0000-0000"],
        "ASN": ["AS999999"],
    }

    for value in edge_cases.get(short_name, []):
        assert pattern.match(value), f"{short_name} edge case failed for {value}"
