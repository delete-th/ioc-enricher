# detects the type of an ioc string using regex patterns

import re

# standard ipv4 address pattern
IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# basic domain pattern — covers most tlds including multi-part ones
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

# file hash patterns by length
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def detect(ioc: str) -> str:
    # strip whitespace before checking
    ioc = ioc.strip()

    if IPV4_PATTERN.match(ioc):
        return "ip"

    # check sha256 before md5/sha1 — longer match is more specific
    if SHA256_PATTERN.match(ioc):
        return "sha256"

    if SHA1_PATTERN.match(ioc):
        return "sha1"

    if MD5_PATTERN.match(ioc):
        return "md5"

    # domain check last — it's the most permissive pattern
    if DOMAIN_PATTERN.match(ioc):
        return "domain"

    return "unknown"
