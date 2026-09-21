import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from port_scanner import ScanResult, is_authorized_target  # noqa: E402


def test_localhost_is_authorized_without_flag():
    assert is_authorized_target("127.0.0.1", allow_flag=False) is True


def test_private_ip_is_authorized_without_flag():
    assert is_authorized_target("192.168.1.1", allow_flag=False) is True


def test_public_ip_requires_explicit_permission():
    # 8.8.8.8 -> δημόσια IP (Google Public DNS), σκόπιμα εκτός RFC1918/reserved
    assert is_authorized_target("8.8.8.8", allow_flag=False) is False


def test_permission_flag_overrides_check():
    assert is_authorized_target("8.8.8.8", allow_flag=True) is True


def test_scan_result_dataclass_defaults():
    result = ScanResult(port=22, is_open=True)
    assert result.port == 22
    assert result.is_open is True
    assert result.banner is None
