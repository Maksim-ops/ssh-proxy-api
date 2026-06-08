from app.api.rate_limit import clear_auth_failures, consume_auth_attempt, is_suspicious_auth_attempt, record_auth_failure
from app.auth.permissions import permissions_for_role
from app.auth.security import build_password_hash, verify_password
from app.config import SETTINGS


def test_password_hash_verification_roundtrip():
    password_hash = build_password_hash('correct horse battery staple')
    assert verify_password('correct horse battery staple', password_hash) is True
    assert verify_password('wrong password', password_hash) is False


def test_auth_rate_limit_and_suspicious_tracking():
    email = 'test@example.com'
    ip_address = '127.0.0.10'

    clear_auth_failures(ip_address=ip_address, email=email)

    limit = SETTINGS.auth_rate_limit_max_attempts
    for _ in range(limit):
        allowed, retry_after = consume_auth_attempt(ip_address=ip_address, email=email)
        assert allowed is True
        assert retry_after == 0

    allowed, retry_after = consume_auth_attempt(ip_address=ip_address, email=email)
    assert allowed is False
    assert retry_after > 0

    for _ in range(SETTINGS.auth_suspicious_threshold):
        record_auth_failure(ip_address=ip_address, email=email)

    assert is_suspicious_auth_attempt(ip_address=ip_address, email=email) is True


def test_superadmin_permissions_include_global_access():
    permissions = permissions_for_role('superadmin')
    assert 'servers:read_all' in permissions
    assert 'auth:revoke_any_session' in permissions
