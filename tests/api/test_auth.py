"""
Tests for authentication, registration, MFA, and admin endpoints.
"""
import re
import uuid

import pytest
import requests


def _csrf(session, base_url):
    """The login form's CSRF token; the GET also sets the CSRF session cookie it is bound to."""
    page = session.get(f"{base_url}/login", timeout=30)
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)


class TestLogin:
    """POST /login and POST /logout."""

    def test_login_page_loads(self, api, ensure_running):
        r = api.get("/login")
        assert r.status_code in [200, 302]

    def test_login_with_valid_credentials(self, api, ensure_running):
        # A fresh session: signing the shared one in again would replace its cookie mid-run
        fresh = requests.Session()
        r = fresh.post(f"{api.url}/login", data={
            "email": "admin@shikari.app",
            "password": "BigGameHunter",
            "csrf_token": _csrf(fresh, api.url),
        }, allow_redirects=False, timeout=30)
        assert r.status_code == 303
        assert "shikari_session" in fresh.cookies
        fresh.close()

    def test_login_with_invalid_credentials(self, api, ensure_running):
        # A new address each run: the rate limit is per address and account, so a fixed one
        # turns into a 429 after five runs in five minutes
        fresh = requests.Session()
        r = fresh.post(f"{api.url}/login", data={
            "email": f"wrong-{uuid.uuid4().hex[:8]}@wrong.com",
            "password": "wrongpassword",
            "csrf_token": _csrf(fresh, api.url),
        }, allow_redirects=False, timeout=30)
        assert r.status_code == 401
        assert "Invalid email or password" in r.text
        fresh.close()

    def test_login_without_csrf_token_refused(self, api, ensure_running):
        fresh = requests.Session()
        r = fresh.post(f"{api.url}/login", data={
            "email": "admin@shikari.app",
            "password": "BigGameHunter",
        }, allow_redirects=False, timeout=30)
        assert r.status_code == 422
        fresh.close()

    def test_login_with_forged_csrf_token_refused(self, api, ensure_running):
        fresh = requests.Session()
        _csrf(fresh, api.url)  # the CSRF session cookie, with a token that isn't its own
        r = fresh.post(f"{api.url}/login", data={
            "email": "admin@shikari.app",
            "password": "BigGameHunter",
            "csrf_token": "forged",
        }, allow_redirects=False, timeout=30)
        assert r.status_code == 403
        assert "shikari_session" not in fresh.cookies
        fresh.close()

    def test_login_empty_fields(self, api, ensure_running):
        fresh = requests.Session()
        r = fresh.post(f"{api.url}/login", data={
            "email": "",
            "password": "",
        }, allow_redirects=False, timeout=30)
        assert r.status_code in [200, 302, 400, 401, 422]
        fresh.close()

    def test_logout(self, api, ensure_running):
        # Its own session: logging out the shared one would sign every later test out
        from tests.live_auth import sign_in

        fresh = requests.Session()
        assert sign_in(fresh, api.url)
        assert fresh.get(f"{api.url}/logout", allow_redirects=False, timeout=30).status_code == 200
        assert fresh.get(f"{api.url}/library", allow_redirects=False, timeout=30).status_code == 200
        r = fresh.post(f"{api.url}/logout", allow_redirects=False, timeout=30)
        assert r.status_code == 303
        assert fresh.get(f"{api.url}/library", allow_redirects=False, timeout=30).status_code == 303
        fresh.close()


class TestRegistration:
    """/register: open only in the desktop app's local Shikari; a server sends it to /login (invitations)."""

    def test_register_page_loads(self, api, ensure_running):
        r = api.get("/register")
        assert r.status_code in [200, 302]

    def test_register_missing_fields(self, api, ensure_running):
        r = api.post("/register", data={
            "email": "",
            "password": "",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 400, 422]


class TestPasswordReset:
    """Password reset flow."""

    def test_forgot_password_page(self, api, ensure_running):
        r = api.get("/forgot-password")
        assert r.status_code in [200, 302]

    def test_request_reset(self, api, ensure_running):
        r = api.post("/api/auth/request-reset", json={
            "email": "test@test.com",
        })
        # Always returns 200 to prevent email enumeration
        assert r.status_code in [200, 401, 422]

    def test_reset_with_invalid_token(self, api, ensure_running):
        r = api.post("/api/auth/reset-password", json={
            "token": "invalid-token",
            "new_password": "NewPassword123!",
        })
        assert r.status_code in [200, 400, 401, 422]


class TestMFA:
    """MFA setup and verification."""

    def test_mfa_status(self, api, ensure_running):
        r = api.get("/api/mfa/status")
        assert r.status_code in [200, 401]

    def test_mfa_setup(self, api, ensure_running):
        r = api.post("/api/mfa/setup")
        assert r.status_code in [200, 401]

    def test_mfa_verify_invalid_code(self, api, ensure_running):
        r = api.post("/api/mfa/verify", json={"code": "000000"})
        assert r.status_code in [200, 400, 401, 422]

    def test_backup_codes_generate(self, api, ensure_running):
        r = api.post("/api/backup-codes/generate")
        assert r.status_code in [200, 401]


class TestChangePassword:
    """POST /api/change-password."""

    def test_change_password_wrong_current(self, api, ensure_running):
        r = api.post("/api/change-password", json={
            "current_password": "wrong",
            "new_password": "NewPass123!",
        })
        assert r.status_code in [200, 400, 401, 422]


class TestProfileAPI:
    """User profile management."""

    def test_get_profile(self, api, ensure_running):
        r = api.get("/profile", allow_redirects=False)
        assert r.status_code in [200, 302]

    def test_update_profile(self, api, ensure_running):
        r = api.post("/api/profile", json={
            "display_name": "Test User",
        })
        assert r.status_code in [200, 401, 422]

    def test_profile_timeline(self, api, ensure_running):
        r = api.get("/api/profile/timeline")
        assert r.status_code in [200, 401]

    def test_api_keys_list(self, api, ensure_running):
        r = api.get("/api/profile/apikeys")
        assert r.status_code in [200, 401]

    def test_create_api_key(self, api, ensure_running):
        r = api.post("/api/profile/apikeys", json={
            "name": "test-key",
        })
        assert r.status_code in [200, 401, 422]


class TestAdminEndpoints:
    """Admin user management (requires admin role)."""

    def test_admin_users_list(self, api, ensure_running):
        r = api.get("/api/admin/users")
        assert r.status_code in [200, 401, 403]

    def test_admin_invite(self, api, ensure_running):
        # An address that fails validation: a real one would leave a live invitation behind
        r = api.post("/api/admin/invitations", json={"email": "not-an-email", "role": "standard"})
        assert r.status_code in [401, 403, 422]

    def test_admin_invitations_list(self, api, ensure_running):
        r = api.get("/api/admin/invitations")
        assert r.status_code in [200, 401, 403]

    def test_admin_reset_access(self, api, ensure_running):
        # An id nobody has: a real one would sign that account out
        r = api.post("/api/admin/users/999999999/reset-access")
        assert r.status_code in [401, 403, 404]

    def test_users_list(self, api, ensure_running):
        r = api.get("/api/users")
        assert r.status_code in [200, 401, 403]

    def test_activities_list(self, api, ensure_running):
        r = api.get("/api/activities")
        assert r.status_code in [200, 401]
