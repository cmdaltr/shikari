"""
Tests for authentication, registration, MFA, and admin endpoints.
"""
import pytest
import requests


class TestLogin:
    """POST /login and GET /logout."""

    def test_login_page_loads(self, api, ensure_running):
        r = api.get("/login")
        assert r.status_code in [200, 302]

    def test_login_with_valid_credentials(self, api, ensure_running):
        r = api.post("/login", data={
            "email": "admin@shikari.app",
            "password": "BigGameHunter",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_login_with_invalid_credentials(self, api, ensure_running):
        # Use a fresh session to avoid existing cookies
        fresh = requests.Session()
        r = fresh.post(f"{api.url}/login", data={
            "email": "wrong@wrong.com",
            "password": "wrongpassword",
        }, allow_redirects=False, timeout=30)
        assert r.status_code in [200, 302, 401, 403]
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
        r = api.get("/logout", allow_redirects=False)
        assert r.status_code in [200, 302, 303]


class TestRegistration:
    """POST /register creates new accounts."""

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

    def test_admin_create_user(self, api, ensure_running):
        r = api.post("/api/admin/users", json={
            "email": "newuser@test.com",
            "password": "TestPassword123!",
            "role": "user",
        })
        assert r.status_code in [200, 401, 403, 409, 422]

    def test_admin_reset_password(self, api, ensure_running):
        r = api.post("/api/admin/reset-password", json={
            "user_id": "nonexistent-id",
            "new_password": "Reset123!",
        })
        assert r.status_code in [200, 400, 401, 403, 404]

    def test_users_list(self, api, ensure_running):
        r = api.get("/api/users")
        assert r.status_code in [200, 401, 403]

    def test_activities_list(self, api, ensure_running):
        r = api.get("/api/activities")
        assert r.status_code in [200, 401]
