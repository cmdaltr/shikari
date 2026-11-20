# Admin Scripts

User administration and management utilities.

## Scripts

### create_admin.py
A first admin's invitation, for a fresh team server or for getting back in when no admin is left. The same as `shikari first-admin <email>`; everyone else is invited from Settings → Users → Invite, or with `shikari invite <email> --role standard|operator|admin`.

**Usage**:
```bash
python scripts/admin/create_admin.py <email> [--force] [--link-only]
docker compose exec shikari python scripts/admin/create_admin.py <email>   # Docker
```

It's refused, with exit status 5, while an active admin exists (a local Shikari's default `admin` counts), unless `--force`, which then needs a free licence seat. Each run revokes the previous first-admin link, so only the newest works.

**Example**:
```bash
$ python scripts/admin/create_admin.py security-admin@company.com
Invitation for security-admin@company.com (admin). Give them this link, which works once within 24 hours:

  http://localhost:32453/accept-invite#...
```

The link opens a page where they give their name, choose a password and set up an authenticator app (always required); the account is made when a code from it checks out, and they see their backup codes once. Issuing and accepting are recorded in the audit log (`invitation_created`, `account_created`).

---

### reset_password.py
Reset access for an account that can't sign in: a lost password, authenticator or backup codes. The same as `shikari reset-access <email>`.

**Usage**:
```bash
python scripts/admin/reset_password.py <email>
docker compose exec shikari python scripts/admin/reset_password.py <email>   # Docker
```

**Arguments**:
- `<email>` - User's email address

**Example**:
```bash
$ python scripts/admin/reset_password.py user@company.com
Access reset for user@company.com; their sessions have ended. Give them this link, which works once within 24 hours:

  http://localhost:32453/reset-access#...
```

The link opens a page where they choose a new password and set up a new authenticator app (required, even if they never used MFA), then see fresh backup codes once and are signed in. Their sessions end and their API tokens are revoked when the link is made; the old password, authenticator and backup codes keep working until it's used (nothing refuses sign-in while a reset is open), and any API token or session made in between is ended then. Wrong codes on the page count towards the sign-in lockout (5, then 15 minutes). The token is in the link's fragment (after `#`), so it never reaches server or proxy logs; the link's host is `BASE_URL` (as in the Forgot password email), and the command warns on stderr when it isn't set. Issuing and using it are recorded in the audit log (`access_reset_issued`, `access_reset_completed`).

**Alternative**: an admin can do the same from Settings → Users → Reset access

---

## Security Notes

- Passwords must meet minimum complexity requirements
- Admin users have full access to all Shikari features
- Use strong, unique passwords for all admin accounts
- Consider using API keys for programmatic access instead of shared admin accounts

## Related Documentation

- [Security Features](../../docs/features/SECURITY_FEATURES.md)
- [Getting Started](../../GETTING_STARTED.md)
