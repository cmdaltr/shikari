# Admin Scripts

User administration and management utilities.

## Scripts

### create_admin.py
Create a new administrator user for Archer.

**Usage**:
```bash
python scripts/admin/create_admin.py
```

**Interactive Prompts**:
- Email address
- Password
- Confirm password

**Example**:
```bash
$ python scripts/admin/create_admin.py
Enter email: security-admin@company.com
Enter password: ••••••••••••
Confirm password: ••••••••••••
✓ Admin user created successfully
```

---

### reset_password.py
Reset a user's password.

**Usage**:
```bash
python scripts/admin/reset_password.py <email>
```

**Arguments**:
- `<email>` - User's email address

**Example**:
```bash
$ python scripts/admin/reset_password.py user@company.com
Enter new password: ••••••••••••
Confirm password: ••••••••••••
✓ Password reset successfully
```

**Alternative**: Use the web interface at Settings → Users → Reset Password

---

## Security Notes

- Passwords must meet minimum complexity requirements
- Admin users have full access to all Archer features
- Use strong, unique passwords for all admin accounts
- Consider using API keys for programmatic access instead of shared admin accounts

## Related Documentation

- [Security Features](../../docs/features/SECURITY_FEATURES.md)
- [Getting Started](../../GETTING_STARTED.md)
