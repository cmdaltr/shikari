"""
Email sending functionality for password reset and notifications.

Supports both SMTP and development mode (console output).
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

logger = logging.getLogger(__name__)

# Email configuration (can be set via environment variables)
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "noreply@archer.local")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Archer Security Platform")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"

# Base URL for reset links
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")


def send_password_reset_email(email: str, token: str, full_name: Optional[str] = None) -> bool:
    """
    Send password reset email to user.

    Args:
        email: Recipient email address
        token: Password reset token
        full_name: User's full name (optional)

    Returns:
        True if email sent successfully, False otherwise
    """
    # Generate reset URL
    reset_url = f"{BASE_URL}/reset-password?token={token}"

    # Prepare email content
    subject = "Password Reset Request - Archer Security Platform"

    # Personalize greeting
    greeting = f"Hello {full_name}," if full_name else "Hello,"

    # HTML version
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                line-height: 1.6;
                color: #1a1a1a;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }}
            .container {{
                background: #ffffff;
                border-radius: 8px;
                padding: 30px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            }}
            .header {{
                text-align: center;
                padding-bottom: 20px;
                border-bottom: 2px solid #C53030;
            }}
            .header h1 {{
                color: #C53030;
                margin: 0;
                font-size: 24px;
            }}
            .content {{
                padding: 20px 0;
            }}
            .button {{
                display: inline-block;
                padding: 12px 24px;
                background: #C53030;
                color: #ffffff;
                text-decoration: none;
                border-radius: 6px;
                font-weight: 600;
                margin: 20px 0;
            }}
            .button:hover {{
                background: #9b2626;
            }}
            .footer {{
                padding-top: 20px;
                border-top: 1px solid #e2e8f0;
                font-size: 14px;
                color: #718096;
                text-align: center;
            }}
            .warning {{
                background: #fff5f5;
                border-left: 4px solid #feb2b2;
                padding: 12px;
                margin: 20px 0;
                border-radius: 4px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏹 Archer Security Platform</h1>
            </div>
            <div class="content">
                <p>{greeting}</p>
                <p>We received a request to reset your password for your Archer account.</p>
                <p>Click the button below to reset your password:</p>
                <p style="text-align: center;">
                    <a href="{reset_url}" class="button">Reset Password</a>
                </p>
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; background: #f7fafc; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px;">
                    {reset_url}
                </p>
                <div class="warning">
                    <strong>⚠️ Security Notice:</strong>
                    <ul style="margin: 8px 0 0 0; padding-left: 20px;">
                        <li>This link will expire in <strong>1 hour</strong></li>
                        <li>If you didn't request this reset, please ignore this email</li>
                        <li>Never share this link with anyone</li>
                    </ul>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated message from Archer Security Platform.</p>
                <p>If you have questions, please contact your system administrator.</p>
            </div>
        </div>
    </body>
    </html>
    """

    # Plain text version (fallback)
    text_body = f"""
{greeting}

We received a request to reset your password for your Archer account.

Click the link below to reset your password:
{reset_url}

SECURITY NOTICE:
- This link will expire in 1 hour
- If you didn't request this reset, please ignore this email
- Never share this link with anyone

This is an automated message from Archer Security Platform.
If you have questions, please contact your system administrator.
    """

    # Send email
    return send_email(
        to_email=email,
        subject=subject,
        html_body=html_body,
        text_body=text_body
    )


def send_email(to_email: str, subject: str, html_body: str, text_body: str) -> bool:
    """
    Send an email using configured SMTP server.

    Args:
        to_email: Recipient email address
        subject: Email subject
        html_body: HTML version of email body
        text_body: Plain text version of email body

    Returns:
        True if email sent successfully, False otherwise
    """
    # Development mode - just log the email
    if not EMAIL_ENABLED:
        logger.info("=" * 80)
        logger.info("EMAIL (Development Mode - Not Actually Sent)")
        logger.info("=" * 80)
        logger.info(f"To: {to_email}")
        logger.info(f"From: {SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>")
        logger.info(f"Subject: {subject}")
        logger.info("-" * 80)
        logger.info(text_body)
        logger.info("=" * 80)
        return True

    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg['To'] = to_email

        # Attach both plain text and HTML versions
        part1 = MIMEText(text_body, 'plain')
        part2 = MIMEText(html_body, 'html')
        msg.attach(part1)
        msg.attach(part2)

        # Send email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_USE_TLS:
                server.starttls()

            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)

            server.sendmail(SMTP_FROM_EMAIL, to_email, msg.as_string())

        logger.info(f"Password reset email sent successfully to {to_email}")
        return True

    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False


def get_email_configuration_status() -> dict:
    """
    Get current email configuration status for debugging.

    Returns:
        Dictionary with email configuration details
    """
    return {
        "enabled": EMAIL_ENABLED,
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "smtp_from": SMTP_FROM_EMAIL,
        "smtp_username_configured": bool(SMTP_USERNAME),
        "smtp_password_configured": bool(SMTP_PASSWORD),
        "base_url": BASE_URL
    }
