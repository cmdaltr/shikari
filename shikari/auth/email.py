"""
Email sending: self-service reset-access links (Forgot password) and notifications.

Supports both SMTP and development mode (console output).
"""

import html
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
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "noreply@shikari.local")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Shikari Security Platform")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
SMTP_TIMEOUT = float(os.getenv("SMTP_TIMEOUT", "10"))

# The address links name (shikari/auth/links.py); self-service links are emailed only when it's set
BASE_URL = os.getenv("BASE_URL") or "http://localhost:32453"  # empty, as compose passes it unset: the default


def send_reset_access_email(email: str, link: str, full_name: Optional[str] = None,
                            hours: int = 24) -> bool:
    """Email a self-service reset-access link (shikari/auth/reset_access.py): a new password and a new
    authenticator. The link carries its token after #, so it never reaches a server's logs."""
    subject = "Reset your access - Shikari Security Platform"
    greeting = f"Hello {full_name}," if full_name else "Hello,"

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
                <h1>Shikari Security Platform</h1>
            </div>
            <div class="content">
                <p>{html.escape(greeting)}</p>
                <p>Someone asked to reset access to your Shikari account. The link lets you choose a new
                password and set up a new authenticator app; your old ones keep working until you finish.</p>
                <p style="text-align: center;">
                    <a href="{html.escape(link)}" class="button">Reset access</a>
                </p>
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; background: #f7fafc; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px;">
                    {html.escape(link)}
                </p>
                <div class="warning">
                    <strong>Security notice:</strong>
                    <ul style="margin: 8px 0 0 0; padding-left: 20px;">
                        <li>The link works once, within <strong>{hours} hours</strong></li>
                        <li>If you didn't ask for this, ignore this email: nothing changes unless the link is used</li>
                        <li>Never share this link with anyone</li>
                    </ul>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated message from Shikari Security Platform.</p>
                <p>If you have questions, please contact your system administrator.</p>
            </div>
        </div>
    </body>
    </html>
    """

    text_body = f"""
{greeting}

Someone asked to reset access to your Shikari account. This link lets you choose a new password and
set up a new authenticator app; your old ones keep working until you finish:

{link}

SECURITY NOTICE:
- The link works once, within {hours} hours
- If you didn't ask for this, ignore this email: nothing changes unless the link is used
- Never share this link with anyone

This is an automated message from Shikari Security Platform.
If you have questions, please contact your system administrator.
    """

    return send_email(to_email=email, subject=subject, html_body=html_body, text_body=text_body)


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
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
            if SMTP_USE_TLS:
                server.starttls()

            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)

            server.sendmail(SMTP_FROM_EMAIL, to_email, msg.as_string())

        logger.info(f"Email sent to {to_email}: {subject}")
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
