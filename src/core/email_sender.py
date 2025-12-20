"""Async email sending service using aiosmtplib."""

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from src.core.settings import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


class EmailSender:
    """Async email sender using SMTP."""

    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str | None = None,
    ) -> bool:
        """Send an email asynchronously."""
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{settings.smtp_from_name} <{settings.smtp_from_email}>"
        message["To"] = to_email

        # Add text part (fallback)
        if text_body:
            message.attach(MIMEText(text_body, "plain"))

        # Add HTML part
        message.attach(MIMEText(html_body, "html"))

        try:
            await aiosmtplib.send(
                message,
                hostname=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_username,
                password=settings.smtp_password,
                use_tls=settings.smtp_use_tls,
            )
            logger.info(f"Email sent successfully to {to_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False

    async def send_verification_email(self, to_email: str, token: str) -> bool:
        """Send email verification link."""
        verification_url = f"{settings.frontend_url}/verify-email?token={token}"
        subject = "Verify your email address"
        html_body = f"""
        <html>
        <body>
            <h2>Email Verification</h2>
            <p>Please click the link below to verify your email address:</p>
            <p><a href="{verification_url}">Verify Email</a></p>
            <p>This link will expire in {settings.email_verification_expire_hours} hours.</p>
            <p>If you didn't request this, please ignore this email.</p>
        </body>
        </html>
        """
        text_body = f"Verify your email: {verification_url}"
        return await self.send_email(to_email, subject, html_body, text_body)

    async def send_password_reset_email(self, to_email: str, token: str) -> bool:
        """Send password reset link."""
        reset_url = f"{settings.frontend_url}/reset-password?token={token}"
        subject = "Reset your password"
        html_body = f"""
        <html>
        <body>
            <h2>Password Reset</h2>
            <p>Please click the link below to reset your password:</p>
            <p><a href="{reset_url}">Reset Password</a></p>
            <p>This link will expire in {settings.password_reset_expire_minutes} minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
        </body>
        </html>
        """
        text_body = f"Reset your password: {reset_url}"
        return await self.send_email(to_email, subject, html_body, text_body)

    async def send_magic_link_email(self, to_email: str, token: str) -> bool:
        """Send magic link for passwordless login."""
        magic_url = f"{settings.frontend_url}/auth/magic-link?token={token}"
        subject = "Your login link"
        html_body = f"""
        <html>
        <body>
            <h2>Magic Login Link</h2>
            <p>Click the link below to log in:</p>
            <p><a href="{magic_url}">Log In</a></p>
            <p>This link will expire in {settings.magic_link_expire_minutes} minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
        </body>
        </html>
        """
        text_body = f"Log in with this link: {magic_url}"
        return await self.send_email(to_email, subject, html_body, text_body)

    async def send_new_device_alert(
        self,
        to_email: str,
        device_name: str,
        ip_address: str,
        timestamp: str,
    ) -> bool:
        """Send alert for login from new device."""
        subject = "New Device Login Alert"
        html_body = f"""
        <html>
        <body>
            <h2>New Device Detected</h2>
            <p>A new device has been used to log into your account:</p>
            <ul>
                <li><strong>Device:</strong> {device_name}</li>
                <li><strong>IP Address:</strong> {ip_address}</li>
                <li><strong>Time:</strong> {timestamp} UTC</li>
            </ul>
            <p>If this was you, you can safely ignore this email.</p>
            <p>If you did not log in from this device, please secure your account immediately by:</p>
            <ol>
                <li>Changing your password</li>
                <li>Reviewing your active sessions</li>
                <li>Enabling two-factor authentication if not already enabled</li>
            </ol>
            <p><a href="{settings.frontend_url}/settings/security">Review Security Settings</a></p>
        </body>
        </html>
        """
        text_body = f"New device login detected. Device: {device_name}, IP: {ip_address}"
        return await self.send_email(to_email, subject, html_body, text_body)

    async def send_new_location_alert(
        self,
        to_email: str,
        location: str,
        ip_address: str,
        isp: str | None,
        timestamp: str,
    ) -> bool:
        """Send alert for login from new location."""
        subject = "New Location Login Alert"
        isp_info = f"<li><strong>ISP:</strong> {isp}</li>" if isp else ""
        html_body = f"""
        <html>
        <body>
            <h2>Login from New Location</h2>
            <p>Your account was accessed from a new location:</p>
            <ul>
                <li><strong>Location:</strong> {location}</li>
                <li><strong>IP Address:</strong> {ip_address}</li>
                {isp_info}
                <li><strong>Time:</strong> {timestamp} UTC</li>
            </ul>
            <p>If this was you, you can safely ignore this email.</p>
            <p>If you did not log in from this location, please secure your account immediately.</p>
            <p><a href="{settings.frontend_url}/settings/security">Review Security Settings</a></p>
        </body>
        </html>
        """
        text_body = f"New location login detected. Location: {location}, IP: {ip_address}"
        return await self.send_email(to_email, subject, html_body, text_body)


# Singleton instance
email_sender = EmailSender()
