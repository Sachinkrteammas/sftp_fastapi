"""Send e-mail with attachments through the SMTP server in .env (SMTP_*, MAIL_*)."""
from __future__ import annotations

import smtplib
import socket
import ssl
from email.message import EmailMessage
from typing import List, Tuple

from .config import get_settings
from .logger import get_logger

log = get_logger("email")


class EmailNotConfiguredError(Exception):
    """SMTP_HOST / MAIL_TO / MAIL_FROM missing in .env."""


class EmailSendError(Exception):
    """SMTP connection, login or sending failed."""


def send_email(subject: str, body: str, attachments: List[Tuple[str, bytes, str]]) -> List[str]:
    """Send one mail to MAIL_TO (+ MAIL_CC). attachments: (file name, data, mime type 'text/csv').
    Returns the recipients."""
    s = get_settings()
    missing = [n for n, v in (("SMTP_HOST", s.smtp_host), ("MAIL_TO", s.mail_to),
                              ("MAIL_FROM", s.mail_from)) if not v]
    if missing:
        raise EmailNotConfiguredError(f"E-mail not configured, set in .env: {', '.join(missing)}")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = s.mail_from
    msg["To"] = ", ".join(s.mail_to)
    if s.mail_cc:
        msg["Cc"] = ", ".join(s.mail_cc)
    msg.set_content(body)
    for name, data, mime in attachments:
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    recipients = list(s.mail_to) + list(s.mail_cc)

    timeout = s.sftp_timeout_seconds
    try:
        if s.smtp_security == "ssl":
            server = smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=timeout,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=timeout)
        with server:
            if s.smtp_security == "starttls":
                server.starttls(context=ssl.create_default_context())
            if s.smtp_username:
                server.login(s.smtp_username, s.smtp_password)
            server.send_message(msg, to_addrs=recipients)
    except smtplib.SMTPAuthenticationError as exc:
        raise EmailSendError("SMTP login failed (check SMTP_USERNAME / SMTP_PASSWORD)") from exc
    except smtplib.SMTPRecipientsRefused as exc:
        raise EmailSendError(f"SMTP refused recipients: {', '.join(exc.recipients)}") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise EmailSendError(f"SMTP connection timed out ({s.smtp_host}:{s.smtp_port})") from exc
    except (smtplib.SMTPException, OSError) as exc:
        raise EmailSendError(f"Sending e-mail failed: {type(exc).__name__}: {exc}") from exc
    log.info("E-mail '%s' sent to %s (%s attachments)", subject, ", ".join(recipients), len(attachments))
    return recipients
