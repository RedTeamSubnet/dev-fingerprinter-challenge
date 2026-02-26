# -*- coding: utf-8 -*-

import smtplib
import time
from email.message import EmailMessage

from pydantic import validate_call, SecretStr, EmailStr, constr, conint

from api.logger import logger


class EmailHelper:

    @validate_call
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: SecretStr,
        email_sender: EmailStr,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.email_sender = email_sender

    @validate_call
    def send(
        self,
        to: EmailStr,
        subject: constr(strip_whitespace=True, min_length=1),  # type: ignore
        body: str,
        retries: int = 3,
        delay: int = 2,
    ) -> bool:
        """Send an email with retry logic.

        Args:
            to (EmailStr): Recipient email address.
            subject (str): Email subject.
            body (str): Email body.
            retries (int): Number of retries on failure. Defaults to 3.
            delay (int): Delay in seconds between retries. Defaults to 2.

        Returns:
            bool: True if sent successfully, False otherwise.
        """
        logger.info(f"Sending email with subject '{subject}'...")

        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = f"DFP Challenger System <{self.email_sender}>"
        msg["To"] = to

        for attempt in range(1, retries + 1):
            try:
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password.get_secret_value())
                    server.send_message(msg)

                logger.info(f"Successfully sent email.")
                return True

            except Exception as e:
                logger.warning(f"Attempt {attempt}/{retries} failed to send email: {e}")
                if attempt < retries:
                    time.sleep(delay)
                else:
                    logger.error(f"Failed to send email after {retries} attempts.")
                    return False
        return False
