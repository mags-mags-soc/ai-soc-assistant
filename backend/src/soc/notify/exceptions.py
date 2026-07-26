"""Exception hierarchy for the notification layer (Telegram, Email, etc.).

A single base class (`NotificationError`) lets the pipeline catch any delivery
failure uniformly, while subclasses allow channel-specific handling.
"""

from __future__ import annotations


class NotificationError(Exception):
    """Base class for all notification-related errors."""


class NotificationConfigError(NotificationError):
    """Raised when required configuration (token, chat id, SMTP creds) is missing."""


class NotificationDeliveryError(NotificationError):
    """Raised when the message could not be delivered to the remote service."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
