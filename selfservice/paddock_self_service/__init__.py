"""Paddock Self-Service: the desktop app that lists what the organization offers and asks paddockd to install,
update or remove it over the local self-service socket (ADR 0049, plan M13b §3.5).

The app holds no credential and never runs as root; everything it shows comes from the socket and is treated as
untrusted plain text.
"""

APP_ID = "com.paddock.SelfService"
