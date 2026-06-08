from __future__ import annotations

import os


CONFIG_PATH = os.getenv("PCTL_CONFIG", "/etc/pctl/config.yml")
API_TOKEN = os.getenv("PCTL_API_TOKEN")
SSH_CONFIG = os.getenv("PCTL_SSH_CONFIG", "/home/appuser/.ssh/config")
SSH_KNOWN_HOSTS = os.getenv("PCTL_SSH_KNOWN_HOSTS", "/home/appuser/.ssh/known_hosts")
AUDIT_LOG_PATH = os.getenv("PCTL_AUDIT_LOG", "/var/log/pctl/audit.jsonl")
AUTH_PASSWORD_PEPPER = os.getenv("PCTL_AUTH_PASSWORD_PEPPER", "")
SUPERADMIN_EMAIL = os.getenv("PCTL_SUPERADMIN_EMAIL", "superadmin@local")
SUPERADMIN_USERNAME = os.getenv("PCTL_SUPERADMIN_USERNAME", "superadmin")
SUPERADMIN_PASSWORD = os.getenv("PCTL_SUPERADMIN_PASSWORD", "superadmin-change-me")
AUTH_ACCESS_TTL_MINUTES = int(os.getenv("PCTL_AUTH_ACCESS_TTL_MINUTES", "480"))
AUTH_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("PCTL_AUTH_RATE_LIMIT_WINDOW_SECONDS", "300"))
AUTH_RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("PCTL_AUTH_RATE_LIMIT_MAX_ATTEMPTS", "10"))
AUTH_SUSPICIOUS_THRESHOLD = int(os.getenv("PCTL_AUTH_SUSPICIOUS_THRESHOLD", "5"))
AUTH_PASSWORD_ITERATIONS = int(os.getenv("PCTL_AUTH_PASSWORD_ITERATIONS", "600000"))
SSH_IMPORT_MODE = os.getenv("PCTL_IMPORT_SSH_CONFIG_MODE", "off")
SSH_IMPORT_MARKER = os.getenv("PCTL_IMPORT_SSH_CONFIG_MARKER", "### START FLINT ###")
