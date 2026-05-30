import os


CONFIG_PATH = os.getenv("PCTL_CONFIG", "/etc/pctl/config.yml")
API_TOKEN = os.getenv("PCTL_API_TOKEN")

SSH_CONFIG = os.getenv("PCTL_SSH_CONFIG", "/home/appuser/.ssh/config")
SSH_KNOWN_HOSTS = os.getenv("PCTL_SSH_KNOWN_HOSTS", "/home/appuser/.ssh/known_hosts")

AUDIT_LOG_PATH = os.getenv("PCTL_AUDIT_LOG", "/var/log/pctl/audit.jsonl")