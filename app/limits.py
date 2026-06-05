from typing import Dict, Any, Tuple

from .config import get_global_limits


DEFAULT_MAX_STDOUT_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_STDERR_BYTES = 1 * 1024 * 1024


def get_effective_limits(server_cfg: Dict[str, Any]) -> Dict[str, int]:
    global_limits = get_global_limits()
    server_limits = server_cfg.get("limits", {}) or {}

    max_stdout = int(
        server_limits.get(
            "maxStdoutBytes",
            global_limits.get("maxStdoutBytes", DEFAULT_MAX_STDOUT_BYTES),
        )
    )

    max_stderr = int(
        server_limits.get(
            "maxStderrBytes",
            global_limits.get("maxStderrBytes", DEFAULT_MAX_STDERR_BYTES),
        )
    )

    return {
        "maxStdoutBytes": max_stdout,
        "maxStderrBytes": max_stderr,
    }


def truncate_text_by_bytes(text: str, max_bytes: int) -> Tuple[str, bool]:
    raw = text.encode("utf-8")

    if len(raw) <= max_bytes:
        return text, False

    truncated_raw = raw[:max_bytes]

    truncated_text = truncated_raw.decode("utf-8", errors="ignore")
    truncated_text += (
        f"\n\n[pctl] output truncated: exceeded {max_bytes} bytes\n"
    )

    return truncated_text, True


def apply_output_limits(
    *,
    stdout: str,
    stderr: str,
    server_cfg: Dict[str, Any],
) -> tuple[str, str, bool, bool]:
    limits = get_effective_limits(server_cfg)

    stdout_limited, stdout_truncated = truncate_text_by_bytes(
        stdout,
        limits["maxStdoutBytes"],
    )

    stderr_limited, stderr_truncated = truncate_text_by_bytes(
        stderr,
        limits["maxStderrBytes"],
    )

    return stdout_limited, stderr_limited, stdout_truncated, stderr_truncated