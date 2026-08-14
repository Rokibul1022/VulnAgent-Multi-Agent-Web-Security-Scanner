"""Shared helpers for subprocess-based agents."""

import asyncio
import os
import re
import signal

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


async def run_capture(cmd: list[str], timeout: int = 60, input_data: bytes | None = None):
    """Run a command, capture stdout/stderr. Returns (found, out_bytes, err_bytes, rc).
    found=False if the binary is missing; out/err None on timeout.
    input_data is written to stdin (some tools read hosts there instead of args)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except FileNotFoundError:
        return False, None, None, None
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(input=input_data), timeout=timeout
        )
        return True, out, err, proc.returncode
    except asyncio.TimeoutError:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        return True, None, None, None


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def missing_tool_line(name: str, install_hint: str) -> str:
    return f"{name} not found — install with `{install_hint}`"