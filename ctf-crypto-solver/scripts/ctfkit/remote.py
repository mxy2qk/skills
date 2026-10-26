"""Network and subprocess tubes for remote/oracle challenges.

Re-exports the socket helpers from util and adds a subprocess-backed tube for
challenges that ship a server script instead of a host:port.
"""

from __future__ import annotations

import subprocess
import time

from .util import Tube, connect

__all__ = [
    "Tube",
    "connect",
    "ProcessTube",
    "connect_process",
    "oracle",
    "solve_pow_for_tube",
    "read_menu",
    "choose",
    "retry",
]


class ProcessTube(Tube):
    """A Tube over a subprocess's stdin/stdout.

    Useful for local challenge servers (`python server.py`, socat wrappers)
    and for binary oracles. Reads are blocking with an optional timeout
    implemented by polling the pipe.
    """

    def __init__(self, argv, cwd: str | None = None, timeout: float = 10.0):
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
        )
        self.buf = b""
        self.timeout = timeout
        # Deliberately not calling Tube.__init__: there is no socket.

    def recv(self, n: int = 4096) -> bytes:
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            chunk = self.proc.stdout.read(1) if n == 1 else self.proc.stdout.read(n)
            if chunk:
                return chunk
            if self.proc.poll() is not None:
                return b""
            time.sleep(0.005)
        return b""

    def recvuntil(self, delim: bytes, drop: bool = True) -> bytes:
        deadline = time.time() + self.timeout
        while delim not in self.buf:
            if self.proc.poll() is not None and not self.buf:
                break
            chunk = self.proc.stdout.read(4096)
            if chunk:
                self.buf += chunk
            elif time.time() > deadline:
                break
            else:
                time.sleep(0.005)
        if delim not in self.buf:
            data, self.buf = self.buf, b""
            return data
        idx = self.buf.index(delim)
        end = idx + len(delim)
        data, self.buf = self.buf[:end], self.buf[end:]
        return data[:-len(delim)] if drop else data

    def recvall(self) -> bytes:
        chunks = [self.buf]
        self.buf = b""
        while True:
            chunk = self.proc.stdout.read(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def send(self, data: bytes | str):
        if isinstance(data, str):
            data = data.encode()
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
        except Exception:
            pass


def connect_process(argv, cwd: str | None = None, timeout: float = 10.0) -> ProcessTube:
    return ProcessTube(argv, cwd=cwd, timeout=timeout)


def oracle(tube, payload: bytes, until: bytes = b"\n", settle: float = 0.0) -> bytes:
    """Send one payload and read one response. Convenience for oracle loops."""
    tube.sendline(payload)
    if settle:
        time.sleep(settle)
    return tube.recvuntil(until)


def solve_pow_for_tube(tube: Tube, banner: bytes | str, **overrides):
    """Parse the PoW in `banner`, solve it, send the answer.

    Returns (answer, digest) or None. Overrides are passed to solve_pow.
    """
    from .pow import parse_and_solve

    if isinstance(banner, bytes):
        banner = banner.decode("latin-1", errors="replace")
    result = parse_and_solve(banner, **overrides)
    if result is None:
        return None
    tube.sendline(result[0])
    return result


def read_menu(tube: Tube, prompt: bytes = b"> ", timeout: float | None = None) -> str:
    """Read a menu/banner through `prompt` and return it as text."""
    if timeout is not None:
        tube.sock.settimeout(timeout)
    return tube.recvuntil(prompt, drop=True).decode("latin-1", errors="replace")


def choose(tube: Tube, option, prompt: bytes = b"> ") -> str:
    """Send a menu choice and return the next menu text."""
    tube.sendline(str(option))
    return tube.recvuntil(prompt, drop=True).decode("latin-1", errors="replace")


def retry(fn, attempts: int = 3, delay: float = 0.5, exceptions=(OSError, TimeoutError)):
    """Retry a connection/oracle call; useful for flaky CTF infrastructure."""
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except exceptions as exc:  # type: ignore[misc]
            last = exc
            time.sleep(delay)
    if last is not None:
        raise last
    return None
