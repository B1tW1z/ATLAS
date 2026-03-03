"""
ATLAS Terminal WebSocket Route

Provides a real shell terminal over WebSocket using PTY.
Every blocking OS call (read/write/wait) runs in a thread executor
so the asyncio event loop is NEVER blocked.
"""

import os
import pty
import select
import signal
import struct
import fcntl
import termios
import subprocess
import asyncio
import logging
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from api.routes.auth import get_session, get_db

logger = logging.getLogger("atlas.terminal")

router = APIRouter(prefix="/terminal", tags=["Terminal"])


async def authenticate_ws(token: str) -> dict | None:
    """Validate WebSocket token and return user info if authorized."""
    session = get_session(token)
    if not session:
        return None

    db = get_db()
    user = db.get_user_by_username(session["username"])
    if not user:
        return None

    # Only pentester and admin can use terminal
    if user.role not in ("pentester", "admin"):
        return None

    return {
        "username": user.username,
        "name": user.name,
        "role": user.role,
    }


def _set_winsize(fd: int, rows: int, cols: int):
    """Set the terminal window size on the PTY."""
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


# ---------------------------------------------------------------------------
# Blocking helpers — these run ONLY inside run_in_executor
# ---------------------------------------------------------------------------

def _pty_read_blocking(fd: int) -> bytes | None:
    """
    Wait up to 0.5s for data on the PTY master fd, then read it.
    Returns:
        bytes  – data read from PTY
        b""    – EOF / OSError (PTY closed)
        None   – select timeout, no data yet
    Runs inside a thread-pool executor; never on the event loop.
    """
    try:
        ready, _, _ = select.select([fd], [], [], 0.5)
    except (OSError, ValueError):
        return b""  # fd closed

    if not ready:
        return None  # timeout

    try:
        data = os.read(fd, 4096)
        return data if data else b""  # empty read = EOF
    except OSError:
        return b""


def _pty_write_blocking(fd: int, data: bytes):
    """Write data to the PTY master fd.  Runs in executor."""
    try:
        os.write(fd, data)
    except OSError:
        pass


def _wait_process(process, timeout=2):
    """Wait for process to exit. Runs in executor."""
    try:
        process.wait(timeout=timeout)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@router.websocket("/ws")
async def terminal_ws(websocket: WebSocket, token: str = Query(...)):
    """
    WebSocket endpoint that spawns a real bash shell via PTY.

    Query params:
        token: Session auth token

    Messages FROM client:
        - Plain text: stdin data (keystrokes)
        - JSON {"type": "resize", "cols": N, "rows": N}: resize terminal

    Messages TO client:
        - Plain text: stdout/stderr data from the shell
    """
    await websocket.accept()

    # -- Authenticate --
    user = await authenticate_ws(token)
    if not user:
        await websocket.send_text(
            "\r\n\x1b[31m[ACCESS DENIED] Terminal requires a valid "
            "session with pentester or admin role.\x1b[0m\r\n"
        )
        await websocket.close(code=4003, reason="Unauthorized")
        return

    logger.info(f"Terminal session opened for {user['username']} ({user['role']})")

    # -- Create PTY pair --
    master_fd, slave_fd = pty.openpty()

    # -- Spawn bash --
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["SHELL"] = "/bin/bash"
    env["USER"] = user["username"]
    env["HOME"] = os.path.expanduser("~")

    process = subprocess.Popen(
        ["/bin/bash", "--login"],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        preexec_fn=os.setsid,
        env=env,
        cwd=os.path.expanduser("~"),
    )

    # Close slave in parent — child owns it
    os.close(slave_fd)

    # Set default terminal size
    _set_winsize(master_fd, 24, 80)

    loop = asyncio.get_event_loop()
    closed = asyncio.Event()  # signals both tasks to stop

    # ------------------------------------------------------------------
    async def read_pty():
        """Continuously read PTY output → send to WebSocket."""
        try:
            while not closed.is_set():
                data = await loop.run_in_executor(
                    None, _pty_read_blocking, master_fd
                )
                if data is None:
                    # select timeout — just loop again
                    continue
                if not data:
                    # EOF or error — shell exited
                    break
                try:
                    await websocket.send_text(
                        data.decode("utf-8", errors="replace")
                    )
                except Exception:
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"PTY read ended: {e}")
        finally:
            closed.set()

    # ------------------------------------------------------------------
    async def write_pty():
        """Receive WebSocket messages → write to PTY stdin."""
        try:
            while not closed.is_set():
                message = await websocket.receive_text()

                # JSON control messages (resize)
                if message.startswith("{"):
                    try:
                        msg = json.loads(message)
                        if msg.get("type") == "resize":
                            cols = msg.get("cols", 80)
                            rows = msg.get("rows", 24)
                            _set_winsize(master_fd, rows, cols)
                            continue
                    except json.JSONDecodeError:
                        pass

                # Regular stdin — write in executor to avoid blocking
                await loop.run_in_executor(
                    None, _pty_write_blocking, master_fd,
                    message.encode("utf-8")
                )
        except WebSocketDisconnect:
            logger.info(f"Terminal WS disconnected for {user['username']}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"PTY write ended: {e}")
        finally:
            closed.set()

    # ------------------------------------------------------------------
    # Run both tasks; clean up when either finishes
    # ------------------------------------------------------------------
    read_task = asyncio.create_task(read_pty())
    write_task = asyncio.create_task(write_pty())

    try:
        done, pending = await asyncio.wait(
            [read_task, write_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
    finally:
        # -- Kill the shell process (non-blocking) --
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass

        await loop.run_in_executor(None, _wait_process, process, 2)

        if process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            await loop.run_in_executor(None, _wait_process, process, 1)

        # -- Close master fd --
        try:
            os.close(master_fd)
        except OSError:
            pass

        logger.info(f"Terminal session closed for {user['username']}")
