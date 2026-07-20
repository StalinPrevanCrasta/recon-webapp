import os
import signal
import subprocess
from pathlib import Path

# Track active subprocesses per scan_id for cancellation
ACTIVE_PROCS: dict[int, list[subprocess.Popen]] = {}

def register_proc(scan_id: int, proc: subprocess.Popen) -> None:
    ACTIVE_PROCS.setdefault(scan_id, []).append(proc)

def unregister_proc(scan_id: int, proc: subprocess.Popen) -> None:
    procs = ACTIVE_PROCS.get(scan_id)
    if procs and proc in procs:
        procs.remove(proc)
    if procs and not procs:
        del ACTIVE_PROCS[scan_id]

def cancel_scan(scan_id: int) -> int:
    """Kill all subprocesses for a scan. Returns count of processes killed."""
    procs = ACTIVE_PROCS.pop(scan_id, [])
    killed = 0
    for proc in procs:
        if proc.poll() is None:
            try:
                if os.name == "nt":
                    proc.terminate()
                else:
                    proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                killed += 1
            except Exception:
                pass
    return killed


class CommandError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stdout: str, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"Command failed ({returncode}): {' '.join(cmd)}\n{stderr}")


def run_command(cmd: list[str], cwd: Path | None = None, timeout: int | None = None, scan_id: int | None = None) -> tuple[str, str]:
    proc = subprocess.Popen(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if scan_id is not None:
        register_proc(scan_id, proc)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        if scan_id is not None:
            unregister_proc(scan_id, proc)
        raise CommandError(cmd, -1, stdout or "", stderr or "")
    except Exception:
        proc.kill()
        stdout, stderr = proc.communicate()
        if scan_id is not None:
            unregister_proc(scan_id, proc)
        raise
    if scan_id is not None:
        unregister_proc(scan_id, proc)
    if proc.returncode != 0:
        raise CommandError(cmd, proc.returncode, stdout or "", stderr or "")
    return stdout or "", stderr or ""
