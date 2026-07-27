import os
import queue
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class ProcessRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._procs: dict[int, list[subprocess.Popen]] = {}

    @contextmanager
    def track(self, scan_id: int | None, proc: subprocess.Popen) -> Iterator[None]:
        if scan_id is None:
            yield
            return
        self.register(scan_id, proc)
        try:
            yield
        finally:
            self.unregister(scan_id, proc)

    def register(self, scan_id: int, proc: subprocess.Popen) -> None:
        with self._lock:
            self._procs.setdefault(scan_id, []).append(proc)

    def unregister(self, scan_id: int, proc: subprocess.Popen) -> None:
        with self._lock:
            procs = self._procs.get(scan_id)
            if not procs:
                return
            if proc in procs:
                procs.remove(proc)
            if not procs:
                del self._procs[scan_id]

    def pop_scan(self, scan_id: int) -> list[subprocess.Popen]:
        with self._lock:
            return list(self._procs.pop(scan_id, []))


PROCESS_REGISTRY = ProcessRegistry()


class CommandError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stdout: str, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"Command failed ({returncode}): {' '.join(cmd)}\n{stderr}")


class CommandRunner:
    def __init__(self, scan_id: int | None = None, registry: ProcessRegistry = PROCESS_REGISTRY):
        self.scan_id = scan_id
        self.registry = registry

    def run(self, cmd: list[str], cwd: Path | None = None, timeout: int | None = None) -> tuple[str, str]:
        return _run_process(cmd, cwd=cwd, timeout=timeout, scan_id=self.scan_id, registry=self.registry)

    def run_stream(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        timeout: int | None = None,
        output_path: Path | None = None,
        log_prefix: str = "",
    ) -> tuple[str, str]:
        return _run_process_stream(
            cmd,
            cwd=cwd,
            timeout=timeout,
            scan_id=self.scan_id,
            registry=self.registry,
            output_path=output_path,
            log_prefix=log_prefix,
        )


def _run_process(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int | None = None,
    scan_id: int | None = None,
    registry: ProcessRegistry = PROCESS_REGISTRY,
) -> tuple[str, str]:
    proc = subprocess.Popen(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with registry.track(scan_id, proc):
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            raise CommandError(cmd, -1, stdout or "", stderr or "")
        except Exception:
            proc.kill()
            proc.communicate()
            raise
    if proc.returncode != 0:
        raise CommandError(cmd, proc.returncode, stdout or "", stderr or "")
    return stdout or "", stderr or ""


def run_command(cmd: list[str], cwd: Path | None = None, timeout: int | None = None) -> tuple[str, str]:
    return _run_process(cmd, cwd=cwd, timeout=timeout)


def _run_process_stream(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int | None = None,
    scan_id: int | None = None,
    registry: ProcessRegistry = PROCESS_REGISTRY,
    output_path: Path | None = None,
    log_prefix: str = "",
) -> tuple[str, str]:
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    lines: list[str] = []
    line_queue: queue.Queue[str | None] = queue.Queue()

    def read_output() -> None:
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                line_queue.put(line)
        finally:
            line_queue.put(None)

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    started = time.monotonic()
    output_file = output_path.open("a", encoding="utf-8") if output_path else None
    stream_done = False
    try:
        with registry.track(scan_id, proc):
            while not stream_done:
                if timeout is not None and time.monotonic() - started > timeout:
                    proc.kill()
                    break
                try:
                    line = line_queue.get(timeout=0.5)
                except queue.Empty:
                    if proc.poll() is not None and not reader.is_alive():
                        break
                    continue
                if line is None:
                    stream_done = True
                    continue
                lines.append(line)
                if output_file:
                    output_file.write(line)
                    output_file.flush()
                if line.strip():
                    print(f"{log_prefix}{line}", end="", flush=True)
            returncode = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        returncode = proc.wait(timeout=2)
    finally:
        if output_file:
            output_file.close()
        reader.join(timeout=1)

    stdout = "".join(lines)
    if timeout is not None and time.monotonic() - started > timeout and returncode != 0:
        raise CommandError(cmd, -1, stdout, "")
    if returncode != 0:
        raise CommandError(cmd, returncode, stdout, "")
    return stdout, ""


def run_command_stream(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int | None = None,
    output_path: Path | None = None,
    log_prefix: str = "",
) -> tuple[str, str]:
    return _run_process_stream(cmd, cwd=cwd, timeout=timeout, output_path=output_path, log_prefix=log_prefix)


def cancel_scan(scan_id: int) -> int:
    """Kill all subprocesses for a scan. Returns count of processes killed."""
    killed = 0
    for proc in PROCESS_REGISTRY.pop_scan(scan_id):
        if proc.poll() is not None:
            continue
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
