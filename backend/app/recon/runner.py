import subprocess
from pathlib import Path

class CommandError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stdout: str, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"Command failed ({returncode}): {' '.join(cmd)}\n{stderr}")

def run_command(cmd: list[str], cwd: Path | None = None, timeout: int | None = None) -> tuple[str, str]:
    proc = subprocess.run(cmd, cwd=cwd, timeout=timeout, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise CommandError(cmd, proc.returncode, proc.stdout, proc.stderr)
    return proc.stdout, proc.stderr
