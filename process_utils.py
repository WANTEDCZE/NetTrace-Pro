"""Windows-safe child process execution (no flashing console windows)."""
import subprocess
import os

def run_hidden(args, **kwargs):
    if os.name == "nt":
        kwargs.setdefault("creationflags", getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        kwargs.setdefault("startupinfo", startupinfo)
    return subprocess.run(args, shell=False, **kwargs)
