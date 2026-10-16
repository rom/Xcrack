#!/usr/bin/env python3
"""Drive `age -p` over a pty so its passphrase prompt can be answered
non-interactively. Usage: _ptyage.py PASSPHRASE OUTFILE INFILE

age reads the passphrase from the controlling terminal (never stdin/argv, by
design), so a pty is the only way to script it. This is used solely to build
the demo samples; nothing in Xcrack itself needs it.
"""
import os
import pty
import select
import sys
import time


def main() -> int:
    passphrase, outfile, infile = sys.argv[1], sys.argv[2], sys.argv[3]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("age", ["age", "-p", "-o", outfile, infile])
        os._exit(127)
    sent = 0
    deadline = time.time() + 20
    buf = b""
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.5)
        if fd not in r:
            continue
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        buf += data
        # Answer each "passphrase" prompt (enter, then confirm) exactly once each.
        while b"passphrase" in buf.lower() and sent < 2:
            buf = buf.lower().split(b"passphrase", 1)[1]
            os.write(fd, passphrase.encode() + b"\n")
            sent += 1
    _, status = os.waitpid(pid, 0)
    return 0 if os.path.exists(outfile) and os.path.getsize(outfile) > 0 else (status or 1)


if __name__ == "__main__":
    sys.exit(main())
