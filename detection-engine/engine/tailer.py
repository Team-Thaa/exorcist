"""Follow a Zeek JSON log file like `tail -f`, surviving Zeek's hourly log rotation."""
import json
import os
import time


def follow(path, from_start=False, poll=0.5):
    """Yield one dict per Zeek log line. Waits for the file if it does not exist yet."""
    f, inode = None, None
    while True:
        if f is None:
            if not os.path.exists(path):
                time.sleep(poll)
                continue
            f = open(path, "r")
            inode = os.fstat(f.fileno()).st_ino
            if not from_start:
                f.seek(0, os.SEEK_END)
            from_start = True  # after a rotation, read the new file from its start

        line = f.readline()
        if line:
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass
            continue

        # No new line: check whether Zeek rotated the file.
        try:
            if os.stat(path).st_ino != inode:
                f.close()
                f = None
                continue
        except FileNotFoundError:
            f.close()
            f = None
            continue
        time.sleep(poll)
