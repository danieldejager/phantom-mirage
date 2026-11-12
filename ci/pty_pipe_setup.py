#!/usr/bin/env python3
"""Run phantom-mirage-setup the way the one-liner does, on a real pty.

    python3 ci/pty_pipe_setup.py IFACE NETWORK

The installer is piped into sudo, like `curl | sudo bash`, and sudo's
use_pty is left on. Answers are written to the pty as each prompt appears.
"""
import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time


# The marker is the end of the question, so the answer is not sent while
# the prompt is still being drawn.
PROMPTS = (
    ("Sensor name (required): ", "sensor1"),
    ("Admin username: ", "admin"),
    ("[8443]: ", ""),
    ("[browser]: ", ""),
    ("[UTC]: ", ""),
    ("[90]: ", ""),
    ("Admin password (hidden, 12+ characters): ", "Ci-console-pass-1"),
    ("Repeat password: ", "Ci-console-pass-1"),
    ("[Y/n] ", "y"),
)


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: pty_pipe_setup.py IFACE NETWORK\n")
        return 2
    iface, network = sys.argv[1], sys.argv[2]
    driver = "/tmp/pm-pty-driver.sh"
    with open(driver, "w") as f:
        f.write("#!/bin/sh\nexport PM_SETUP_TRACE=1\nexec /usr/sbin/phantom-mirage-setup -i %s -n %s\n" % (iface, network))
    os.chmod(driver, 0o755)
    pid, fd = pty.fork()
    if pid == 0:
        # Cooked echo, so a typed line is one line. A raw pty never delivers it.
        attr = termios.tcgetattr(0)
        attr[0] |= termios.ICRNL
        attr[3] |= termios.ICANON | termios.ECHO | termios.ECHOE | termios.ISIG
        termios.tcsetattr(0, termios.TCSANOW, attr)
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
        os.execvp("bash", ["bash", "-c", "cat %s | sudo bash" % driver])
    buf = b""
    step = 0
    end = time.time() + 120
    rc = 1
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.3)
        if fd in r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b""
            if chunk:
                buf += chunk
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
        text = buf.decode("utf-8", "replace")
        if step < len(PROMPTS) and PROMPTS[step][0] in text:
            time.sleep(0.1)
            os.write(fd, (PROMPTS[step][1] + "\n").encode())
            step += 1
        pid_done, status = os.waitpid(pid, os.WNOHANG)
        if pid_done:
            rc = os.waitstatus_to_exitcode(status)
            break
    else:
        os.kill(pid, 15)
        sys.stderr.write("pty_pipe_setup: timed out at prompt %d\n" % step)
        return 1
    if step != len(PROMPTS):
        sys.stderr.write("pty_pipe_setup: saw %d of %d prompts\n" % (step, len(PROMPTS)))
        return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
