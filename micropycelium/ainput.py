"""Copyright (c) 2025 Jonathan Voss (k98kurz)

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""

from asyncio import sleep_ms
from collections import deque
import sys
import select


line_buffer = deque([], 10)

async def ainput(prompt="", timeout=False):
    """An asynchronous line input function for MicroPython that detects arrow key sequences."""
    sys.stdout.write(prompt)
    flush = getattr(sys.stdout, 'flush', lambda: None)
    flush()
    line = ""
    while True:
        # Poll sys.stdin to see if there's any data available.
        r, _, _ = select.select([sys.stdin], [], [], 0)
        if r:
            char = sys.stdin.read(1)

            # Detect beginning of an escape sequence.
            if char == "\x1b":
                # Give a tiny window for the next bytes (usually 2) to arrive.
                r2, _, _ = select.select([sys.stdin], [], [], 0.01)
                if r2:
                    # Read the next two characters.
                    seq = sys.stdin.read(2)
                    if len(seq) == 2 and seq[0] == "[" and seq[1] in "ABCD":
                        # Arrow key: (ESC + '[' + [A, B, C, or D])
                        if seq[1] == "A":
                            # up
                            if len(line_buffer):
                                # clear the line
                                oldl = line
                                oldll = len(line)
                                line = line_buffer.pop()
                                line_buffer.appendleft(line)
                                if oldl == line:
                                    sys.stdout.write("\r" + prompt + " " * oldll)
                                else:
                                    sys.stdout.write("\r" + prompt + line)
                                    sys.stdout.write(" " * (oldll - len(line)))
                                # move cursor to the end of the line
                                sys.stdout.write("\r" + prompt + line)
                                flush()
                        elif seq[1] == "B":
                            # down
                            if len(line_buffer):
                                # clear the line
                                oldl = line
                                oldll = len(line)
                                line = line_buffer.popleft()
                                line_buffer.append(line)
                                sys.stdout.write("\r" + prompt + line)
                                sys.stdout.write(" " * (oldll - len(line)))
                                if oldl == line:
                                    sys.stdout.write("\r" + prompt + " " * oldll)
                                else:
                                    sys.stdout.write("\r" + prompt + line)
                                    sys.stdout.write(" " * (oldll - len(line)))
                                # move cursor to the end of the line
                                sys.stdout.write("\r" + prompt + line)
                                flush()
                        elif seq[1] == "C":
                            # right; ignore
                            ...
                        elif seq[1] == "D":
                            # left; ignore
                            ...
                        continue
                    else:
                        # Not an arrow key; treat the escape and sequence as normal text.
                        line += char + seq
                        sys.stdout.write(char + seq)
                        flush()
                        continue
                else:
                    # No additional characters found; treat the ESC as a normal character.
                    line += char
                    sys.stdout.write(char)
                    flush()
                    continue

            if char in ("\r", "\n"):
                sys.stdout.write("\n")
                flush()
                if len(line) and line not in line_buffer:
                    line_buffer.append(line)
                return line
            elif char in ("\x08", "\x7f"):
                if line:
                    line = line[:-1]
                    # Erase the last character visually.
                    sys.stdout.write("\b \b")
                    flush()
            else:
                line += char
                sys.stdout.write(char)
                flush()
        # If a timeout flag is set, return None immediately.
        if timeout:
            return None
        # Yield control so other asyncio tasks can run.
        await sleep_ms(10)
