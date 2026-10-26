#!/usr/bin/env python3
"""Render cert.ICONS into icons/*.png with iconkit.js. Re-run after changing ICONS:

  /usr/bin/python3 -B make_icons.py
"""
import json
import os
import subprocess
import sys
import tempfile

import cert

HERE = os.path.dirname(os.path.abspath(__file__))


def jobs(out_dir):
    return [{"out": os.path.join(out_dir, name + ".png"), "bg": bg, "symbol": symbol}
            for name, (bg, symbol) in sorted(cert.ICONS.items())]


def main():
    out_dir = os.path.join(HERE, "icons")
    os.makedirs(out_dir, exist_ok=True)
    todo = jobs(out_dir)
    fd, spec = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(todo, f)
    try:
        r = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", os.path.join(HERE, "iconkit.js"), spec],
                           capture_output=True, text=True, timeout=60)
    finally:
        os.remove(spec)
    sys.stderr.write(r.stderr)  # iconkit names each failed icon here (e.g. an unknown SF Symbol)
    done = r.stdout.strip()
    print("rendered %s icons into %s" % (done or "0/%d" % len(todo), out_dir))
    return 0 if done == "%d/%d" % (len(todo), len(todo)) else 1


if __name__ == "__main__":
    sys.exit(main())
