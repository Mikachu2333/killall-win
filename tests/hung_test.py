"""
hung_test.py - Creates a visible window then freezes it.
Used to test `killall hung`.

Usage:
    python hung_test.py
    killall hung               # dry-run (default): should detect this process
    killall hung -y            # kills it
"""
import tkinter as tk
import time
import threading
import os

def freeze():
    time.sleep(2)   # give window time to appear and register
    print(f"[hung_test] Window frozen. PID={os.getpid()}", flush=True)
    while True:
        pass        # block forever = hung window

root = tk.Tk()
root.title("HUNG TEST WINDOW - killall test")
root.geometry("420x120")
tk.Label(
    root,
    text=f"Intentionally hung process (PID {os.getpid()})\nRun: killall hung --force",
    font=("Consolas", 11),
    pady=20
).pack()
root.update()

t = threading.Thread(target=freeze, daemon=False)
t.start()
t.join()
