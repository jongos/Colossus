"""Bounded, sanitized read-only Git runner extracted from repository_cleanup.py."""
import hashlib
import os
import queue
import subprocess
import threading
from next_cache_native import require

def git_run(executable, repository, args, *, maximum=8*1024*1024, hash_only=False):
    env = {k:v for k,v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='NUL', GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0', GIT_ATTR_NOSYSTEM='1')
    command = [str(executable), '--no-optional-locks', '--literal-pathspecs', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=NUL', '-c', 'core.attributesFile=NUL', '-c', 'core.excludesFile=NUL', *args]
    p = subprocess.Popen(command, cwd=repository, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    done = queue.Queue()
    def read():
        try:
            h = hashlib.sha256(); data = bytearray(); size = 0
            while True:
                part = p.stdout.read(65536)
                if not part: break
                size += len(part); require(size <= maximum, 'Git output limit exceeded')
                if hash_only: h.update(part)
                else: data.extend(part)
            done.put((True, (h.hexdigest(), size) if hash_only else bytes(data)))
        except Exception as exc: done.put((False, exc))
    worker = threading.Thread(target=read, daemon=True); worker.start()
    try:
        ok, result = done.get(timeout=30)
        if not ok: raise result
        require(p.wait(timeout=5) == 0, 'Git command refused')
        return result
    except BaseException:
        p.kill(); p.wait(); raise
    finally:
        worker.join(timeout=5); p.stdout.close()

