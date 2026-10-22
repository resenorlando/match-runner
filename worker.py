"""Trusted supervisor for one shard. Runs as root inside fresh network, mount and PID namespaces
(see .github/workflows/batch.yml) with private empty /run, /tmp and /dev/shm.

1. Refuses to touch the key unless the namespace has no network interface except loopback and
   nothing outside is reachable.
2. Decrypts in memory (the AES-GCM tag is checked before anything is extracted). The bundle's
   own spec.json says which installed program to run, with which arguments and environment.
3. Runs that program as the unprivileged user `w`: no sudo, no new privileges, no capabilities,
   no inherited descriptors except a private log file.
4. Kills every `w` process, encrypts only status, logs and out/, and deletes all plaintext.
The public job log gets one fixed line; everything else stays inside the encrypted result.
"""
import io
import json
import os
import pwd
import re
import resource
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import traceback
from pathlib import Path

import seal

WORKER = "w"
PREP_LOG = Path("/root/prep.log")


def network_sealed():
    """Structural check first (only loopback exists), then probes as a second opinion."""
    if sorted(os.listdir("/sys/class/net")) != ["lo"]:
        return False
    for fam, addr in ((socket.AF_INET, ("1.1.1.1", 443)), (socket.AF_INET, ("8.8.8.8", 53)),
                      (socket.AF_INET6, ("2606:4700:4700::1111", 443))):
        try:
            with socket.socket(fam, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect(addr)
            return False
        except OSError:
            pass
    return True


def fill(value, shard, home):
    return str(value).replace("{shard}", str(shard)).replace("{home}", str(home))


def main():
    if os.geteuid() != 0 or not network_sealed():
        return 2
    key = seal.parse_key(os.environ.pop("JOB_KEY", ""))
    rid = os.environ.pop("RID")
    seal.check_rid(rid)
    shard = int(os.environ.pop("SHARD"))
    repo = Path(os.environ["GITHUB_WORKSPACE"])
    result_path = repo / "result" / "res.enc"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    w = pwd.getpwnam(WORKER)
    home = Path(w.pw_dir)
    ws = home / "ws"
    log_path = Path("/run/job.log")  # private tmpfs, root only
    status = {"shard": shard, "prep_ok": Path("/root/prep.ok").is_file(),
              "exit": None, "error": None, "seconds": None}
    log_bytes = b""
    try:
        try:
            blob = (repo / "jobs" / f"{rid}.enc").read_bytes()
            plain = seal.decrypt(key, blob, seal.job_aad(rid))
            shutil.rmtree(ws, ignore_errors=True)
            with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tf:
                tf.extractall(ws, filter="data")
            del plain
            spec = json.loads((ws / "spec.json").read_text())
            exe = spec["exe"]
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", exe):
                raise ValueError("bad exe")
            argv = [fill(a, shard, home) for a in spec["argv"]]
            (ws / "out").mkdir(exist_ok=True)
            for p in [ws, *ws.rglob("*")]:
                os.chown(p, w.pw_uid, w.pw_gid, follow_symlinks=False)

            env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home), "USER": WORKER,
                   "LANG": "C.UTF-8", "TMPDIR": "/tmp", "NO_COLOR": "1"}
            env.update({k: fill(v, shard, home) for k, v in spec.get("env", {}).items()})
            cmd = ["setpriv", f"--reuid={w.pw_uid}", f"--regid={w.pw_gid}", "--clear-groups",
                   "--no-new-privs", "--inh-caps=-all", "--",
                   str(Path(sys.executable).parent / exe), *argv]
            t0 = time.time()
            with open(log_path, "wb") as log:
                try:
                    p = subprocess.run(cmd, cwd=ws, stdin=subprocess.DEVNULL, stdout=log,
                                       stderr=subprocess.STDOUT, env=env, close_fds=True,
                                       timeout=int(spec.get("wall_seconds", 19800)))
                    status["exit"] = p.returncode
                except subprocess.TimeoutExpired:
                    status["exit"] = "timeout"
            status["seconds"] = round(time.time() - t0)
        except Exception as e:
            status["error"] = type(e).__name__
            log_bytes += ("\n" + traceback.format_exc()).encode()
        finally:
            subprocess.run(["pkill", "-KILL", "-u", WORKER], capture_output=True)

        if log_path.is_file():
            log_bytes = log_path.read_bytes() + log_bytes
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            add_bytes(tf, "status.json", json.dumps(status).encode())
            add_bytes(tf, "log.txt", log_bytes)
            if PREP_LOG.is_file():
                add_bytes(tf, "prep.txt", PREP_LOG.read_bytes())
            out = ws / "out"
            if out.is_dir() and not out.is_symlink():
                for f in sorted(out.rglob("*")):
                    if f.is_file() and not f.is_symlink():
                        add_bytes(tf, "out/" + f.relative_to(out).as_posix(), f.read_bytes())
        enc = seal.encrypt(key, buf.getvalue(), seal.result_aad(rid, shard))
        del buf, log_bytes
        result_path.write_bytes(enc)
        return 0
    finally:
        # Remove every plaintext copy before any later step (the upload) runs.
        shutil.rmtree(ws, ignore_errors=True)
        log_path.unlink(missing_ok=True)
        PREP_LOG.unlink(missing_ok=True)


def add_bytes(tf, name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = 0
    tf.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    try:
        rc = main()
    except Exception:
        rc = 1
    # Fixed public message only: outcomes stay inside the encrypted result.
    print("shard finished" if rc == 0 else f"shard could not produce a result (code {rc})")
    sys.exit(rc)
