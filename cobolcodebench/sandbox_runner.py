"""Trusted supervisor source, executed ONLY in the external Linux sandbox.

A completed setup exec writes the request into a fresh directory. The supervisor
reads and unlinks it before starting the candidate. The setup Python process
generates the key locally; no ancestor shell receives it as stdin or an argument. The key is then memory-only.
The root supervisor drops the child to reserved UID/GID 65532 before exec.
PR_SET_DUMPABLE also protects supervisor memory/fds.
The child has separate stdio, no inherited supervisor descriptors, no core dumps,
no privilege gains, and bounded process/address-space/data limits.
Only the supervisor can authenticate the wait() status. Provider stdout markers
can truncate/destroy the receipt, but cannot manufacture a valid passing receipt.
"""

CANDIDATE_UID = 65532
CANDIDATE_GID = 65532
# procps pkill returns 1 when there are no matching processes.
CLEANUP_COMMAND = ["timeout", "-s", "KILL", "5s",
                   "/usr/bin/pkill", "-KILL", "-u", str(CANDIDATE_UID)]

# Compilers need forks. After the template's independent
# pkill exec, verify quiescence with repeated UID sweeps (escaped sessions too).
# Ignore zombies: they cannot execute and belong to the container's reaper.
UID_QUIESCENCE = r'''
import os, subprocess, time
until = time.monotonic() + 3
while True:
    sweep = subprocess.run(["/usr/bin/pkill", "-KILL", "-u", "65532"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=1)
    if sweep.returncode not in (0, 1):
        raise SystemExit(2)
    active = False
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/" + name + "/status") as stream:
                status = dict(line.split(":", 1) for line in stream if ":" in line)
            if status["Uid"].split()[0] == "65532" and status["State"].split()[0] not in {"Z", "X"}:
                active = True
        except FileNotFoundError:
            pass
    if not active:
        break
    if time.monotonic() >= until:
        raise SystemExit(2)
    time.sleep(0.02)
'''
QUIESCENCE_COMMAND = ["timeout", "-s", "KILL", "5s",
                      "/usr/local/bin/python3", "-I", "-c", UID_QUIESCENCE]

# Setup runs before any candidate exists. Both execs are bounded by the scorer.
SETUP = r'''
import json, os, secrets, sys, tempfile
request = json.load(sys.stdin)
key = secrets.token_hex(32)
request["key"] = key
work = tempfile.mkdtemp(prefix="ccb-", dir="/tmp")
with open(os.path.join(work, "request.json"), "x", encoding="utf-8") as f:
    json.dump(request, f)
sys.stdout.write(json.dumps({"cwd": work, "key": key}))
'''

# Kept as source: importing this module never starts a process or executes code.
RUNNER = r'''
import base64
import ctypes
import hashlib
import hmac
import json
import os
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

CANDIDATE_UID = 65532
CANDIDATE_GID = 65532
libc = ctypes.CDLL(None, use_errno=True)
if os.getuid() != 0 or libc.prctl(4, 0, 0, 0, 0) != 0:
    raise RuntimeError("root Linux supervisor with protected memory required")
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    raise RuntimeError("subreaper required")
work = sys.argv[1]
request_path = os.path.join(work, "request.json")
with open(request_path, encoding="utf-8") as f:
    request = json.load(f)
os.unlink(request_path)
key = bytes.fromhex(request.pop("key"))
limit = request["output_limit"]


def restrict_child():
    # No parent-death signal is trusted: the scorer independently kills this UID.
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        os._exit(125)
    if libc.prctl(8, 0, 0, 0, 0) != 0:  # PR_SET_KEEPCAPS = 0
        os._exit(125)
    # Set before dropping root; inherited by exec and all descendants. Prefer
    # the candidate over the supervisor if a cgroup memory budget is exceeded.
    with open("/proc/self/oom_score_adj", "w") as oom_score:
        oom_score.write("1000")
    os.setgroups([])
    os.setresgid(CANDIDATE_GID, CANDIDATE_GID, CANDIDATE_GID)
    os.setresuid(CANDIDATE_UID, CANDIDATE_UID, CANDIDATE_UID)
    # Set NPROC AFTER changing UID, avoiding execve's PF_NPROC_EXCEEDED trap.
    # These hard limits and the irreversible credential drop survive exec.
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    # Half the production pod's 2 GiB budget leaves supervisor headroom.
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_DATA, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def kill_group(pgid):
    # Kill the entire original session's process group, even if the leader exited.
    # An independent UID sweep below also kills descendants that change sessions.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            pass
        if sig == signal.SIGTERM:
            time.sleep(0.1)



def sweep_uid():
    # No spawn: detached descendants must not consume the slots needed to sign.
    # Reap adopted children too, so zombies don't retain the UID's NPROC budget.
    until = time.monotonic() + 3
    while True:
        active = False
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open("/proc/" + name + "/status") as stream:
                    fields = dict(line.split(":", 1) for line in stream if ":" in line)
                if (fields["Uid"].split()[0] == str(CANDIDATE_UID)
                        and fields["State"].split()[0] not in {"Z", "X"}):
                    active = True
                    os.kill(int(name), signal.SIGKILL)
            except ProcessLookupError:
                pass
            except FileNotFoundError:
                pass
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                break
        if not active:
            return
        if time.monotonic() >= until:
            raise RuntimeError("UID sweep did not complete")
        time.sleep(0.02)


def run_step(argv, timeout, candidate_work):
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) for x in argv):
        raise ValueError("argv must be a nonempty string list")
    with tempfile.TemporaryFile(dir=work) as stdout, tempfile.TemporaryFile(dir=work) as stderr:
        child = subprocess.Popen(
            argv, cwd=candidate_work,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": candidate_work, "TMPDIR": candidate_work},
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True,
            start_new_session=True, preexec_fn=restrict_child,
        )
        status = dict(returncode=125, timeout=False, overflow=False,
                      cleanup_failed=False, supervisor_error=False)
        output = b""
        try:
            status["returncode"] = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            status["timeout"] = True
        except Exception:
            status["supervisor_error"] = True
        finally:
            # Each post-exit operation is isolated: none may suppress signing.
            try:
                kill_group(child.pid)
            except Exception:
                status["cleanup_failed"] = True
            try:
                status["returncode"] = child.wait(timeout=1)
            except Exception:
                status["cleanup_failed"] = True
            try:
                sweep_uid()
            except Exception:
                status["cleanup_failed"] = True
        try:
            stdout.seek(0)
            output = stdout.read(limit + 1)
            status["overflow"] = len(output) >= limit or os.fstat(stderr.fileno()).st_size >= limit
        except Exception:
            status["supervisor_error"] = True
        return status, output


status = dict(returncode=125, timeout=False, overflow=False,
              cleanup_failed=False, supervisor_error=False)
stage = "compile"
compile_success = False
output = b""
outputs = {}


try:
    # Keep launch/request directory root-owned; only its child is writable.
    candidate_work = os.path.join(work, "candidate")
    os.mkdir(candidate_work, 0o700)
    os.chown(candidate_work, CANDIDATE_UID, CANDIDATE_GID)
    os.chmod(work, 0o711)
    for name, content in request["files"].items():
        if not name or name in {".", ".."} or os.path.basename(name) != name:
            raise ValueError("Only plain filenames are allowed")
        path = os.path.join(candidate_work, name)
        with open(path, "x", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, 0o644)
        # COBOL OPEN I-O / EXTEND and REWRITE need owner write access, including
        # when a declared output is also an input. The launch dir stays root-owned.
        os.chown(path, CANDIDATE_UID, CANDIDATE_GID)
    status, output = run_step(request["argv"], request["timeout"], candidate_work)
    stage = "compile"
    compile_success = (status["returncode"] == 0 and not any(status[flag] for flag in
                       ("timeout", "overflow", "cleanup_failed", "supervisor_error")))
    outputs = {}
    if compile_success and "run_argv" in request:
        stage = "run"
        status, output = run_step(request["run_argv"], request["run_timeout"], candidate_work)
        if status["returncode"] == 0 and not any(status[flag] for flag in
                ("timeout", "overflow", "cleanup_failed", "supervisor_error")):
            total_bytes = 0
            for name in request.get("output_files", []):
                if not name or name in {".", ".."} or os.path.basename(name) != name:
                    raise ValueError("Invalid output filename")
                outputs[name] = None
                # Candidate descendants are dead before any file read. Never follow
                # symlinks or open a blocking FIFO/device, even under the root supervisor.
                try:
                    fd = os.open(os.path.join(candidate_work, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, "rb") as f:
                        info = os.fstat(f.fileno())
                        if not stat.S_ISREG(info.st_mode) or info.st_uid != CANDIDATE_UID or info.st_nlink != 1:
                            raise ValueError("Unsafe output file")
                        content = f.read(max(0, limit - total_bytes) + 1)
                    total_bytes += len(content)
                    status["overflow"] = status["overflow"] or total_bytes >= limit
                    outputs[name] = base64.b64encode(content).decode("ascii")
                except (OSError, ValueError):
                    pass
except Exception:
    # Includes candidate-caused launch/read failures and post-run exceptions.
    # Exception text can contain candidate bytes; publish only a signed flag.
    status["supervisor_error"] = True
finally:
    try:
        shutil.rmtree(work)
    except Exception:
        status["cleanup_failed"] = True
    body = json.dumps({**status, "stage": stage, "compile_success": compile_success,
                      "outputs": outputs,
                      "output": base64.b64encode(output).decode("ascii"), "cwd": work}, separators=(",", ":"))
    tag = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    sys.stdout.write(json.dumps({"body": body, "tag": tag}))
    sys.stdout.flush()
'''
