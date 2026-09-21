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
# This entire independent exec has a five-second KILL deadline, including
# deletion. Never walk candidate-controlled directories in the signing exec.
subprocess.run(["/bin/sh", "-c", "exec rm -rf -- /tmp/ccb-*"], check=True)
'''
QUIESCENCE_COMMAND = ["timeout", "-s", "KILL", "5s",
                      "/usr/local/bin/python3", "-I", "-c", UID_QUIESCENCE]

# Shared verbatim by the prerequisite probe and every candidate launch.
RESTRICT_CHILD = r'''
def restrict_child(nofile=256):
    # No parent-death signal is trusted: the scorer independently kills this UID.
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        os._exit(125)
    if libc.prctl(8, 0, 0, 0, 0) != 0:  # PR_SET_KEEPCAPS = 0
        os._exit(125)
    # Useful on native Linux only: gVisor records this but ignores OOM priority.
    # Aggregate RSS is independently bounded by the watchdog below.
    with open("/proc/self/oom_score_adj", "w") as oom_score:
        oom_score.write("1000")
    os.setgroups([])
    os.setresgid(CANDIDATE_GID, CANDIDATE_GID, CANDIDATE_GID)
    os.setresuid(CANDIDATE_UID, CANDIDATE_UID, CANDIDATE_UID)
    # Set NPROC AFTER changing UID, avoiding execve's PF_NPROC_EXCEEDED trap.
    # These hard limits and the irreversible credential drop survive exec.
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
    # Half the production pod's 2 GiB budget leaves supervisor headroom.
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_DATA, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
'''

# Setup runs before any candidate exists. Both execs are bounded by the scorer.
SETUP = r'''
import ctypes, json, os, resource, secrets, shutil, subprocess, sys, tempfile
libc = ctypes.CDLL(None, use_errno=True)
CANDIDATE_UID = 65532
CANDIDATE_GID = 65532
limit = 4096
''' + RESTRICT_CHILD + r'''


def check_prerequisites(work):
    # No candidate bytes run here. Exercise the actual cross-UID /proc access
    # and executable work mount before issuing a key or launching a compiler.
    if os.getuid() != 0 or libc.prctl(4, 0, 0, 0, 0) != 0:
        raise RuntimeError()
    os.listdir("/proc")
    with open("/proc/self/oom_score_adj", "r+") as stream:
        value = stream.read()
        stream.seek(0)
        stream.write(value)
    probe = tempfile.mkdtemp(prefix="probe-", dir=work)
    child = None
    try:
        os.chown(probe, CANDIDATE_UID, CANDIDATE_GID)
        os.chmod(work, 0o711)
        script = os.path.join(probe, "executable")
        with open(script, "x", encoding="utf-8") as stream:
            stream.write("#!/bin/sh\n: > writable\n")
        os.chmod(script, 0o755)
        child = subprocess.Popen(
            [sys.executable, "-I", "-c", "import time; time.sleep(2)"],
            cwd=probe, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True, preexec_fn=restrict_child,
        )
        os.stat("/proc/" + str(child.pid) + "/fd/0")
        with open("/proc/" + str(child.pid) + "/status") as stream:
            fields = dict(line.split(":", 1) for line in stream if ":" in line)
        if (fields["Uid"].split() != [str(CANDIDATE_UID)] * 4
                or int(fields["VmRSS"].split()[0]) < 0):
            raise RuntimeError()
        subprocess.run(
            [script], cwd=probe, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, preexec_fn=restrict_child, check=True, timeout=1,
        )
        if os.stat(os.path.join(probe, "writable")).st_uid != CANDIDATE_UID:
            raise RuntimeError()
    finally:
        try:
            if child is not None:
                child.kill()
                child.wait(timeout=1)
        finally:
            os.chmod(work, 0o700)
            shutil.rmtree(probe)


try:
    request = json.load(sys.stdin)
    work = tempfile.mkdtemp(prefix="ccb-", dir="/tmp")
    check_prerequisites(work)
    key = secrets.token_hex(32)
    request["key"] = key
    with open(os.path.join(work, "request.json"), "x", encoding="utf-8") as f:
        json.dump(request, f)
    sys.stdout.write(json.dumps({"cwd": work, "key": key}))
except Exception:
    # Fixed text only: provider diagnostics and request bytes stay private.
    raise SystemExit("Sandbox setup failed; details withheld.") from None
'''

# Kept as source: importing this module never starts a process or executes code.
RUNNER = r'''
import base64
import ctypes
import errno
import hashlib
import hmac
import json
import os
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import threading
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


''' + RESTRICT_CHILD + r'''


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



def candidate_rss():
    total = 0
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/" + name + "/status") as stream:
                fields = dict(line.split(":", 1) for line in stream if ":" in line)
            if fields["Uid"].split()[0] == str(CANDIDATE_UID):
                # VmRSS is in KiB; zombies may have no VmRSS entry.
                # gVisor counts shared copy-on-write pages in each process's
                # VmRSS, so a 64-child fork storm can hit this aggregate cap.
                # Legitimate compiler/JVM chains have only a handful of
                # processes and stay far below the 768 MiB aggregate budget.
                total += int(fields.get("VmRSS", "0 kB").split()[0]) * 1024
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass
    return total


def kill_candidate(pgid):
    # Immediate KILL, without TERM grace or reaping in the watchdog thread.
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/" + name + "/status") as stream:
                fields = dict(line.split(":", 1) for line in stream if ":" in line)
            if fields["Uid"].split()[0] == str(CANDIDATE_UID):
                os.kill(int(name), signal.SIGKILL)
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass


def watch_memory(pgid, stopped, status):
    try:
        while not stopped.is_set():
            if candidate_rss() > 768 * 1024**2:
                status["memory_exceeded"] = True
                kill_candidate(pgid)
                return
            stopped.wait(0.05)
    except Exception:
        status["supervisor_error"] = True
        try:
            kill_candidate(pgid)
        except Exception:
            status["cleanup_failed"] = True


def candidate_disk_bytes(roots=("/tmp", "/var/tmp", "/dev/shm"), stopped=None,
                         proc_root="/proc"):
    # Return budget + 1 for either byte or inode exhaustion. Cancellation returns
    # the partial count; no complete traversal is needed on the signing path.
    budget = 256 * 1024**2
    total = 0
    count = 0
    seen = {}

    def cancelled():
        return stopped is not None and stopped.is_set()

    def account(info):
        nonlocal total
        if stat.S_ISREG(info.st_mode):
            identity = (info.st_dev, info.st_ino)
            size = info.st_blocks * 512
            previous = seen.get(identity, 0)
            # Count hardlinks, inherited descriptors and visible files once,
            # but include growth observed between the tree and descriptor scans.
            total += max(0, size - previous)
            seen[identity] = max(size, previous)

    # Descriptor-relative traversal prevents a directory swapped for a symlink
    # from redirecting the root supervisor. No file contents are opened.
    def open_directory(path, parent=None):
        try:
            return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                           dir_fd=parent)
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            return None
        except OSError as exc:
            if exc.errno in (errno.ENOTDIR, errno.ELOOP):
                return None
            raise

    for root in roots:
        if cancelled():
            return total
        fd = open_directory(root)
        if fd is None:
            continue
        stack = []
        try:
            stack.append((fd, os.scandir(fd)))
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            os.close(fd)
            continue
        except Exception:
            os.close(fd)
            raise
        try:
            while stack:
                if cancelled():
                    return total
                parent, entries = stack[-1]
                try:
                    entry = next(entries, None)
                except (PermissionError, FileNotFoundError, ProcessLookupError):
                    entry = None
                if entry is None:
                    entries.close()
                    os.close(parent)
                    stack.pop()
                    continue
                count += 1
                if count > 10000:
                    return budget + 1
                try:
                    info = entry.stat(follow_symlinks=False)
                except (PermissionError, FileNotFoundError, ProcessLookupError):
                    continue
                account(info)
                if total > budget:
                    return total
                if stat.S_ISDIR(info.st_mode):
                    fd = open_directory(entry.name, parent)
                    if fd is not None:
                        try:
                            stack.append((fd, os.scandir(fd)))
                        except (PermissionError, FileNotFoundError, ProcessLookupError):
                            os.close(fd)
                        except Exception:
                            os.close(fd)
                            raise
        finally:
            for fd, entries in stack:
                entries.close()
                os.close(fd)
    # /proc magic links expose even unlinked files and anonymous memfds.
    # The candidate's hard NOFILE and NPROC limits bound this scan.
    for name in os.listdir(proc_root):
        if cancelled():
            return total
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(proc_root, name, "status")) as stream:
                fields = dict(line.split(":", 1) for line in stream if ":" in line)
            if fields["Uid"].split()[0] != str(CANDIDATE_UID):
                continue
            with os.scandir(os.path.join(proc_root, name, "fd")) as descriptors:
                for descriptor in descriptors:
                    if cancelled():
                        return total
                    try:
                        account(os.stat(descriptor.path))
                    except (PermissionError, FileNotFoundError, ProcessLookupError):
                        continue
                    if total > budget:
                        return total
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass
    return total


def watch_disk(pgid, stopped, status):
    try:
        while not stopped.is_set():
            if candidate_disk_bytes(stopped=stopped) > 256 * 1024**2:
                status["disk_exceeded"] = True
                kill_candidate(pgid)
                return
            stopped.wait(0.1)
    except Exception:
        status["supervisor_error"] = True
        try:
            kill_candidate(pgid)
        except Exception:
            status["cleanup_failed"] = True


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
    java_step = os.path.basename(argv[0]) in {"java", "javac"}
    child_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": candidate_work,
                 "TMPDIR": candidate_work, "JAVA_TOOL_OPTIONS": "-XX:-UsePerfData"}
    with tempfile.TemporaryFile(dir=work) as stdout, tempfile.TemporaryFile(dir=work) as stderr:
        child = subprocess.Popen(
            argv, cwd=candidate_work,
            env=child_env,
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True,
            start_new_session=True, preexec_fn=lambda: restrict_child(1024 if java_step else 256),
        )
        status = dict(returncode=125, timeout=False, overflow=False, memory_exceeded=False, disk_exceeded=False,
                      cleanup_failed=False, supervisor_error=False)
        output = b""
        stopped = threading.Event()
        watchdogs = [threading.Thread(target=watcher, args=(child.pid, stopped, status), daemon=True)
                     for watcher in (watch_memory, watch_disk)]
        try:
            # Start after Popen: preexec_fn must not fork a threaded supervisor.
            for watchdog in watchdogs:
                watchdog.start()
            status["returncode"] = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            status["timeout"] = True
        except Exception:
            status["supervisor_error"] = True
        finally:
            # Cancel filesystem work immediately, before cleanup. Never wait for
            # a complete scan: even a blocked syscall cannot delay signing.
            stopped.set()
            for watchdog in watchdogs:
                try:
                    watchdog.join(timeout=0.2)
                    if watchdog.is_alive():
                        status["supervisor_error"] = True
                except Exception:
                    status["supervisor_error"] = True
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


status = dict(returncode=125, timeout=False, overflow=False, memory_exceeded=False, disk_exceeded=False,
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
                       ("timeout", "overflow", "memory_exceeded", "disk_exceeded", "cleanup_failed", "supervisor_error")))
    outputs = {}
    if compile_success and "run_argv" in request:
        stage = "run"
        status, output = run_step(request["run_argv"], request["run_timeout"], candidate_work)
        if status["returncode"] == 0 and not any(status[flag] for flag in
                ("timeout", "overflow", "memory_exceeded", "disk_exceeded", "cleanup_failed", "supervisor_error")):
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
    body = json.dumps({**status, "stage": stage, "compile_success": compile_success,
                      "outputs": outputs,
                      "output": base64.b64encode(output).decode("ascii"), "cwd": work}, separators=(",", ":"))
    tag = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    sys.stdout.write(json.dumps({"body": body, "tag": tag}))
    sys.stdout.flush()
    os._exit(0)
'''
