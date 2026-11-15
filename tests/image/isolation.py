"""Isolation guard of the image acceptance harness (security-contracts.md S1.4, SELF-13).

The harness creates, execs into and removes containers and mounts the Docker socket into the images it
tests. It must therefore only ever talk to a Docker daemon the caller named explicitly AND whose identity
matches what the caller declared, and never to the ambient default (DOCKER_HOST, the current CLI context,
/var/run/docker.sock) or to an Unraid host. The guard has no fallback: any doubt raises Refused before the
first container, network or file is created, and again before cleanup (a different daemon at cleanup time
means nothing is removed).

Standard library only.
"""
import json
import os
import stat
import subprocess

# Markers of the production host family. Docker reports the host OS, host name and kernel in `docker info`;
# /etc/unraid-version exists on an Unraid host (a unix-socket endpoint is always on this machine).
UNRAID_MARKERS = ("unraid",)
UNRAID_FILE = "/etc/unraid-version"


class Refused(Exception):
    """The endpoint is not an approved isolated fixture daemon. Nothing may be created or removed."""


def socket_path(endpoint):
    """The absolute unix socket path of an explicit endpoint (unix:///abs/path). Anything else is refused:
    the harness bind-mounts the socket into the images under test, which a TCP or SSH endpoint cannot give."""
    if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
        raise Refused("the fixture endpoint must be an explicit unix:///absolute/path socket")
    path = endpoint[len("unix://"):]
    if "\0" in path or ".." in path.split("/"):
        raise Refused("the fixture endpoint path is not a plain absolute path")
    return path


def _info(endpoint):
    """`docker info` on exactly this endpoint. DOCKER_HOST and DOCKER_CONTEXT are removed from the child
    environment, so --host is the only selector in effect."""
    env = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST", "DOCKER_CONTEXT")}
    try:
        p = subprocess.run(["docker", "--host", endpoint, "info", "--format", "{{json .}}"], capture_output=True, text=True, timeout=60, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("the fixture daemon could not be queried: " + type(exc).__name__)
    if p.returncode != 0:
        raise Refused("the fixture daemon did not answer `docker info`")
    try:
        doc = json.loads(p.stdout)
    except ValueError:
        raise Refused("the fixture daemon returned unreadable identity information")
    if not isinstance(doc, dict):
        raise Refused("the fixture daemon returned unreadable identity information")
    return doc


def verify(endpoint, expect_id=None, expect_name=None):
    """Return the daemon's identity dict when, and only when, it is the declared isolated fixture daemon."""
    path = socket_path(endpoint)
    if not (expect_id or expect_name):
        raise Refused("an expected daemon ID or name is mandatory")
    try:
        is_socket = stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        is_socket = False
    if not is_socket:
        raise Refused("the fixture endpoint is not an existing unix socket")
    if os.path.exists(UNRAID_FILE):
        raise Refused("this is an Unraid host: the harness never runs there")
    doc = _info(endpoint)
    ident = {k: str(doc.get(k) or "") for k in ("ID", "Name", "OperatingSystem", "KernelVersion", "ServerVersion")}
    blob = " ".join(ident[k] for k in ("Name", "OperatingSystem", "KernelVersion")).lower()
    if any(m in blob for m in UNRAID_MARKERS):
        raise Refused("the daemon identifies as an Unraid host: the harness never runs there")
    if not ident["ID"]:
        raise Refused("the daemon reports no ID")
    if expect_id and ident["ID"] != expect_id:
        raise Refused("the daemon ID is not the declared fixture daemon")
    if expect_name and ident["Name"] != expect_name:
        raise Refused("the daemon name is not the declared fixture daemon")
    return ident


def unsafe_ancestors(path):
    """Directories above `path` (and `path` itself when it exists) that the product's storage walk would refuse
    (internal/store/files.go): not owned by root or the invoking user, writable by group or others, or a
    symbolic link. Returns [(directory, reason)]. The harness creates its own state directories 0700 whatever the
    umask, but it cannot repair ancestors its caller made, so it names them up front instead of letting every
    state-dependent check fail one by one."""
    bad = []
    absolute = os.path.abspath(path)
    parts = absolute.strip("/").split("/")
    current = "/"
    for part in [""] + parts:
        current = os.path.join(current, part) if part else "/"
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(st.st_mode):
            bad.append((current, "is a symbolic link"))
        elif st.st_uid not in (0, os.getuid()):
            bad.append((current, "is owned by another user"))
        elif st.st_mode & 0o022:
            bad.append((current, "is group/world-writable (mode %04o)" % (st.st_mode & 0o7777)))
    return bad
