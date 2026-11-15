"""Footprint measurement helpers of the P1.20 release acceptance (standard library only).

Budgets are technical-decisions.md §10.2 and are numbers, not adjectives:
  image   <= 60 MB compressed
  idle    <= 50 MB RSS  (after startup, SQLite initialized, 1 local Docker endpoint connected)
  load    <= 150 MB RSS (20 concurrent API/MCP clients polling status/logs + 5 active log streams)
A megabyte is applied as 10^6 bytes, the smaller and therefore stricter reading (1 MiB = 1048576 bytes would
admit about 5% more). Every report states the raw byte count and both units so the choice cannot hide a failure.
The image figure is the sum of the real gzip-compressed OCI blobs (layers + config + manifest).
"""
import json
import os
import statistics
import tarfile

MB = 1000 * 1000
MIB = 1024 * 1024
BUDGET_IMAGE_BYTES = 60 * MB
BUDGET_IDLE_RSS_BYTES = 50 * MB
BUDGET_LOAD_RSS_BYTES = 150 * MB


def within(measured, budget):
    """A budget passes only for a real, positive measurement not above the limit. A missing or zero reading
    (a failed measurement) is never a pass."""
    return isinstance(measured, (int, float)) and not isinstance(measured, bool) and 0 < measured <= budget


def units(n):
    return {"bytes": n, "MB": round(n / MB, 2), "MiB": round(n / MIB, 2)}


def parse_status(text):
    """/proc/<pid>/status -> {name: bytes} for the memory fields (reported in kB = KiB)."""
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition(":")
        if k in ("VmRSS", "VmHWM", "RssAnon", "RssFile", "RssShmem", "VmSize", "VmData", "VmSwap"):
            parts = v.split()
            if parts and parts[0].isdigit():
                out[k] = int(parts[0]) * 1024
    return out


def read_status(pid):
    with open("/proc/%d/status" % pid) as fh:
        return parse_status(fh.read())


def cgroup_dir(pid):
    """The cgroup v2 directory of a process, or None (cgroup v1 or an unreadable file: reported, never guessed)."""
    try:
        with open("/proc/%d/cgroup" % pid) as fh:
            for line in fh:
                if line.startswith("0::"):
                    d = "/sys/fs/cgroup" + line.strip()[3:]
                    return d if os.path.isdir(d) else None
    except OSError:
        return None
    return None


def cgroup_memory(pid):
    d = cgroup_dir(pid)
    out = {}
    if not d:
        return out
    for name in ("memory.current", "memory.peak", "memory.max"):
        try:
            with open(os.path.join(d, name)) as fh:
                v = fh.read().strip()
            out[name] = int(v) if v.isdigit() else v
        except OSError:
            pass
    return out


def percentile(sorted_values, p):
    """Nearest-rank percentile of an ascending list (p in 0..1); 0 for an empty list."""
    if not sorted_values:
        return 0.0
    i = max(0, min(len(sorted_values) - 1, int(round(p * (len(sorted_values) - 1)))))
    return float(sorted_values[i])


def latency_summary(ms):
    v = sorted(ms)
    return {"n": len(v), "p50_ms": round(percentile(v, 0.5), 3), "p95_ms": round(percentile(v, 0.95), 3), "p99_ms": round(percentile(v, 0.99), 3),
            "mean_ms": round(statistics.fmean(v), 3) if v else 0.0}


def oci_compressed_size(oci_tar):
    """Sum of the sizes of every blob an OCI archive's image manifest references (layers, config) plus the
    manifest itself: the bytes a registry stores for one platform image. Returns (total, layers)."""
    with tarfile.open(oci_tar) as t:
        index = json.load(t.extractfile("index.json"))
        total, layers = 0, []

        def blob(digest):
            return t.extractfile("blobs/sha256/" + digest.split(":", 1)[1]).read()

        def walk(desc):
            nonlocal total
            mt = desc.get("mediaType", "")
            raw = blob(desc["digest"])
            if "index" in mt or "manifest.list" in mt:
                for m in json.loads(raw)["manifests"]:
                    if m.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
                        continue  # provenance/SBOM attestations are not the runtime image
                    walk(m)
                return
            total += len(raw)
            man = json.loads(raw)
            total += man["config"]["size"]
            for layer in man["layers"]:
                total += layer["size"]
                layers.append({"digest": layer["digest"], "size": layer["size"], "mediaType": layer["mediaType"]})

        for d in index["manifests"]:
            walk(d)
    return total, layers


def reset_peak(pid):
    """Reset the kernel's peak-RSS (VmHWM) of a process so the next reading is the peak of the window that follows.
    Needs write access to /proc/<pid>/clear_refs (the process owner); returns False when that is not permitted, in which
    case the caller must say that VmHWM covers the whole process lifetime."""
    try:
        with open("/proc/%d/clear_refs" % pid, "w") as fh:
            fh.write("5")
        return True
    except OSError:
        return False


def fsync_latency(directory, n=200):
    """Latency of write(4 KiB) + fsync on the filesystem that holds the data directories: the floor under every
    synchronous durable commit (usage accounting, security-control writes) on this host. Returns a latency summary."""
    path = os.path.join(directory, ".fsync-probe-%d" % os.getpid())
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
    import time
    ms = []
    try:
        for _ in range(n):
            os.pwrite(fd, b"x" * 4096, 0)
            t0 = time.perf_counter()
            os.fsync(fd)
            ms.append((time.perf_counter() - t0) * 1000)
    finally:
        os.close(fd)
        os.unlink(path)
    return latency_summary(ms)
