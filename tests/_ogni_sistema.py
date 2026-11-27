# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""The equivalents the tests use where a system lacks the POSIX function (0.14.1, 27/11/2026: the whole suite on Linux,
macOS and Windows). Each one names what it stands for; where a system has none, the caller skips and says why.

  memory cap of a child   POSIX setrlimit(RLIMIT_AS)  | Windows Job Object ProcessMemoryLimit | macOS: none the kernel
                                                                                                 enforces (RLIMIT_AS
                                                                                                 cannot be lowered)
  process-count cap       RLIMIT_NPROC                | Windows Job Object ActiveProcessLimit
  CPU time of a child     /proc/<pid>/stat (Linux)    | macOS `ps -o time=` | Windows GetProcessTimes
  non-blocking pipe       fcntl O_NONBLOCK            | os.set_blocking (Windows pipes from 3.12) | before 3.12 on Windows
                                                                         SetNamedPipeHandleState(PIPE_NOWAIT), which
                                                                         is what os.set_blocking calls
  a device that is full   /dev/full (Linux)           | a filled volume named by OE_FULL_DIR (CI: an HFS+ RAM disk on
                                                        macOS, a FAT VHD on Windows)
  FIFO                    os.mkfifo                   | Windows named pipe \\\\.\\pipe\\<name>
"""
import os
import subprocess
import sys
import time

WINDOWS = os.name == "nt"
MACOS = sys.platform == "darwin"

if WINDOWS:
    import ctypes
    from ctypes import wintypes

    class _IO(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rt", "wt", "ot")]

    class _BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

    class _EXT(ctypes.Structure):
        _fields_ = [("Basic", _BASIC), ("Io", _IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(ctypes.c_ulonglong)] * 4
    _k32.SetNamedPipeHandleState.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
                                             ctypes.c_void_p]
    _ntdll = ctypes.WinDLL("ntdll")
    _ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]

    def win_job(memory=None, processes=None):
        """a Job Object with a per-process memory limit and/or a cap on the processes alive in it"""
        job = _k32.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())
        info = _EXT()
        if memory is not None:
            info.Basic.LimitFlags |= 0x100          # JOB_OBJECT_LIMIT_PROCESS_MEMORY
            info.ProcessMemoryLimit = memory
        if processes is not None:
            info.Basic.LimitFlags |= 0x8            # JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            info.Basic.ActiveProcessLimit = processes
        if not _k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):   # ExtendedLimitInformation
            raise ctypes.WinError(ctypes.get_last_error())
        return job

    def win_assign(job, handle):
        if not _k32.AssignProcessToJobObject(job, handle):
            raise ctypes.WinError(ctypes.get_last_error())


def limit_self_processes():
    """this process may start no other: RLIMIT_NPROC = 1 on POSIX, a Job Object of one process on Windows"""
    if WINDOWS:
        win_assign(win_job(processes=1), _k32.GetCurrentProcess())
    else:
        import resource
        resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))


def run_capped(argv, memory, timeout, **kw):
    """subprocess.run(argv) with the child's memory capped where the system can cap it (see the table above)"""
    if WINDOWS:
        p = subprocess.Popen(argv, creationflags=0x4, **{k: v for k, v in kw.items() if k not in ("capture_output",)},
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)   # CREATE_SUSPENDED: capped before it runs
        try:
            win_assign(win_job(memory=memory), int(p._handle))
        finally:
            _ntdll.NtResumeProcess(int(p._handle))
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            raise
        return subprocess.CompletedProcess(argv, p.returncode, out, err)

    def cap():
        import resource
        try:
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        except (ValueError, OSError):
            if not MACOS:                            # macOS refuses to lower RLIMIT_AS: nothing else caps it there
                raise
    return subprocess.run(argv, preexec_fn=cap, timeout=timeout, **kw)


def cpu_seconds(p):
    """user + system CPU seconds of the live process p (a Popen)"""
    if WINDOWS:
        c, e, k, u = (ctypes.c_ulonglong() for _ in range(4))
        if not _k32.GetProcessTimes(int(p._handle), ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            raise OSError("GetProcessTimes failed")
        return (k.value + u.value) / 1e7
    if MACOS:
        out = subprocess.run(["ps", "-o", "time=", "-p", str(p.pid)], capture_output=True, text=True).stdout.strip()
        if not out:
            raise OSError("process gone")
        secs = 0.0
        for part in out.replace("-", ":").split(":"):   # [[dd-]hh:]mm:ss.ss
            secs = secs * 60 + float(part)
        return secs
    with open(f"/proc/{p.pid}/stat", "rb") as f:
        fields = f.read().rsplit(b")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def set_nonblocking(fd):
    if WINDOWS and sys.version_info < (3, 12):
        import msvcrt
        mode = wintypes.DWORD(1)                     # PIPE_NOWAIT
        if not _k32.SetNamedPipeHandleState(msvcrt.get_osfhandle(fd), ctypes.byref(mode), None, None):
            raise ctypes.WinError(ctypes.get_last_error())
        return
    os.set_blocking(fd, False)


def full_file():
    """a path whose writes fail with ENOSPC, or None: /dev/full, else a new file on the filled volume OE_FULL_DIR"""
    if os.path.exists("/dev/full"):
        return "/dev/full"
    d = os.environ.get("OE_FULL_DIR")
    if d and os.path.isdir(d):
        return os.path.join(d, "out-%d-%d" % (os.getpid(), time.monotonic_ns()))
    return None


FULL_WHY = "no /dev/full and no filled volume in OE_FULL_DIR (the CI makes one on macOS and Windows)"


def win_pipe_server(name):
    """a named pipe \\\\.\\pipe\\<name> that is listening, the Windows equivalent of a FIFO: returns (path, closer)"""
    from multiprocessing.connection import Listener
    path = "\\\\.\\pipe\\" + name
    lst = Listener(path, family="AF_PIPE")
    return path, lst.close
