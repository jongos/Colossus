"""Synthetic-only benchmark; never inspects an existing project. No third-party modules."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time


def snapshot(root):
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
            for p in root.rglob('*') if p.is_file()}


def run(binary, root):
    with tempfile.TemporaryFile(mode='w+b') as out, tempfile.TemporaryFile(mode='w+b') as err:
        started = time.perf_counter()
        proc = subprocess.Popen([str(binary), 'audit', '--root', str(root), '--format', 'json', '--quiet'], stdout=out, stderr=err)
        peak = 0
        if os.name == 'nt':
            class Counters(ctypes.Structure):
                _fields_ = [('cb', ctypes.c_ulong), ('PageFaultCount', ctypes.c_ulong)] + [(x, ctypes.c_size_t) for x in ['PeakWorkingSetSize', 'WorkingSetSize', 'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage']]
            api = ctypes.WinDLL('psapi').GetProcessMemoryInfo
            api.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
            api.restype = ctypes.c_int
        while proc.poll() is None:
            if os.name == 'nt':
                counters = Counters()
                counters.cb = ctypes.sizeof(counters)
                if api(int(proc._handle), ctypes.byref(counters), counters.cb):
                    peak = max(peak, counters.PeakWorkingSetSize)
            time.sleep(0.01)
        elapsed = time.perf_counter() - started
        err.seek(0)
        if proc.returncode != 0:
            raise RuntimeError(f'Audit incomplete/error {proc.returncode}: {err.read().decode()}')
        out.seek(0)
        report = json.load(out)
        return report, {'elapsed_seconds': elapsed, 'peak_working_set_bytes_sampled': peak or None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--files', type=int, default=10000)
    args = ap.parse_args()
    binary = args.binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='colossus-benchmark-'))
    for i in range(args.files):
        folder = root / f'group-{i//100:04d}'
        folder.mkdir(exist_ok=True)
        (folder / f'file-{i:06d}.txt').write_bytes(b'x' * 1024)
    before = snapshot(root)
    report, timing = run(binary, root)
    preserved = before == snapshot(root)
    assert preserved
    assert report['totals']['logical_bytes'] == args.files * 1024
    result = {'platform': platform.platform(), 'architecture': platform.machine(), 'processor': platform.processor(),
              'logical_cpus': os.cpu_count(), 'workload': {'files': args.files, 'bytes_per_file': 1024, 'directories': (args.files+99)//100},
              'source_preserved_content_and_mtime': preserved, 'complete': report['complete'], 'totals': report['totals'], **timing,
              'limitations': ['Single local run; warm filesystem cache after preservation hashing; not an SSD throughput benchmark.',
                              '10ms peak-working-set sampling can miss brief peaks. No network or unsupported platforms measured.',
                              'Fixture retained in OS temp directory. No destructive cleanup performed.']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
