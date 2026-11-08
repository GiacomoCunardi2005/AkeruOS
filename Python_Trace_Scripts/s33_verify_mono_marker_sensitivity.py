#!/usr/bin/env python3
"""Measure sensitivity of the experimental C mono output to candidate marker bits."""
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import numpy as np

root = Path(__file__).resolve().parent.parent
source = root / 'AkeruOS/camera/mono_raw.c'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
outdir = root / 'outputs' / datetime.now(timezone.utc).strftime('mono_marker_sensitivity_%Y%m%dT%H%M%SZ')
outdir.mkdir(parents=True, exist_ok=False)
offsets = np.arange(32, dtype=np.int64) * 8416 + 13263616
assert np.all(offsets % 2 == 0) and offsets[-1] < 4208 * 3152 * 2
rows = []
with tempfile.TemporaryDirectory() as tmp:
    lib = Path(tmp) / 'mono.so'
    subprocess.run(['cc', '-std=c11', '-O2', '-shared', '-fPIC', str(source), '-o', str(lib)], check=True)
    fn = ctypes.CDLL(str(lib)).akeru_mono_raw
    ptr = ctypes.POINTER(ctypes.c_uint16)
    fn.argtypes = [ptr, ptr, ctypes.c_size_t, ctypes.c_size_t]
    fn.restype = ctypes.c_int
    source_hash, script_hash = sha(source), sha(Path(__file__))
    for number in range(1003, 1013):
        path = root / 'RawsAnalysis' / f'DSCo{number}.raw'
        before = sha(path)
        assert path.stat().st_size == 4208 * 3152 * 2
        raw = np.fromfile(path, dtype='<u2').reshape(3152, 4208)
        assert ''.join(str(int(v & 1)) for v in raw.ravel()[offsets // 2]) == '10011001101010101001100110101010'
        changed = raw.copy()
        changed.ravel()[offsets // 2] ^= 1
        a, b = np.empty_like(raw), np.empty_like(raw)
        for inp, dest in ((raw, a), (changed, b)):
            assert fn(inp.ctypes.data_as(ptr), dest.ctypes.data_as(ptr), 4208, 3152) == 0
        y, x = np.nonzero(a != b)
        difference = np.abs(a[y, x].astype(np.int32) - b[y, x].astype(np.int32))
        marker_y, marker_x = np.divmod(offsets // 2, 4208)
        assert all(np.any((abs(marker_y - yy) <= 1) & (abs(marker_x - xx) <= 1)) for yy, xx in zip(y, x))
        assert len(y) <= 32 * 9 and (not len(y) or difference.max() <= 1)
        assert sha(path) == before
        rows.append({'raw': path.name, 'sha256': before, 'changed_input_samples': 32,
                     'changed_output_pixels': int(len(y)), 'max_difference_raw_units': int(difference.max()) if len(y) else 0,
                     'output_positions_yx': np.column_stack((y, x)).tolist()})
        print(path.name, len(y), flush=True)
assert sha(source) == source_hash and sha(Path(__file__)) == script_hash
(outdir / 'report.json').write_text(json.dumps({'status': 'PASS_HOST_MARKER_INVERSION',
    'input_marker_offsets_bytes': offsets.tolist(), 'source_sha256': source_hash,
    'script_sha256': script_hash, 'results': rows}, indent=2) + '\n')
print(outdir)
