#!/usr/bin/env python3
"""Controlla strisce mono e riferimento su porzioni del DSCo locale, sola lettura."""
import ctypes
import hashlib
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
from s33_mono_raw_offline import luminance

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'RawsAnalysis/DSCo1012.raw'
SOURCE = ROOT / 'AkeruOS/camera/mono_raw.c'


def sha(path):
    with path.open('rb') as f:
        h = hashlib.sha256()
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
        return h.hexdigest()


def main():
    inputs = {str(p): sha(p) for p in (RAW, SOURCE, Path(__file__))}
    assert RAW.stat().st_size == 4208 * 3152 * 2
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        lib = Path(tmp) / 'mono.so'
        subprocess.run(['cc', '-std=c11', '-O2', '-shared', '-fPIC', str(SOURCE), '-o', str(lib)], check=True)
        dll = ctypes.CDLL(str(lib))
        ptr = ctypes.POINTER(ctypes.c_uint16)
        full, rows = dll.akeru_mono_raw, dll.akeru_mono_raw_rows
        full.argtypes, full.restype = [ptr, ptr, ctypes.c_size_t, ctypes.c_size_t], ctypes.c_int
        rows.argtypes, rows.restype = [ptr, ptr, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t], ctypes.c_int
        frame = np.memmap(RAW, dtype='<u2', mode='r', shape=(3152, 4208))
        for y, x in ((0, 0), (1250, 2000), (3136, 4192)):
            crop = np.ascontiguousarray(frame[y:y+16, x:x+16])
            out = np.empty_like(crop)
            chunks = np.full_like(crop, 65535)
            assert full(crop.ctypes.data_as(ptr), out.ctypes.data_as(ptr), 16, 16) == 0
            for start, n in ((0, 1), (1, 3), (4, 5), (9, 7)):
                assert rows(crop.ctypes.data_as(ptr), chunks[start:].ctypes.data_as(ptr), 16, 16, start, n) == 0
            assert np.array_equal(out, chunks)
            ref = luminance(crop, ('RG', 'GB'), [0]*3, [4092]*3,
                            [[1.75, 0, 0], [0, 1, 0], [0, 0, 1.43]]) * 4092
            error = float(np.max(np.abs(out.astype(float) - ref)))
            assert error < 0.7, (y, x, error)
            cases.append(dict(y=y, x=x, rows=[1, 3, 5, 7], max_error_raw_units=error))
    assert all(sha(Path(p)) == h for p, h in inputs.items())
    outdir = ROOT / 'Risultati/Mono_RAW' / datetime.now(timezone.utc).strftime('rows_real_%Y%m%dT%H%M%S%fZ')
    outdir.mkdir(parents=True)
    (outdir / 'evidence.json').write_text(json.dumps(dict(status='PASS', inputs=inputs, cases=cases,
        limits='Host, ritagli LE16 e CFA RGGB presunti; nessuna acquisizione o buffer camera.'), indent=2)+'\n')
    print('PASS three real crops, four row partitions:', outdir)


if __name__ == '__main__':
    main()
