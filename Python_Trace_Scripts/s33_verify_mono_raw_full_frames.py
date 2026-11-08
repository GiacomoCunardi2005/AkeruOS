#!/usr/bin/env python3
"""Compare host C luminance with the saved float reference on complete RAWs."""
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import numpy as np
from PIL import Image

root = Path(__file__).resolve().parent.parent
sources = [root / 'AkeruOS/camera' / x for x in ('mono_raw.c', 'color_mode.c')]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
output = root / 'outputs' / ('mono_raw_c_full_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
output.mkdir(parents=True, exist_ok=False)
results = []
with tempfile.TemporaryDirectory() as tmp:
    lib = Path(tmp) / 'mono.so'
    subprocess.run(['cc', '-std=c11', '-O2', '-shared', '-fPIC', *map(str, sources), '-o', str(lib)], check=True)
    fn = ctypes.CDLL(str(lib)).akeru_color_process
    ptr = ctypes.POINTER(ctypes.c_uint16)
    fn.argtypes = [ctypes.c_int, ptr, ptr, ctypes.c_size_t, ctypes.c_size_t]
    fn.restype = ctypes.c_int
    for number in (1003, 1012):
        raw = root / 'RawsAnalysis' / f'DSCo{number}.raw'
        refdir = root / 'outputs/mono_raw_20261029' / f'DSCo{number}'
        refimage = refdir / 'luminanza_lineare_float32.tiff'
        reference_jpeg = refdir / 'mono_sperimentale.jpg'
        inputs = [raw, refimage, reference_jpeg, refdir / 'report.json', *sources, Path(__file__)]
        hashes = {str(p.relative_to(root)): sha(p) for p in inputs}
        params = json.loads((refdir / 'report.json').read_text())
        assert hashes[str(raw.relative_to(root))] == params['sha256_raw']
        assert raw.stat().st_size == 3152 * 4208 * 2
        a = np.memmap(raw, dtype='<u2', mode='r', shape=(3152, 4208))
        out = np.empty(a.shape, dtype=np.uint16)
        assert fn(1, a.ctypes.data_as(ptr), out.ctypes.data_as(ptr), 4208, 3152) == 1
        ref = np.asarray(Image.open(refimage))
        assert ref.shape == a.shape and np.isfinite(ref).all()
        delta = np.abs(out.astype(np.float64) - ref.astype(np.float64) * 4092)
        maximum, mean = float(delta.max()), float(delta.mean())
        assert maximum < 0.7, (number, maximum)
        del delta, ref
        lo, hi = params['tone_limits']
        x = np.clip((out.astype(np.float64) / 4092 - lo) / (hi - lo), 0, 1)
        x += .16 * x * (1 - x) ** 2
        encoded = np.where(x <= .0031308, 12.92 * x, 1.055 * x ** (1 / 2.4) - .055)
        jpeg = output / f'DSCo{number}_mono_C.jpg'
        Image.fromarray(np.uint8(np.round(np.clip(encoded, 0, 1) * 255))).save(jpeg, quality=98)
        decoded = np.asarray(Image.open(jpeg), dtype=np.int16)
        original = np.asarray(Image.open(reference_jpeg), dtype=np.int16)
        jpeg_delta = np.abs(decoded - original)
        assert all(sha(root / p) == h for p, h in hashes.items())
        results.append({'raw': raw.name, 'pixels_compared': int(out.size), 'max_error_raw_units': maximum,
                        'mean_error_raw_units': mean, 'jpeg_decoded_max_difference': int(jpeg_delta.max()),
                        'jpeg_decoded_mean_difference': float(jpeg_delta.mean()), 'tone_limits': [lo, hi],
                        'jpeg_sha256': sha(jpeg), 'input_sha256': hashes})
        print(raw.name, 'PASS', maximum, flush=True)
(output / 'report.json').write_text(json.dumps({'status': 'PASS_HOST_FULL_FRAMES', 'results': results}, indent=2) + '\n')
print(output)
