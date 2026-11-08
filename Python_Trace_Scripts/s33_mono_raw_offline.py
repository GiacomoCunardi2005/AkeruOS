#!/usr/bin/env python3
"""Experimental offline Mono RAW Luminance; calibration must be supplied explicitly."""
import argparse
import hashlib
import json
from pathlib import Path

import cv2
import numpy as np
from PIL import Image

WEIGHTS = np.array([0.2126, 0.7152, 0.0722], dtype=np.float64)


def luminance(samples, pattern, black, white, matrix):
    """Vectorized equivalent of s33_mono_reference.luminance, including borders."""
    a = np.asarray(samples)
    tile = np.asarray([list(row) for row in pattern])
    black, white, matrix = (np.asarray(x, dtype=np.float64) for x in (black, white, matrix))
    if a.ndim != 2 or min(a.shape) < 2 or not np.issubdtype(a.dtype, np.number) or not np.isfinite(a).all():
        raise ValueError('samples must be a finite numeric 2D array at least 2x2')
    if tile.shape != (2, 2) or sorted(tile.ravel()) != ['B', 'G', 'G', 'R'] or ((tile[0, 0] == 'G') != (tile[1, 1] == 'G')):
        raise ValueError('invalid Bayer tile')
    if black.shape != (3,) or white.shape != (3,) or matrix.shape != (3, 3) or not all(np.isfinite(x).all() for x in (black, white, matrix)) or np.any(white <= black):
        raise ValueError('invalid calibration')
    coeff = WEIGHTS @ matrix
    result = np.zeros(a.shape, dtype=np.float64)
    kernel = np.ones((3, 3), dtype=np.float64)
    for i, color in enumerate('RGB'):
        mask = np.zeros(a.shape, dtype=np.float64)
        for y in range(2):
            for x in range(2):
                if tile[y, x] == color:
                    mask[y::2, x::2] = 1
        values = (a.astype(np.float64) - black[i]) / (white[i] - black[i]) * mask
        total = cv2.filter2D(values, -1, kernel, borderType=cv2.BORDER_CONSTANT)
        count = cv2.filter2D(mask, -1, kernel, borderType=cv2.BORDER_CONSTANT)
        result += coeff[i] * np.where(mask != 0, values, total / np.maximum(count, 1))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('raw', type=Path)
    parser.add_argument('output', type=Path, help='new output directory')
    args = parser.parse_args()
    data = args.raw.read_bytes()
    if len(data) != 4208 * 3152 * 2:
        raise ValueError('expected a complete 4208 x 3152 LE16 DSCo raster')
    # Provisional settings reproduce the project experiments; they are not sensor calibration.
    pattern = ('RG', 'GB')
    black, white = [0, 0, 0], [4092, 4092, 4092]
    matrix = [[1.75, 0, 0], [0, 1, 0], [0, 0, 1.43]]
    y = luminance(np.frombuffer(data, dtype='<u2').reshape(3152, 4208), pattern, black, white, matrix)
    lo, hi = np.percentile(y[::8, ::8], [0.1, 99.8])
    if not np.isfinite(y).all() or hi <= lo:
        raise ValueError('invalid or flat luminance')
    x = np.clip((y - lo) / (hi - lo), 0, 1)
    x = x + .16 * x * (1 - x) ** 2
    encoded = np.where(x <= .0031308, 12.92*x, 1.055*x**(1/2.4)-.055)
    args.output.mkdir(parents=True, exist_ok=False)
    Image.fromarray(y.astype(np.float32)).save(args.output/'luminanza_lineare_float32.tiff')
    Image.fromarray(np.uint8(np.round(np.clip(encoded, 0, 1)*255))).save(args.output/'mono_sperimentale.jpg', quality=98)
    info = {'source': str(args.raw.resolve()), 'sha256_raw': hashlib.sha256(data).hexdigest(),
            'shape': [3152, 4208], 'pattern_assumed': pattern, 'black_assumed': black,
            'white_assumed': white, 'matrix_assumed': matrix, 'tone_percentiles': [.1, 99.8],
            'tone_limits': [float(lo), float(hi)], 'shadows': .16, 'jpeg_quality': 98,
            'limitations': ['No measured sensor calibration; matrix is a provisional gain, not a sensor-to-sRGB profile.',
                            'Offline processing; physical CFA remains; no firmware or camera execution.']}
    (args.output/'report.json').write_text(json.dumps(info, indent=2)+'\n')
    print('Output:', args.output)


if __name__ == '__main__':
    main()
