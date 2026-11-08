#!/usr/bin/env python3
"""Compare the SD update with the local MSDC candidate; never write to SD."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = 'af65ab0e66781c1a1036ab2349700e9d2110c6618738b02208da8b83c8813544'
LOCAL = ROOT / 'Risultati/Firmware_sperimentali/USB_MSDC_Default/S33_USB_MSDC_DEFAULT_OFFLINE_NON_INSTALLARE.bin'


def inspect(path):
    before = path.stat()
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ), f'File changed during reading: {path}'
    return {'path': str(path), 'size': after.st_size, 'sha256': digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sd-file', type=Path, default=Path('/run/media/jack/disk/firmware/firmware.bin'))
    args = parser.parse_args()
    local = inspect(LOCAL)
    assert local['size'] == 29602084 and local['sha256'] == EXPECTED
    sd = inspect(args.sd_file)
    match = (sd['size'], sd['sha256']) == (local['size'], local['sha256'])
    result = {'utc': datetime.now(timezone.utc).isoformat(), 'sd': sd, 'local': local,
              'match': match, 'status': 'MATCH' if match else 'MISMATCH',
              'scope': 'Read-only file hashes; no camera flash/runtime readback or SD writes.'}
    print(json.dumps(result, indent=2))
    return 0 if match else 1


if __name__ == '__main__':
    raise SystemExit(main())
