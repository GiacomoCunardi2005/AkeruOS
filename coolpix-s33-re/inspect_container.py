#!/usr/bin/env python3
"""Read-only structural inspector for Nikon COOLPIX S33 update images.
Does not modify or unpack its input.
"""
from pathlib import Path
from argparse import ArgumentParser
import hashlib
import json
import struct

MARKERS = (b'TBIB_SK501.BIN', b'TBM_SK501.BIN', b'Sunny10-SK501', b'RTOSINIT')


def u32(buf, pos):
    return struct.unpack_from('<I', buf, pos)[0]


def preview(buf, pos, radius=32):
    start = max(0, pos-radius)
    end = min(len(buf), pos+radius)
    return {'start_hex': f'0x{start:X}', 'bytes_hex': buf[start:end].hex(' ')}


def main():
    p = ArgumentParser(description=__doc__)
    p.add_argument('firmware', type=Path)
    p.add_argument('--json', type=Path, default=None, help='Optional JSON report path')
    args = p.parse_args()
    data = args.firmware.read_bytes()
    report = {'file': str(args.firmware), 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    report['markers'] = {}
    for marker in MARKERS:
        positions = []
        start = 0
        while True:
            offset = data.find(marker, start)
            if offset < 0:
                break
            positions.append({'offset_hex': f'0x{offset:X}', 'offset': offset})
            start = offset+1
        report['markers'][marker.decode()] = positions[:50]
    report['candidate_descriptors'] = []
    for offset in (0x60, 0x480AC):
        if offset+12 <= len(data):
            a, b, c = (u32(data, offset+i) for i in (0,4,8))
            report['candidate_descriptors'].append({
                'descriptor_offset': f'0x{offset:X}',
                'start': f'0x{a:X}', 'length': f'0x{b:X}', 'end': f'0x{c:X}',
                'sum_matches': a+b == c,
                'within_file': a <= c <= len(data),
                'start_preview': preview(data, a, 16) if a < len(data) else None,
                'end_preview': preview(data, c, 16) if c < len(data) else None,
            })
    report['boundary_previews'] = {}
    for boundary in (0x4806C, 0x1114AB8):
        if boundary < len(data):
            report['boundary_previews'][f'0x{boundary:X}'] = preview(data, boundary, 32)
    print('Size:', report['size'])
    print('SHA256:', report['sha256'])
    print('\nMarkers:')
    for marker, hits in report['markers'].items():
        print(' ', marker, ', '.join(hit['offset_hex'] for hit in hits) or '(not found)')
    print('\nCandidate descriptors (little-endian):')
    for d in report['candidate_descriptors']:
        print(' ', d['descriptor_offset'], ':', d['start'], '+', d['length'], '=', d['end'],
              'match=', d['sum_matches'], 'within_file=', d['within_file'])
    print('\nBoundary previews:')
    for offset, boundary in report['boundary_previews'].items():
        print(' ', offset, boundary['bytes_hex'])
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print('\nReport:', args.json)


if __name__ == '__main__':
    main()
