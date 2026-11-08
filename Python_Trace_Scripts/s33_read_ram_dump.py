#!/usr/bin/env python3
"""Validate an AKRDMP1 sequential RAM capture; no incomplete dump is accepted."""
import argparse
import json
from pathlib import Path
import struct
import zlib

MAX_BYTES = 512 * 1024 * 1024


def parse_dump(data):
    if len(data) < 48 or data[:8] != b'AKRDMP1\0':
        raise ValueError('Missing/truncated AKRDMP1 header')
    version, sequence, count, total, start, flags = struct.unpack_from('<6I', data, 8)
    if version != 1 or not 1 <= count <= 16 or total > MAX_BYTES or flags not in (1,3):
        raise ValueError('Unsupported format, range count, flags or size')
    offset, summed, regions, previous_end = 32, 0, [], 0
    for _ in range(count):
        if offset + 12 > len(data):
            raise ValueError('Truncated region header')
        header_offset = offset
        address, length, began = struct.unpack_from('<3I', data, offset)
        offset += 12
        if not length or length > total - summed or address >= 0x0fe00000 or length > 0x0fe00000 - address:
            raise ValueError('Invalid or MMIO region')
        if regions and address < previous_end:
            raise ValueError('Overlapping or unordered RAM regions')
        previous_end = address+length
        end = offset + length
        if end + 8 > len(data):
            raise ValueError('Truncated RAM data/trailer')
        body = data[offset:end]
        finished, crc = struct.unpack_from('<2I', data, end)
        if zlib.crc32(data[header_offset:end+4]) != crc:
            raise ValueError('RAM region CRC mismatch')
        regions.append(dict(address=address, length=length, start_ms=began,
                            end_ms=finished, crc32=crc, data=body))
        summed += length
        offset = end + 8
    if summed != total or len(data) != offset + 16 or data[offset:offset+8] != b'AKRDONE\0':
        raise ValueError('Incomplete capture, unexpected trailing bytes or wrong total')
    completed, finish = struct.unpack_from('<2I', data, offset+8)
    if completed != count:
        raise ValueError('Incomplete region count')
    return dict(version=version, sequence=sequence, total_bytes=total,
                start_ms=start, end_ms=finish, atomic=False, regions=regions,
                coverage='all_declared_ram_banks' if flags&2 else 'selected_regions',
                persistence_proven=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dump', type=Path)
    args = parser.parse_args()
    try:
        result = parse_dump(args.dump.read_bytes())
    except (ValueError, OSError) as exc:
        parser.exit(1, f'Invalid dump: {exc}\n')
    for region in result['regions']:
        del region['data']
        region['address'] = hex(region['address'])
        region['crc32'] = f"{region['crc32']:08x}"
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
