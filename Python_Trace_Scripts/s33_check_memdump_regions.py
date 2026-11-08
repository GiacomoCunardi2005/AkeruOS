#!/usr/bin/env python3
"""Read-only verification of v8-style files against an explicitly supplied map."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def check(directory, regions):
    if not isinstance(regions, list) or not 1 <= len(regions) <= 16:
        raise ValueError('la mappa deve contenere da 1 a 16 regioni')
    expected = {}
    end = 0
    for i, region in enumerate(regions):
        if not isinstance(region, dict) or set(region) != {'address', 'length'}:
            raise ValueError('ogni regione deve avere soltanto address e length')
        base, size = region['address'], region['length']
        if type(base) is not int or type(size) is not int or base < 0 or size <= 0 or base >= 0x0fe00000 or size > 0x0fe00000 - base or (i and base < end):
            raise ValueError('intervallo vuoto, sovrapposto, non ordinato o fuori limite')
        expected[f'{base:08X}.BIN'] = size
        end = base + size
    found = {}
    for entry in directory.iterdir():
        name = entry.name.upper()
        if re.fullmatch(r'[0-9A-F]{8}\.BIN', name):
            if name in found:
                raise ValueError(f'nome duplicato ignorando maiuscole: {name}')
            found[name] = entry
    results = []
    for name, size in expected.items():
        entry = found.get(name)
        if entry is None:
            results.append({'file': name, 'expected_bytes': size + 256, 'status': 'missing'})
        elif entry.is_symlink() or not entry.is_file():
            results.append({'file': name, 'expected_bytes': size + 256, 'status': 'not_regular'})
        else:
            with entry.open('rb') as stream:
                digest = hashlib.sha256(); actual = 0
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk); actual += len(chunk)
            results.append({'file': name, 'expected_bytes': size + 256, 'actual_bytes': actual,
                            'sha256': digest.hexdigest(), 'status': 'size_matches' if actual == size + 256 else 'size_mismatch'})
    unexpected = sorted(found.keys() - expected.keys())
    ok = not unexpected and all(r['status'] == 'size_matches' for r in results)
    return {'status': 'FILES_MATCH_DECLARED_MAP_ONLY' if ok else 'INCOMPLETE_OR_UNEXPECTED',
            'files': results, 'unexpected': unexpected,
            'limits': 'Size and SHA-256 do not prove the physical map, capture origin, close success, persistence or atomicity.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('map', type=Path, help='JSON array of integer address/length objects')
    parser.add_argument('directory', type=Path, help='directory containing copied dump files')
    args = parser.parse_args()
    try:
        result = check(args.directory, json.loads(args.map.read_text()))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'FILES_MATCH_DECLARED_MAP_ONLY' else 1


if __name__ == '__main__':
    sys.exit(main())
