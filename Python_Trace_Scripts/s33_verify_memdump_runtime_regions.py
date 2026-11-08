#!/usr/bin/env python3
"""Compare the camera dump's region table with the existing software-layout model."""
import hashlib
import json
import struct
from pathlib import Path
from s33_verify_nand_pc_ram_regions import reference

ROOT = Path(__file__).resolve().parents[1]
DUMP = ROOT / 'Risultati/Dump_fotocamera/MEMDUMP_20261106/MEMDUMP.BIN'


def main():
    data = DUMP.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert len(data) == 0x104074c and digest == 'c91888b23a8def81dc0afbf5a62a6210361308fea030bfbafcf6a43338286107'
    expected, _, lowest, _, _ = reference()
    rows = [struct.unpack_from('<6I', data, 0x3766f4 + 24 * i) for i in range(len(expected))]
    assert len(rows) == 111
    for index, (actual, model) in enumerate(zip(rows, expected)):
        assert all(actual[field] == model[field] for field in (0, 1, 3, 4, 5)), index
    assert struct.unpack_from('<I', data, 0x441f68 + 12)[0] == len(rows)
    assert struct.unpack_from('<I', data, 0x441f68 + 44)[0] == lowest == 0x1bf9800
    nonzero = [{'index': i, 'id': hex(r[0]), 'state': hex(r[2]), 'base': hex(r[3]), 'size': hex(r[4])}
               for i, r in enumerate(rows) if r[2]]
    assert len(nonzero) == 9 and all(row['state'] == '0x1' for row in nonzero)
    assert all(r[3] >= len(data) for r in rows)
    print(json.dumps({'dump_sha256': digest, 'records': len(rows), 'matching_layout_fields': [0, 1, 3, 4, 5],
                      'minimum_software_base': hex(lowest), 'nonzero_state': nonzero,
                      'limits': 'One non-atomic hardware dump. Software region descriptors are not proof of physical RAM, continuous readability, or distinct banks.'}, indent=2))


if __name__ == '__main__':
    main()
