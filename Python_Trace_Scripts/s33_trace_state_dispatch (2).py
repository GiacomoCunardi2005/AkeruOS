#!/usr/bin/env python3
"""Static-only S33 V1.1 analysis of CaptureImage state-byte and dispatcher candidates.

Reads original verified TBM payloads from the user's project and performs GNU ARC
linear disassembly. Does NOT invoke PTP, run firmware, write TBM files or flash.
Outputs narrowly-scoped JSON, Markdown and disassembly windows for manual CFG review.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

STATE_BASE = 0x681FF0
STATE_BYTE = 0x68200D
HANDLER = 0x65ED6C
REG_ADDR = 0x783D9C
NAME_ADDR = 0x783E0C
MARKER_LITERALS = {0x65F474: 0xB80022, 0x65F480: 0xB80023,
                   0x65FDEC: 0xB80022, 0x65FDF0: 0xB80023}
EXPECTED_LITERAL_ADDRESSES = {STATE_BASE: [0x65F0EC, 0x65F5FC, 0x65FE74,
    0x66043C, 0x6608A8, 0x6609A4, 0x660BEC, 0x660EC4, 0x661644,
    0x661770, 0x662008, 0x66254C, 0x662934, 0x662BE8],
    STATE_BYTE: [0x65ED64, 0x660F80]}
HEX_REF = re.compile(r';0x([0-9a-fA-F]+)\s*$')
ADDR = re.compile(r'^\s*([0-9a-fA-F]+):\s+')
LOADED_REGISTER = re.compile(r'\t(?:ld_s|ld)\s+(r\d+),\[pcl,')
MEM_WRITE = re.compile(r'\t(stb_s|stb|st_s|st)\s+[^,]+,\[(r\d+)(?:,\s*(0x[0-9a-fA-F]+|\d+))?\]')
DIS_BLOCKS = {0, 1, 2, 3}  # Restricted first pass; not all code/data blocks.


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def he(n: int) -> str:
    return f'0x{n:x}'


def run(args: list[Path | str], timeout: int = 180) -> str:
    return subprocess.run([str(a) for a in args], check=True,
        capture_output=True, text=True, timeout=timeout).stdout


def verified_payloads(project: Path) -> tuple[list[dict], dict[int, bytes], Path]:
    block_dir = (project / 'S33-sections' / 'TBM_blocks').resolve()
    manifest_path = block_dir / 'manifest.json'
    blocks = json.loads(manifest_path.read_text())
    valid = [b for b in blocks if b.get('within_file')]
    if len(valid) != 16 or len({b['index'] for b in valid}) != 16:
        raise ValueError('Manifest: expected exactly 16 distinct valid TBM blocks')
    payloads: dict[int, bytes] = {}
    for b in valid:
        src = (block_dir / b['file']).resolve()
        if not src.is_relative_to(block_dir) or not src.is_file():
            raise ValueError(f'Unsafe or missing block source: {src}')
        data = src.read_bytes()
        if len(data) != b['size'] or sha(data) != b['sha256']:
            raise ValueError(f'Size/SHA mismatch in block {b["index"]}')
        payloads[b['index']] = data
    info = {b['index']: b for b in valid}
    if info[2]['load_address_candidate'] != 0x5FE800 or info[3]['load_address_candidate'] != 0x669800:
        raise ValueError('Unexpected block bases: likely a different firmware')

    def u32(index: int, address: int) -> int:
        b = info[index]
        ofs = address - b['load_address_candidate']
        if not 0 <= ofs <= len(payloads[index]) - 4:
            raise ValueError(f'Out-of-bounds read: block {index} address {he(address)}')
        return struct.unpack_from('<I', payloads[index], ofs)[0]

    for value, addresses in EXPECTED_LITERAL_ADDRESSES.items():
        for addr in addresses:
            if u32(2, addr) != value:
                raise ValueError(f'Unexpected state literal at {he(addr)}')
    for addr, value in MARKER_LITERALS.items():
        if u32(2, addr) != value:
            raise ValueError(f'Marker literal mismatch at {he(addr)}')
    if [u32(3, REG_ADDR + i * 4) for i in range(3)] != [0x4405, HANDLER, 0x4406]:
        raise ValueError('CaptureImage registration mismatch')
    name_ofs = NAME_ADDR - info[3]['load_address_candidate']
    if payloads[3][name_ofs: name_ofs + 13] != b'CaptureImage\x00':
        raise ValueError('CaptureImage name does not match')
    return valid, payloads, block_dir


def objdump_text(project: Path, block_dir: Path, b: dict, payload: bytes) -> str:
    objcopy = project / 'work' / 'build-arc' / 'binutils' / 'objcopy'
    objdump = project / 'work' / 'build-arc' / 'binutils' / 'objdump'
    if not objcopy.is_file() or not objdump.is_file():
        raise FileNotFoundError(f'ARC toolchain missing: {objcopy}, {objdump}')
    with tempfile.TemporaryDirectory(prefix='s33-state-dispatch-') as td:
        elf = Path(td) / f'block_{b["index"]}.elf'
        bin_again = Path(td) / f'block_{b["index"]}.bin'
        run([objcopy, '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
             '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
             '--change-section-vma', f'.data={b["load_address_candidate"]:#x}',
             '--strip-all', block_dir / b['file'], elf])
        run([objcopy, '--dump-section', f'.text={bin_again}', elf])
        if bin_again.read_bytes() != payload:
            raise ValueError(f'ELF roundtrip differs: block {b["index"]}')
        text = run([objdump, '-d', '-m', 'arc:ARC700', '-EL', elf])
        if 'out of bounds' in text.lower():
            raise ValueError(f'Objdump reported OOB in block {b["index"]}')
        return text


def parse_listing(text: str) -> tuple[list[int], list[str]]:
    addresses, lines = [], []
    for line in text.splitlines():
        m = ADDR.match(line)
        if m:
            addresses.append(int(m.group(1), 16))
            lines.append(line)
    if addresses != sorted(addresses):
        raise ValueError('Nonmonotonic disassembly output; cannot create windows safely')
    return addresses, lines


def window(addresses: list[int], lines: list[str], center: int,
           before: int = 96, after: int = 160) -> str:
    i = bisect.bisect_left(addresses, center - before)
    j = bisect.bisect_left(addresses, center + after)
    return '\n'.join(lines[i:j])


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project-root', type=Path, required=True)
    p.add_argument('--output-dir', type=Path, required=True)
    a = p.parse_args()
    root = a.project_root.expanduser().resolve()
    output = a.output_dir.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    blocks, payloads, block_dir = verified_payloads(root)

    result = {
        'analysis': 'STATIC candidate xrefs to CaptureImage state, not a recovered S2 path',
        'firmware_reference': 'Nikon S33 V1.1; camera observed V1.0; offsets not portable without proof',
        'verified_blocks': 16, 'disassembled_blocks': sorted(DIS_BLOCKS),
        'state_byte': he(STATE_BYTE), 'capture_handler': he(HANDLER),
        'state_literals_checked': {he(v): [he(x) for x in sites]
                                   for v, sites in EXPECTED_LITERAL_ADDRESSES.items()},
        'pc_relative_refs': [], 'candidate_stores': [], 'service_id_literal_refs': [],
        'raw_service_registration_window': [], 'limits': [
            'All raw ID occurrences and PC literal loads are candidates, not proven code xrefs.',
            'A load-to-store proximity check does not track register clobbering or aliasing.',
            'ARC objdump is linear and can disassemble data as code. Review CFG manually.',
            'No firmware or camera commands were executed or modified.'
        ]
    }
    by_index = {b['index']: b for b in blocks}
    id_word_sites: dict[int, set[int]] = {}
    for block_id in DIS_BLOCKS:
        b = by_index[block_id]
        data = payloads[block_id]
        base = b['load_address_candidate']
        sites = set()
        needle = struct.pack('<I', 0x4405)
        offset = data.find(needle)
        while offset >= 0:
            if (base + offset) % 4 == 0:
                sites.add(base + offset)
            offset = data.find(needle, offset + 1)
        id_word_sites[block_id] = sites

    details: list[str] = ['# S33 — windows of state-byte and dispatcher candidates',
                          '# All offsets correspond to V1.1 and are static candidates only.', '']
    visited: set[tuple[int, int]] = set()
    for block_id in sorted(DIS_BLOCKS):
        b = by_index[block_id]
        listing = objdump_text(root, block_dir, b, payloads[block_id])
        addresses, lines = parse_listing(listing)
        known = {a for arr in EXPECTED_LITERAL_ADDRESSES.values() for a in arr} if block_id == 2 else set()
        for i, (site, line) in enumerate(zip(addresses, lines)):
            ref_match = HEX_REF.search(line)
            if not ref_match:
                continue
            reference = int(ref_match.group(1), 16)
            if reference not in known and reference not in id_word_sites[block_id]:
                continue
            m = LOADED_REGISTER.search(line)
            if not m:
                continue
            register = m.group(1)
            is_state = reference in known
            row = {'block': block_id, 'site': he(site), 'literal': he(reference),
                   'register': register, 'instruction': line.strip()}
            if is_state:
                value = STATE_BYTE if reference in EXPECTED_LITERAL_ADDRESSES[STATE_BYTE] else STATE_BASE
                row['literal_value'] = he(value)
                result['pc_relative_refs'].append(row)
                # Deliberately *candidate only*: no CFG, aliases or clobber checking.
                for future_site, future_line in zip(addresses[i + 1:], lines[i + 1:]):
                    if future_site > site + 160:
                        break
                    w = MEM_WRITE.search(future_line)
                    if w and w.group(2) == register:
                        offset = int(w.group(3), 0) if w.group(3) else 0
                        if offset == (0 if value == STATE_BYTE else 0x1D):
                            result['candidate_stores'].append({**row,
                                'store_site': he(future_site), 'store_instruction': future_line.strip(),
                                'warning': 'Proximity, not proven data flow'})
            else:
                result['service_id_literal_refs'].append(row)
            if (block_id, site) not in visited:
                visited.add((block_id, site))
                details.append(f'====== block {block_id} site {he(site)} literal {he(reference)} ======')
                details.append(window(addresses, lines, site, 96, 192))
                details.append('')
        # Independently show contexts near known state-byte literal locations even if no PC xref.
        if block_id == 2:
            for address in (0x65ED64, 0x660F80):
                details.extend([f'====== raw literal around {he(address)} ======',
                     window(addresses, lines, address, 64, 96), ''])

    b3 = by_index[3]
    p3 = payloads[3]
    for addr in range(REG_ADDR - 0x28, REG_ADDR + 0x60, 4):
        offset = addr - b3['load_address_candidate']
        if 0 <= offset <= len(p3) - 4:
            w = struct.unpack_from('<I', p3, offset)[0]
            result['raw_service_registration_window'].append({'address': he(addr), 'raw_le_word': he(w)})

    out_json = output / 's33_state_dispatch_candidates.json'
    (root / 'MDs').mkdir(parents=True, exist_ok=True)
    out_md = root / 'MDs' / 's33_state_dispatch_candidates.md'
    out_txt = output / 's33_state_dispatch_candidates_disassembly.txt'
    report = ['# S33 — CaptureImage state/dispatch candidates', '',
              'Firmware V1.1 static analysis; camera observed V1.0.', '',
              f'Hash-verified {len(blocks)} blocks; GNU ARC linear disassembly of blocks '
              + ', '.join(str(x) for x in sorted(DIS_BLOCKS)) + '.', '',
              '## Results', '',
              f'- PC-relative state literal loads in scanned disassembly: **{len(result["pc_relative_refs"])}**',
              f'- Proximate store candidates at offsets +0x1D or +0: **{len(result["candidate_stores"])}**',
              f'- PC-relative 0x4405 literal loads in scanned disassembly: **{len(result["service_id_literal_refs"])}**',
              '- The CaptureImage table raw bytes are saved in the JSON; they do not establish a dispatch algorithm.', '',
              '## State pointer loads', '',
              '| Site | Literal address | Value | Target register |', '|---|---|---|---|']
    for r in result['pc_relative_refs']:
        report.append(f'| `{r["site"]}` | `{r["literal"]}` | `{r["literal_value"]}` | `{r["register"]}` |')
    report.extend(['', '## Candidate stores (not proven register data flow)', '',
                   '| Load site | Store site | Store instruction |', '|---|---|---|'])
    for r in result['candidate_stores']:
        report.append(f'| `{r["site"]}` | `{r["store_site"]}` | `{r["store_instruction"]}` |')
    report.extend(['', '## Literal references to service ID 0x4405', '',
                   'The following are PC-relative references in the scanned blocks, not a recovered dispatcher.', ''])
    for r in result['service_id_literal_refs'][:100]:
        report.append(f'- block {r["block"]} at `{r["site"]}` loads `{r["literal"]}`')
    if len(result['service_id_literal_refs']) > 100:
        report.append(f'- ... {len(result["service_id_literal_refs"])-100} more in JSON')
    report.extend(['', '## Limitations', ''] + [f'- {x}' for x in result['limits']] +
                  ['', 'Next: inspect store candidate windows, separate tables from executable code, '
                   'and only then attempt control/data-flow links to the physical shutter S2.', ''])
    out_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    out_md.write_text('\n'.join(report) + '\n')
    out_txt.write_text('\n'.join(details) + '\n')
    for path in (out_md, out_json, out_txt):
        print('Saved', path)
    print('SHA-256 verification of 16 original blocks: YES')
    print('Candidate state stores:', len(result['candidate_stores']))
    print('Physical S2 chain proven: NO')


if __name__ == '__main__':
    main()
