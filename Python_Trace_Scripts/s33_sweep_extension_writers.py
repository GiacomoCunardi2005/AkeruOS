#!/usr/bin/env python3
"""Static sweep of original V1.1 payloads (and TBIB body) for references to the
extension interval [0x35BC00,0x35CE00) and the surrounding gap [0x35B000,0x361000).

Extends the RAM-region evidence: inventories every aligned word pointing into the
sweep range, finds the PC-relative loads that reference it in the GNU ARC listing,
and flags proximate stores/calls as candidate writers (proximity only, no dataflow).
Read-only: firmware, blocks and tools are never modified.
"""
import bisect
from datetime import datetime, timezone
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'coolpix-s33-re'))
from s33_trace_state_dispatch import (verified_payloads, objdump_text, parse_listing, window,
                                      HEX_REF, LOADED_REGISTER, he)
from s33_run_gnu_arc700 import ROOT, sha
from s33_extract import parse_firmware

EXT_LO, EXT_HI = 0x35BC00, 0x35CE00
SWEEP_LO, SWEEP_HI = 0x35B000, 0x361000
GAP_END = 0x360800            # start of payload1: everything below it is the payload0 tail gap
EVIDENCE = ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'
FIRMWARE = ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin'
CANDIDATE = ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC/container_20261021T104016Z/S33_NAND_PC_RAW_OFFLINE_NON_INSTALLARE.bin'
CANDIDATE_SHA = '0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9'
MEM_WRITE_BASE = re.compile(r'\t(stb_s|stb|st_s|st|sthw|stw)\s+[^,]+,\[(r\d+)(?:,\s*(0x[0-9a-fA-F]+|[-\d]+))?\]')
MEM_WRITE_VALUE = re.compile(r'\t(stb_s|stb|st_s|st|sthw|stw)\s+(r\d+),')
LIMM_RANGE = re.compile(r',(0x3[5-6][0-9a-f]{4})\b')
MOVHI_RANGE = re.compile(r'\t(movhi|ori|or)\s+(r\d+),(?:r\d+,)?(0x35b|0x35c)\b')


def classify(value):
    if EXT_LO <= value < EXT_HI:
        return 'inside_extension'
    if SWEEP_LO <= value < EXT_LO:
        return 'below_extension'
    return 'gap_above_extension'


def word_sites(payload, base):
    """Every 2-byte-aligned LE word in the sweep range, with alignment class."""
    sites = []
    for off in range(0, len(payload)-3, 2):
        value = struct.unpack_from('<I', payload, off)[0]
        if SWEEP_LO <= value < SWEEP_HI:
            sites.append(dict(site=base+off, value=value, aligned4=off % 4 == 0,
                              kind=classify(value)))
    return sites


def raw_disasm(payload, vma, tolerate_oob=False):
    """GNU ARC listing of a raw binary at a given VMA (objcopy roundtrip checked)."""
    objcopy = ROOT/'work/build-arc/binutils/objcopy'
    objdump = ROOT/'work/build-arc/binutils/objdump'
    with tempfile.TemporaryDirectory(prefix='s33-ext-sweep-') as td:
        raw = Path(td)/'body.bin'; raw.write_bytes(payload)
        elf = Path(td)/'body.elf'
        subprocess.run([str(objcopy), '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
                        '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
                        '--change-section-vma', f'.data={vma:#x}', '--strip-all', str(raw), str(elf)],
                       check=True, capture_output=True)
        back = Path(td)/'back.bin'
        subprocess.run([str(objcopy), '--dump-section', f'.text={back}', str(elf)], check=True, capture_output=True)
        assert back.read_bytes() == payload, 'ELF roundtrip differs'
        text = subprocess.run([str(objdump), '-d', '-m', 'arc:ARC700', '-EL', str(elf)],
                              check=True, capture_output=True, text=True).stdout
        oob = 'out of bounds' in text.lower()
        if oob and not tolerate_oob:
            raise ValueError('objdump reported out of bounds')
        return text, oob


def analyze_listing(text, sites, windows_out, base):
    """Find pcl loads and limm/movhi uses of the sweep range; flag proximate stores."""
    addresses, lines = parse_listing(text)
    literal_sites = {s['site']: s for s in sites}
    referencers = []
    limm_uses = []
    movhi_uses = []
    for i, (site, line) in enumerate(zip(addresses, lines)):
        m = LOADED_REGISTER.search(line)
        if m:
            ref = HEX_REF.search(line)
            if ref and int(ref.group(1), 16) in literal_sites:
                register = m.group(1)
                entry = dict(site=he(site), register=register, instruction=line.strip(),
                             literal_value=he(literal_sites[int(ref.group(1), 16)]['value']),
                             kind=classify(literal_sites[int(ref.group(1), 16)]['value']),
                             proximate_stores=[])
                # Proximity-only writer flags: stores within 24 instructions using the
                # loaded register as base or as the stored value. Not proven dataflow.
                for future_site, future_line in zip(addresses[i+1:i+25], lines[i+1:i+25]):
                    if future_site > site+240:
                        break
                    wm = MEM_WRITE_BASE.search(future_line)
                    if wm and wm.group(2) == register:
                        entry['proximate_stores'].append(dict(site=he(future_site),
                              role='base', instruction=future_line.strip()))
                    vm = MEM_WRITE_VALUE.search(future_line)
                    if vm and vm.group(2) == register:
                        entry['proximate_stores'].append(dict(site=he(future_site),
                              role='value', instruction=future_line.strip()))
                referencers.append(entry)
                windows_out.append(f'====== referencer {he(site)} loads {entry["literal_value"]} ({entry["kind"]}) ======')
                windows_out.append(window(addresses, lines, site, 96, 192))
                windows_out.append('')
        else:
            lm = LIMM_RANGE.search(line)
            if lm and SWEEP_LO <= int(lm.group(1), 16) < SWEEP_HI:
                limm_uses.append(dict(site=he(site), instruction=line.strip(),
                                      value=he(int(lm.group(1), 16))))
                windows_out.append(f'====== limm use {he(site)} ======')
                windows_out.append(window(addresses, lines, site, 48, 96))
                windows_out.append('')
            hm = MOVHI_RANGE.search(line)
            if hm:
                movhi_uses.append(dict(site=he(site), instruction=line.strip()))
                windows_out.append(f'====== movhi/ori candidate {he(site)} ======')
                windows_out.append(window(addresses, lines, site, 32, 64))
                windows_out.append('')
    return referencers, limm_uses, movhi_uses


def sweep_block(payload, base, name, windows_out, tolerate_oob=False):
    sites = word_sites(payload, base)
    text, oob = raw_disasm(payload, base, tolerate_oob)
    referencers, limm_uses, movhi_uses = analyze_listing(text, sites, windows_out, base)
    return dict(name=name, base=he(base), size=len(payload), words_in_range=len(sites),
                disassembly_oob_boundary=oob,
                inside_extension_words=sum(1 for s in sites if s['kind'] == 'inside_extension'),
                referencers=referencers, limm_uses=limm_uses, movhi_or_ori_candidates=movhi_uses), sites


def main():
    out = EVIDENCE/('extension_writers_sweep_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(parents=True, exist_ok=False)
    try:
        blocks, payloads, block_dir = verified_payloads(ROOT)
        windows_out = ['# S33 — sweep riferimenti intervallo estensione [0x35b000,0x361000)',
                       '# Listato GNU ARC lineare: finestre sono supporto, non CFG provata.', '']
        results = []
        all_sites = {}
        for b in sorted(blocks, key=lambda x: x['index']):
            res, sites = sweep_block(payloads[b['index']], b['load_address_candidate'],
                                     f'payload{b["index"]}', windows_out)
            results.append(res)
            all_sites[b['index']] = sites
        # TBIB body: boot-stage references to the Main gap.
        data = FIRMWARE.read_bytes()
        sections, _ = parse_firmware(data)
        tbib_base, body_size, checksum, entry = struct.unpack_from('<4I', data, sections[0].data_start)
        assert (tbib_base, body_size, entry) == (0x1000000, 0x44bbc, 0x1000000)
        tbib_start = sections[0].data_start+16
        body = data[tbib_start:tbib_start+body_size]
        assert sum(x[0] for x in struct.iter_unpack('<I', body)) & 0xffffffff == checksum
        res, _ = sweep_block(body, 0x1000000, 'TBIB_body', windows_out, tolerate_oob=True)
        results.append(res)
        # Candidate payload0: original referencers must survive in the candidate image.
        cand = CANDIDATE.read_bytes()
        assert sha(CANDIDATE) == CANDIDATE_SHA, 'hash candidato inatteso'
        c_sections, _ = parse_firmware(cand)
        tbm_start = c_sections[1].data_start
        cand_p0 = cand[tbm_start+512:tbm_start+512+2810880]
        orig_p0 = payloads[0]
        assert len(cand_p0) == len(orig_p0)
        delta = [i for i in range(len(orig_p0)) if orig_p0[i] != cand_p0[i]]
        cand_res, cand_sites = sweep_block(cand_p0, 0xAD800, 'candidate_payload0', windows_out)
        results.append(cand_res)
        # The original payload0 referencer set must be a subset of the candidate's.
        orig_refs = {(r['site'], r['literal_value']) for r in results[0]['referencers']}
        cand_refs = {(r['site'], r['literal_value']) for r in cand_res['referencers']}
        assert orig_refs <= cand_refs, 'il candidato ha perso riferimenti originali'
        new_refs = sorted(cand_refs-orig_refs)
        (out/'windows.txt').write_text('\n'.join(windows_out)+'\n')
        summary = []
        for r in results:
            summary.append(dict(name=r['name'], base=r['base'], words_in_range=r['words_in_range'],
                                inside_extension=r['inside_extension_words'],
                                pcl_referencers=len(r['referencers']),
                                referencers_with_proximate_stores=sum(1 for x in r['referencers'] if x['proximate_stores']),
                                limm_uses=len(r['limm_uses']), movhi_or_ori_candidates=len(r['movhi_or_ori_candidates'])))
        result = dict(status='PASS_EXTENSION_WRITERS_SWEEP_STATIC',
                      sweep_range=[he(SWEEP_LO), he(SWEEP_HI)], extension=[he(EXT_LO), he(EXT_HI)],
                      payload0_end=he(0x35BC00), payload1_start=he(GAP_END),
                      blocks=summary, details=results,
                      candidate=dict(path=str(CANDIDATE.relative_to(ROOT)), sha256=CANDIDATE_SHA,
                                     payload0_delta_bytes=len(delta),
                                     payload0_delta_first=[he(0xAD800+d) for d in delta[:16]],
                                     original_referencers_preserved=True,
                                     new_referencers=[[s, v] for s, v in new_refs]),
                      limits=['Proximity stores are candidates only: no dataflow, no CFG, no aliasing proof',
                              'GNU ARC listing is linear: data can be disassembled as code and vice versa',
                              'Words scanned at 2-byte alignment; unaligned-by-one literals are not covered',
                              'DMA, cache and computed writes remain outside a static word sweep',
                              'Blocks 11-15 share base 0x1044800 (overlay): same RAM, separate records',
                              'No firmware executed, no candidate install: NON_INSTALLARE invariato'],
                      sources={str(p): sha(p) for p in [Path(__file__), FIRMWARE, CANDIDATE,
                                                       ROOT/'S33-sections/TBM_blocks/manifest.json']})
        (out/'verified_evidence.json').write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n')
        (EVIDENCE/'extension_writers_sweep_latest.json').write_text(json.dumps(
            dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))), indent=2)+'\n')
        print('PASS', out)
        for s in summary:
            print(f"{s['name']:22s} words={s['words_in_range']:3d} ext={s['inside_extension']:3d} "
                  f"pcl={s['pcl_referencers']:3d} store_candidates={s['referencers_with_proximate_stores']:3d} limm={s['limm_uses']}")
    except BaseException as exc:
        (out/'failure.json').write_text(json.dumps(dict(status='FAIL', error=repr(exc)), indent=2)+'\n')
        raise


if __name__ == '__main__':
    main()
