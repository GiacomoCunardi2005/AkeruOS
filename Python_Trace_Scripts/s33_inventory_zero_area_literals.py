#!/usr/bin/env python3
"""Literal inventory toward the MainCode zeroing-area top, with instruction-aware artifact filtering.

Correction over the naive aligned-word scan: in ARC instruction streams a large
share of aligned words that numerically fall in [0x5DA000,0x5DC000) are ENCODING
STRADDLES of ordinary instructions (branch tables at 2-mod-4 alignment, st/asl
pairs, ...). This verifier classifies every candidate site:

  real    = pcl-referenced literal (loaded by some ld rX,[pcl,...]) or the
            displayed 32-bit immediate of its covering instruction (limm);
  artifact = the site is covered by a decoded instruction and the value is not
            that instruction's immediate.

Read-only; the raw word counts of the previous evidence remain as history.
"""
from datetime import datetime, timezone
import bisect
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'Python_Trace_Scripts'))
from s33_trace_state_dispatch import verified_payloads, objdump_text, parse_listing, HEX_REF, LOADED_REGISTER

SWEEP_LO, SWEEP_HI = 0x5da000, 0x5dc000
ZERO_END = 0x5da5dc
SP_BASE = 0x5dadcc
EVIDENCE = ROOT/'Ghidra_Results/ghidra_reports'


def main():
    out = EVIDENCE/('zero_area_top_literals_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(parents=True, exist_ok=False)
    try:
        blocks, payloads, block_dir = verified_payloads(ROOT)
        info = {b['index']: b for b in blocks}
        rows = []
        for idx, p in payloads.items():
            base = info[idx]['load_address_candidate']
            # Skip payload blocks without any candidate site quickly is not possible
            # before the scan; the listing is only built for blocks with hits.
            candidates = []
            for off in range(0, len(p)-3, 4):
                value = struct.unpack_from('<I', p, off)[0]
                if SWEEP_LO <= value < SWEEP_HI:
                    candidates.append((base+off, value))
            if not candidates:
                continue
            text = objdump_text(ROOT, block_dir, [b for b in blocks if b['index'] == idx][0], payloads[idx])
            addresses, lines = parse_listing(text)
            pcl_sites = set()
            for line in lines:
                m = LOADED_REGISTER.search(line)
                if m:
                    r = HEX_REF.search(line)
                    if r:
                        pcl_sites.add(int(r.group(1), 16))
            for site, value in candidates:
                i = bisect.bisect_right(addresses, site)-1
                start, line = addresses[i], lines[i]
                end = addresses[i+1] if i+1 < len(addresses) else start+4
                covering = start <= site < end
                displayed = f'{value:#x}' in line
                if site in pcl_sites or displayed:
                    kind = 'real'
                elif covering:
                    kind = 'artifact_instruction_straddle'
                else:
                    kind = 'unclassified'
                rows.append(dict(block=idx, site=site, value=value, kind=kind,
                                 covering_instruction=line.strip()[:72] if covering else None,
                                 below_zero_end=value < ZERO_END))
        real = [r for r in rows if r['kind'] == 'real']
        artifact = [r for r in rows if r['kind'] == 'artifact_instruction_straddle']
        unclassified = [r for r in rows if r['kind'] == 'unclassified']
        by_block = {}
        for r in rows:
            key = str(r['block'])
            by_block.setdefault(key, dict(raw=0, real=0, artifact=0, unclassified=0))
            by_block[key]['raw'] += 1
            by_block[key][{'real': 'real', 'artifact_instruction_straddle': 'artifact',
                           'unclassified': 'unclassified'}[r['kind']]] += 1
        distinct_real = sorted({r['value'] for r in real})
        result = dict(status='PASS_ZERO_AREA_TOP_LITERAL_INVENTORY_V2',
                      correction=('I conteggi "word allineate" della versione precedente includevano straddle di '
                                  'encoding di istruzioni (tabelle di salti a allineamento 2-mod-4, coppie st/asl, '
                                  'blc). Questa versione classifica ogni sito: reale solo se letterale pcl '
                                  'referenziato o immediato limm visualizzato. I risultati della versione precedente '
                                  'restano come storia; la "griglia a passo 0x100" era un artefatto della tabella '
                                  'di salti di payload6 a 0xAF454E..'),
                      sweep_range=[hex(SWEEP_LO), hex(SWEEP_HI)], zero_end=hex(ZERO_END), sp_base=hex(SP_BASE),
                      raw_candidates=len(rows), real_references=len(real),
                      artifact_straddles=len(artifact), unclassified=len(unclassified),
                      per_block=by_block,
                      real_sites=[[r['block'], hex(r['site']), hex(r['value'])] for r in real],
                      distinct_real_values=[hex(v) for v in distinct_real],
                      unclassified_sites=[[r['block'], hex(r['site']), hex(r['value'])] for r in unclassified],
                      limits=['Real classification covers pcl-loaded literals and displayed limm only: data tables '
                              'never loaded via pcl and not limm remain invisible to this method',
                              'The linear GNU listing decodes data as instructions: unclassified sites are rare '
                              'here but the method cannot prove a data site real by absence of coverage',
                              'No execution; writers/DMA/ownership unchanged; candidate NON_INSTALLARE'],
                      sources={str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in [ROOT/'S33-sections/TBM_blocks/manifest.json']})
        (out/'verified_evidence.json').write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n')
        (EVIDENCE/'zero_area_top_literals_latest.json').write_text(json.dumps(
            dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))), indent=2)+'\n')
        print('PASS', out)
        print(' raw:', len(rows), 'real:', len(real), 'artifact:', len(artifact), 'unclassified:', len(unclassified))
        print(' per_block:', json.dumps(by_block))
        print(' valori reali distinti:', [hex(v) for v in distinct_real])
    except BaseException as exc:
        (out/'failure.json').write_text(json.dumps(dict(status='FAIL', error=repr(exc)), indent=2)+'\n')
        raise


if __name__ == '__main__':
    main()
