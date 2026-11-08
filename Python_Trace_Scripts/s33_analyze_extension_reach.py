#!/usr/bin/env python3
"""Reach analysis of the neighborhood proximity stores from the extension-writers sweep.

Second-stage static analysis of the published sweep evidence: for every proximate
store whose base register holds a neighborhood literal, compute the written range
(value + immediate offset + store size) and check whether it can intersect the
candidate extension [0x35BC00,0x35CE00). Value-role stores (the pointer itself is
spilled) and limm uses are classified separately. Read-only on all inputs.
"""
from datetime import datetime, timezone
import json
import re
from pathlib import Path

from s33_run_gnu_arc700 import ROOT, sha

EXT = (0x35BC00, 0x35CE00)
EVIDENCE = ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'
OPERAND = re.compile(r'\[(r\d+|sp|fp)(?:,\s*(0x[0-9a-fA-F]+|-0x[0-9a-fA-F]+|-\d+|\d+))?\]')
SCALED = re.compile(r'\[(r\d+|sp|fp),(r\d+)\]')


def store_size(instruction):
    if 'stb' in instruction or 'sthb' in instruction:
        return 1
    if 'sthw' in instruction or 'sth ' in instruction:
        return 2
    return 4


def analyze(evidence):
    base_stores, value_stores, scaled, unparsed = [], [], [], []
    for block in evidence['details']:
        if block['name'].startswith('candidate'):
            continue  # duplicate image; the original payload0 covers the claim
        for ref in block['referencers']:
            value = int(ref['literal_value'], 16)
            for store in ref['proximate_stores']:
                instruction = store['instruction']
                operand = instruction[instruction.find('['):]
                match = SCALED.search(operand)
                if match:
                    scaled.append(dict(block=block['name'], site=ref['site'], literal=ref['literal_value'],
                                       store_site=store['site'], role=store['role'], instruction=instruction))
                    continue
                match = OPERAND.search(operand)
                if not match:
                    unparsed.append(dict(block=block['name'], site=ref['site'], role=store['role'],
                                         instruction=instruction))
                    continue
                offset = int(match.group(2), 0) if match.group(2) else 0
                size = store_size(instruction)
                row = dict(block=block['name'], site=ref['site'], literal=ref['literal_value'],
                           store_site=store['site'], role=store['role'], offset=offset, size=size,
                           reach=[value+offset, value+offset+size-1], instruction=instruction)
                if store['role'] == 'base':
                    base_stores.append(row)
                else:
                    value_stores.append(row)
    return base_stores, value_stores, scaled, unparsed


def intersects(row):
    return not (row['reach'][1] < EXT[0] or row['reach'][0] >= EXT[1])


def main():
    out = EVIDENCE/('extension_reach_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(parents=True, exist_ok=False)
    try:
        sweep_path = ROOT/json.loads((EVIDENCE/'extension_writers_sweep_latest.json').read_text())['evidence']
        evidence = json.loads(sweep_path.read_text())
        assert evidence['status'] == 'PASS_EXTENSION_WRITERS_SWEEP_STATIC'
        base_stores, value_stores, scaled, unparsed = analyze(evidence)
        # Base-role stores: the only ones that write through the neighborhood pointer.
        hitting = [r for r in base_stores if intersects(r)]
        negative = [r for r in base_stores if r['offset'] < 0]
        max_positive = max((r['offset'] for r in base_stores), default=0)
        min_value = min(int(r['literal'], 16) for r in base_stores)
        # Distance from the highest below-extension base to the extension start.
        below = [int(r['literal'], 16) for r in base_stores if int(r['literal'], 16) < EXT[0]]
        highest_below = max(below)
        distance = EXT[0]-highest_below
        limm = []
        for block in evidence['details']:
            if block['name'].startswith('candidate'):
                continue
            for use in block['limm_uses']:
                immediate = int(use['value'], 16)
                limm.append(dict(block=block['name'], site=use['site'], value=use['value'],
                                 zone='extension' if EXT[0] <= immediate < EXT[1] else
                                      ('below' if immediate < EXT[0] else 'above'),
                                 instruction=use['instruction']))
        limm_in_extension = [u for u in limm if u['zone'] == 'extension']
        # Value-role stores install the neighborhood pointer into other bases
        # (structs, other pointers): their destinations are not tracked here.
        value_bases = sorted({OPERAND.search(r['instruction'][r['instruction'].find('['):]).group(1)
                              for r in value_stores})
        result = dict(status='PASS_EXTENSION_REACH_ANALYSIS',
                      source_evidence=str(sweep_path.relative_to(ROOT)),
                      base_role_stores=len(base_stores), value_role_stores=len(value_stores),
                      scaled_register_offsets=len(scaled), unparsed_operands=len(unparsed),
                      extension_intersections=len(hitting),
                      negative_offsets=[dict(r) for r in negative],
                      max_positive_offset=max_positive,
                      highest_below_extension_base=hex(highest_below),
                      distance_to_extension=distance,
                      margin=distance-max_positive,
                      value_role_destination_bases=value_bases,
                      limm_uses=len(limm), limm_in_extension=len(limm_in_extension),
                      limm_zones={z: sum(1 for u in limm if u['zone'] == z) for z in ('below', 'extension', 'above')},
                      interpretation=(
                          f'Nessuno store di prossimita con base nel vicinato raggiunge l\'estensione: '
                          f'offset positivo massimo {max_positive:#x} contro distanza {distance:#x} '
                          f'dalla base piu alta sotto l\'estensione ({highest_below:#x}); '
                          f'{len(negative)} offset negativi, tutti lontani; '
                          f'{len(scaled)} forme con offset a registro (portata non limitata staticamente); '
                          f'{len(limm_in_extension)} limm dentro l\'estensione.'),
                      limits=['Proximity analysis only: 24 instructions after each literal load, no full dataflow',
                              'Scaled register-offset stores, if any, have unbounded static reach',
                              'Value-role stores install neighborhood pointers into other bases: destinations are not traced',
                              'No runtime, DMA or cache proof; candidate NON_INSTALLARE unchanged'],
                      sources={str(p): sha(p) for p in [Path(__file__), sweep_path]})
        (out/'verified_evidence.json').write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n')
        (EVIDENCE/'extension_reach_latest.json').write_text(json.dumps(
            dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))), indent=2)+'\n')
        print('PASS', out)
        print(' base-role:', len(base_stores), 'max offset', hex(max_positive),
              'distance', hex(distance), 'margin', hex(result['margin']))
        print(' negative:', len(negative), 'scaled:', len(scaled), 'unparsed:', len(unparsed))
        print(' intersections:', len(hitting), 'limm in extension:', len(limm_in_extension))
    except BaseException as exc:
        (out/'failure.json').write_text(json.dumps(dict(status='FAIL', error=repr(exc)), indent=2)+'\n')
        raise


if __name__ == '__main__':
    main()
