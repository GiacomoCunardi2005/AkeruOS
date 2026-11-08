#!/usr/bin/env python3
"""Compare an existing MainCode export with the offline RAW candidate; read only."""
import argparse
import hashlib
import json
from pathlib import Path

from s33_analyze_maincode_export import ROOT, tbm_offset, tbm_of
from s33_build_raw_always_on_offline import PATCHES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('export', type=Path)
    parser.add_argument('--combined', action='store_true', help='confronta il candidato RAW + HiddenMenu')
    args = parser.parse_args()
    export = args.export.read_bytes()
    if args.combined:
        candidate = tbm_of('Risultati/HiddenMenu_RAW_Combinato/20261027T122133Z/'
                           'firmware_RAW_HIDDENMENU_OFFLINE_NON_INSTALLARE.bin',
                           'a997f1e3acf518530233b41a0f93e2bd07f06edf0369b9a2d388d9c5e2ec8c19')
    else:
        candidate = tbm_of('Risultati/HiddenMenu_RAW_Firmware/20261027T110219Z/'
                           'firmware_RAW_FORZATO_OFFLINE_NON_INSTALLARE.bin',
                           '56c9457646be23bde6e1bda47c6cefaada5bf52657ba299f83339306debf4cbf')
    if len(export) < len(candidate):
        parser.error(f'export troppo corto: {len(export)} byte; minimo {len(candidate)}')
    checks = []
    for address, (original, modified, label) in PATCHES.items():
        offset = tbm_offset(address)
        actual = export[offset:offset + len(modified)]
        checks.append({'address': hex(address), 'label': label, 'offset': hex(offset),
                       'observed': actual.hex(), 'original': original.hex(),
                       'candidate': modified.hex(),
                       'match': 'candidate' if actual == modified else
                                'original' if actual == original else 'other'})
    result = {'export': str(args.export), 'size': len(export),
              'sha256': hashlib.sha256(export).hexdigest(),
              'candidate_tbm_prefix_match': export[:len(candidate)] == candidate,
              'checks': checks,
              'limit': 'Il dump mostra la partizione esportata, non dimostra la copia avviata o la data.'}
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
