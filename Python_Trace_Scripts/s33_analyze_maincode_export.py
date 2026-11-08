#!/usr/bin/env python3
"""Classify a MainCode export (HiddenMenu Dump2File) against the known image generations.

Read-only analyzer for the decisive step of the NAND/PC goal: when the user
produces a new DUMPS/MainCode.dmp, this tool reports which generation the flash
contains. It never asserts a preferred outcome: it measures the FF slot 0x9A3460,
the MSDC byte (RAM 0xC5EEA), the candidate hook (RAM 0x820C88), the record17 tail
and the whole-TBM identity against the four known images, then classifies.
An export shows the flash MainCode content at export time: it does not prove
which image is currently booted (see the generations checkpoint for that limit).
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS
sys.path.insert(0, str(ROOT/'coolpix-s33-re'))
from s33_extract import parse_firmware

IMAGES = {
    'original': ('OriginalSoftware_NikonS33_V1.1/firmware.bin',
                 '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'),
    'sd_candidate': ('Risultati/Firmware_sperimentali/SD/S33_MODIFICA_SD_SPERIMENTALE_NON_INSTALLARE.bin',
                     'ce504526dcb1ebffab33f17bf1467fd03f70b01c5393ad03812523f978b3e8c9'),
    'msdc_default': ('Risultati/Firmware_sperimentali/USB_MSDC_Default/S33_USB_MSDC_DEFAULT_OFFLINE_NON_INSTALLARE.bin',
                     'af65ab0e66781c1a1036ab2349700e9d2110c6618738b02208da8b83c8813544'),
    'nandpc_candidate': ('Risultati/Firmware_sperimentali/USB_NAND_PC/CONSEGNA_NON_INSTALLARE_20261021T142753Z/firmware.bin',
                          '0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9'),
}
SLOT_RAM = 0x9A3460
MSDC_RAM = 0xC5EEA
HOOK_RAM = 0x820C88
ORIGINAL_TBM_LEN = 17615360
CANDIDATE_TAIL = 4608


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tbm_offset(ram):
    """TBM-file offset of a RAM address, using the payload manifest bases."""
    for b in BS:
        base = b['load_address_candidate']
        if base <= ram < base+b['size']:
            return b['offset']+(ram-base)
    raise ValueError(hex(ram))


def tbm_of(rel, expected):
    pkg = (ROOT/rel).read_bytes()
    assert sha(pkg) == expected, (rel, sha(pkg))
    sections, _ = parse_firmware(pkg)
    return pkg[sections[1].data_start:sections[1].data_end]


def diff_runs(a, b):
    n = min(len(a), len(b))
    idx = [i for i in range(n) if a[i] != b[i]]
    if not idx:
        return []
    runs, s, p = [], idx[0], idx[0]
    for d in idx[1:]:
        if d == p+1:
            p = d
        else:
            runs.append((s, p)); s = p = d
    runs.append((s, p))
    return runs


def analyze(export_path):
    export = Path(export_path).read_bytes()
    slot_off, msdc_off, hook_off = tbm_offset(SLOT_RAM), tbm_offset(MSDC_RAM), tbm_offset(HOOK_RAM)
    slot = struct.unpack_from('<I', export, slot_off)[0] if len(export) >= slot_off+4 else None
    msdc = export[msdc_off] if len(export) > msdc_off else None
    hook = export[hook_off:hook_off+8].hex() if len(export) >= hook_off+8 else None
    tail = export[ORIGINAL_TBM_LEN:ORIGINAL_TBM_LEN+CANDIDATE_TAIL]
    tail_non_ff = sum(1 for x in tail if x != 255)
    tbms = {name: tbm_of(rel, expected) for name, (rel, expected) in IMAGES.items()}
    comparisons = {}
    for name, tbm in tbms.items():
        runs = diff_runs(tbm, export[:min(len(export), len(tbm))])
        comparisons[name] = dict(tbm_length=len(tbm), diff_runs=[[a, b] for a, b in runs][:32],
                                 diff_run_count=len(runs), prefix_match=not runs)
    exact = [name for name, c in comparisons.items() if c['prefix_match'] and len(export) >= len(tbms[name])]
    # Classification: measured facts first, interpretation after.
    facts = dict(export=str(Path(export_path)), sha256=sha(export), length=len(export),
                 slot_9a3460=hex(slot) if slot is not None else None,
                 msdc_byte_c5eea=hex(msdc) if msdc is not None else None,
                 hook_820c88=hook,
                 record17_tail=dict(present=len(tail) == CANDIDATE_TAIL,
                                    non_ff_bytes=tail_non_ff,
                                    full_tail=len(tail) == CANDIDATE_TAIL and tail_non_ff >= CANDIDATE_TAIL-16))
    if slot == 0x0035BD40 and facts['record17_tail']['full_tail']:
        verdict = 'GENERAZIONE_CANDIDATO_NAND_PC'
        meaning = ("l'export contiene il TBM del candidato 0bb25fd6: slot RAW puntato a 35BD40, "
                   'record17/coda presenti. Questo indica che la flash MainCode contiene il candidato; '
                   'non prova da solo quale copia sia avviata, ma rende il dispatch RAW possibile.')
    elif slot == 0x00820B2C:
        if exact:
            verdict = f'GENERAZIONE_{exact[0].upper()}'
            meaning = (f"l'export coincide integralmente col TBM di {exact[0]} (slot originale 820B2C): "
                       'generazione precedente, il candidato NAND/PC non è nella flash MainCode.')
        else:
            verdict = 'GENERAZIONE_ORIGINALE_SCONOSCIUTA'
            meaning = ('slot originale 820B2C e nessuna identità integrale con le immagini note: '
                       'variante non ancora classificata; confrontare i diff_runs.')
    else:
        verdict = 'GENERAZIONE_SCONOSCIUTA'
        meaning = 'slot non corrisponde a nessuna generazione nota: verificare il metodo di export.'
    return dict(status='ANALYSIS_COMPLETE', facts=facts, comparisons=comparisons,
                exact_matches=exact, verdict=verdict, meaning=meaning,
                limits=['Un export mostra il contenuto flash MainCode al momento del Dump2File, non la copia avviata',
                        'La classificazione dipende dalle quattro immagini note; varianti nuove restano SCONOSCIUTE',
                        'Nessuna scrittura, nessun comando alla fotocamera, candidato NON_INSTALLARE'])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--export', default='DUMPS/MainCode.dmp', help='percorso dell\'export MainCode da classificare')
    ap.add_argument('--save', action='store_true', help='salva l\'analisi in Risultati/USB_SCSI/Accesso_NAND_PC')
    args = ap.parse_args()
    result = analyze((ROOT/args.export).resolve() if not Path(args.export).is_absolute() else Path(args.export))
    if args.save:
        out = ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/('maincode_export_analysis_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
        out.mkdir(parents=True, exist_ok=False)
        (out/'analysis.json').write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n')
        (out/'analyzer_snapshot.py').write_bytes(Path(__file__).read_bytes())
        (ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/'maincode_export_analysis_latest.json').write_text(json.dumps(
            dict(analysis=str((out/'analysis.json').relative_to(ROOT))), indent=2)+'\n')
        result['saved'] = str((out/'analysis.json').relative_to(ROOT))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    main()
