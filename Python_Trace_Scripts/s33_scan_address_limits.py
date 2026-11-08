#!/usr/bin/env python3
"""Inventory address candidates in every ASM row; never infer physical RAM from a maximum."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import re
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import ORIGINAL,EXPECTED,PS,sha,disasm,u32
from s33_disassemble_firmware11 import ROW, OUTPUT
OUT=ROOT/'Ghidra_Results/ghidra_reports/address_limits'
ABSOLUTE=re.compile(r'\[(0x[0-9a-f]+)\]')
PCREL=re.compile(r'\[pcl,(-?(?:0x[0-9a-f]+|\d+))\]')

def band(value):
    if value<0x1000000:return 'below_01000000'
    if value<0xF000000:return '01000000_to_0effffff'
    if value<0xFE00000:return '0f000000_to_0fdfffff'
    if value<0x10000000:return '0fe00000_to_0fffffff'
    return '10000000_and_above'

def pool_address(pc,operand,op):
    return (pc&~3)+int(operand,0)*(4 if op=='ld.as' else 1)

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    source=OUTPUT;data=ORIGINAL.read_bytes();assert sha(data)==EXPECTED
    prior=json.loads((ROOT/'Ghidra_Results/ghidra_reports/firmware11_full/verified_evidence.json').read_text())
    regions={r['name']:r for r in prior['regions']}
    assert pool_address(0x269702,'0x12c','ld_s')==0x26982C
    assert pool_address(0x1392E0,'-144','ld.as')==0x1390A0
    assert band(0xFE800F8)=='0fe00000_to_0fffffff'
    top={};counts=Counter();rows=0;cursor=0;region=None;max_numeric=0;max_mapped_end=0;bad_pools=0
    asm_hash=hashlib.sha256();byte_hash=hashlib.sha256()
    def record(kind,value,example):
        key=kind+'/'+band(value)+'/'+('boot_main_linear' if region['name'] in ('TBM_00','TBIB_BODY') else 'other_payloads_linear')
        counts[key]+=1;values=top.setdefault(key,{})
        if value in values:values[value]['occurrences']+=1;return
        if len(values)==12:
            lowest=min(values)
            if value<=lowest:return
            del values[lowest]
        values[value]=dict(value=f'0x{value:08X}',occurrences=1,**example)
    with source.open('rb') as stream:
        for line_no,binary_line in enumerate(stream,1):
            asm_hash.update(binary_line);line=binary_line.decode()
            if line.startswith('; REGION '):region=regions[line.split()[2]]
            m=ROW.match(line.rstrip('\n'))
            if not m:continue
            pos=int(m[1],16);b=bytes.fromhex(m[3]);assert pos==cursor and data[pos:pos+len(b)]==b
            cursor+=len(b);rows+=1;byte_hash.update(b)
            if m[2]=='--------':continue
            pc=int(m[2],16);max_mapped_end=max(max_mapped_end,pc+len(b))
            assembly=m[4].split(';',1)[0].strip();parts=assembly.split(None,1)
            if not parts or parts[0].startswith('.'):continue
            op=parts[0];args=parts[1] if len(parts)>1 else ''
            for h in re.findall(r'0x[0-9a-f]+',args):max_numeric=max(max_numeric,int(h,16))
            example=dict(line=line_no,region=region['name'],pc=f'0x{pc:08X}',file_offset=f'0x{pos:08X}',assembly=assembly)
            if op.startswith(('ld','st')):
                for h in ABSOLUTE.findall(args):record('absolute_di' if '.di' in op else 'absolute_normal',int(h,16),example)
            if op in ('mov','mov_s'):
                immediate=re.fullmatch(r'[^,]+,(0x[0-9a-f]+)',args)
                if immediate:record('move_immediate_untyped',int(immediate[1],16),example)
            if op in ('ld','ld_s','ld.as'):
                literal=PCREL.search(args)
                if not literal:continue
                target=pool_address(pc,literal[1],op);offset=target-region['base']
                if offset<0 or offset+4>region['end']-region['start']:bad_pools+=1;continue
                value=struct.unpack_from('<I',data,region['start']+offset)[0]
                record('pcl_loaded_word_untyped',value,dict(pool=f'0x{target:08X}',**example))
    assert cursor==len(data) and rows==prior['output']['rows'] and byte_hash.hexdigest()==EXPECTED
    assert asm_hash.hexdigest()==prior['output']['sha256']
    ranked={key:sorted(values.values(),key=lambda x:int(x['value'],16),reverse=True) for key,values in sorted(top.items())}
    # Independently re-anchor selected meaningful examples, rather than treating scan maxima as executed code.
    windows=[(0x2696F4,0x269710),(0x17750C,0x177532),(0x178D10,0x178D38)]
    gnu=OUT/'gnu_verified.txt';gnu.write_text('\n'.join(disasm(a,b) for a,b in windows))
    bases=[u32(a) for a in range(0x269828,0x269838,4)]
    assert bases==[0xF794000,0xF798000,0xF7A0000,0xF7B0000]
    assert u32(0x1775FC)==0x2696F4
    known_buffer_end=0xF798000+0x4180+0x3000;assert known_buffer_end==0xF79F180
    result=dict(firmware_sha256=EXPECTED,asm_sha256=asm_hash.hexdigest(),asm_rows=rows,covered_bytes=cursor,
        max_hex_operand=f'0x{max_numeric:08X}',max_candidate_loaded_region_end=f'0x{max_mapped_end:08X}',
        rank_scope='Top12 per syntax/address band/source group; every row scanned; candidates are not executable xrefs',
        counts=dict(counts),ranked=ranked,pcl_candidates_outside_own_region=bad_pools,
        fixed_region_bases=[f'0x{x:08X}' for x in bases],known_workspace=dict(start='0x0F79B180',end_exclusive=hex(known_buffer_end),size=0x4000),
        conditional_zero_based_contiguous_ram_bytes=known_buffer_end,
        physical_ram_size_proven=False,gnu_windows=len(windows),
        limits=['Linear decode includes data and false instructions; no reachability or RAM type inferred',
                'Address bands organize results, not a physical RAM/peripheral partition',
                'A highest used address cannot prove an upper bound on physical capacity',
                'Zero-based contiguous calculation assumes physical RAM, no alias, no holes; assumptions unproven',
                'Computed pointers, DMA/bus mappings and banks can exceed or alias explicit literals'],
        files={'script':sha(Path(__file__).read_bytes()),'gnu_verified.txt':sha(gnu.read_bytes())})
    (OUT/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    report=f'''# Indirizzi più alti nell'ASM e limite della stima RAM

20 ottobre 2026. Scansionate **{rows:,} righe**, ricostruiti tutti i {cursor:,} byte e lo SHA-256 del firmware originale. Il massimo numero esadecimale negli operandi è **0x{max_numeric:08X}**: non equivale alla dimensione della RAM.

[Script](../Python_Trace_Scripts/s33_scan_address_limits.py), [risultati e massimi per categoria](../Ghidra_Results/ghidra_reports/address_limits/verified_evidence.json), [tre finestre GNU](../Ghidra_Results/ghidra_reports/address_limits/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_scan_address_limits.py`. Si analizza il listato canonicoCMP3, non si rigenerano i due ASM. I gruppi numerici sono contenitori di ricerca, non una classificazione fisica della memoria.

## Cosa si può ricavare davvero

- La fine massima dei payload con base CPU candidata è **0x{max_mapped_end:08X}**, cioè {max_mapped_end/1048576:.3f} MiB dall'indirizzo zero. Questa è geometria dei payload, con overlay e fasi distinte: non è la quantità di RAM installata.
- Il getter reale `0x2696F4`, riancorato con GNU, restituisce quattro basi: {', '.join(f'`0x{x:08X}`' for x in bases)}. La più alta di queste quattro basi è `0x0F7B0000`: il suo indirizzo non ne stabilisce dimensione o natura fisica.
- Il workspace già ricostruito occupa `[0x0F79B180, 0x0F79F180)`, **16 KiB**. Getter, due casi e literal sono ricontrollati; il raccordo completo precedente è in [origine dei buffer](S33_Origine_Celle_Buffer_e_Area_Condivisa_Stadi.md). Questo dà un intervallo software concreto, non una RAM contigua da zero.
- **Solo ipotizzando** RAM fisica lineare dazero, senza buchi o alias, la fine di quel workspace richiederebbe almeno {known_buffer_end:,} byte, circa **{known_buffer_end/1048576:.3f} MiB**. Non dimostra 256 MiB installati: le ipotesi non sono verificate e potrebbe trattarsi di una finestra di memoria interna a un motore hardware.

Un indirizzo alto della memoria indica, sotto ipotesi precise, un minimo di copertura necessario. Non stabilisce un massimo della capacità: può esistere RAM non usata, indirizzata tramite calcoli o in altre banche. Viceversa un piccolo blocco fisico può essere mappato a un indirizzo numericamente molto alto. I registri hardware e le maschere numeriche non vanno sommati alla RAM.

## Massimi della scansione da trattare come candidati

| Categoria e intervallo numerico | Provenienza | Valore più alto | Riga ASM |
|---|---|---|---:|
'''
    for key,values in ranked.items():
        if key.startswith(('absolute_normal/','absolute_di/','pcl_loaded_word_untyped/')):
            row=values[0];kind,span,scope=key.split('/')
            report+=f"| {kind}, {span} | {scope} | `{row['value']}` | {row['line']} |\n"
    report+='''
La tabella è un inventario di dove cercare, non un elenco di accessi RAM verificati. I massimi possono derivare da dati disassemblati come codice. Le parole caricate da pool e gli immediati non hanno un tipo: possono essere puntatori, maschere o numeri. Le formule PC-relative sono applicate soltanto alle tre forme riconosciute; gli altri costruttori e gli indirizzi calcolati non sono risolti.

Prossimo punto utile: ricostruire il controller memoria e le sue impostazioni di base/capienza/banchi, oppure trovare una descrizione hardware pertinente del chip RAM. Non inizializzare nell'emulatore tutta la fascia fino al numero massimo: nasconderebbe anche accessi hardware sconosciuti. Nessun file firmware modificato o accesso alla Nikon; nessuna nuova prova di boot completo o recupero. NO-GO al flash invariato.
'''
    docs=ROOT/'MDs';docs.mkdir(parents=True,exist_ok=True)
    (docs/'S33_Limiti_Indirizzi_e_Stima_RAM.md').write_text(report)
    assert ORIGINAL.read_bytes()==data
    print(f'PASS:{rows} ASM rows,all {cursor} bytes,original hash;max operand {max_numeric:#x};physical RAM size remains unproven')

if __name__=='__main__':main()
