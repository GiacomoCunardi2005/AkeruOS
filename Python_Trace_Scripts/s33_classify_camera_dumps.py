#!/usr/bin/env python3
"""Classify local camera exports without changing dumps or contacting hardware."""
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import csv
import hashlib
import json
import os
import re
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,ORIGINAL,EXPECTED,disasm
from audit_patch import sum32


def sha(data):return hashlib.sha256(data).hexdigest()


def main():
    source=ROOT/'DUMPS'
    out=ROOT/'Risultati/Dump_fotocamera'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    contents={p.name:p.read_bytes() for p in sorted(source.iterdir()) if p.is_file()}
    required={'MainCode.dmp','BootCode.dmp','Calibration.dmp','Calibration_2.dmp','CameraParam.dmp','CameraParam_2.dmp',
              'CalibrationItem.txt','ReservedItem.txt','NANDReserved.dmp','NANDP1.dmp','NANDPartition.txt','BootNANDBase.dmp','BFNSetting.txt','NIKON001.DSC'}
    assert required<=contents.keys()
    original=ORIGINAL.read_bytes();assert sha(original)==EXPECTED
    candidate_path=ROOT/'Risultati/Firmware_sperimentali/SD/S33_MODIFICA_SD_SPERIMENTALE_NON_INSTALLARE.bin'
    candidate=candidate_path.read_bytes();assert sha(candidate)=='ce504526dcb1ebffab33f17bf1467fd03f70b01c5393ad03812523f978b3e8c9'
    tbm_start,tbm_size=struct.unpack_from('<II',candidate,0x480ac)
    tbib_start,tbib_size=struct.unpack_from('<II',original,0x60)
    res_marker=struct.unpack_from('<I',original,0x480b4)[0]
    res_start,res_size=struct.unpack_from('<II',original,res_marker+0x40)
    main=contents['MainCode.dmp'];boot=contents['BootCode.dmp'];reserved=contents['NANDReserved.dmp']
    assert main[:tbm_size]==candidate[tbm_start:tbm_start+tbm_size]
    assert len(main)>tbm_size and set(main[tbm_size:])=={255}
    assert boot[:tbib_size]==original[tbib_start:tbib_start+tbib_size] and set(boot[tbib_size:])=={255}
    tbib_base,tbib_length,tbib_sum,tbib_entry=struct.unpack_from('<4I',boot)
    assert sum32(boot[16:16+tbib_length])==tbib_sum
    assert reserved[512:512+res_size]==original[res_start:res_start+res_size]
    block_checks=[]
    for b in BS:
        offset,size=b['offset'],b['size'];data=main[offset:offset+size]
        assert data==candidate[tbm_start+offset:tbm_start+offset+size]
        assert sum32(data)==struct.unpack_from('<I',main,0x10+16*b['index']+12)[0]
        block_checks.append(dict(index=b['index'],size=size,sha256=sha(data),matches_candidate=True,matches_original=data==PS[b['index']]))
    header,complement=struct.unpack_from('<II',main,0x1f4)
    assert main[:4]==b'RHIR' and main[0x1f0:0x1f4]==b'KHIR'
    assert header==sum32(main[:0x1f0]) and complement==((~header)&0xffffffff)
    assert contents['Calibration.dmp']==contents['Calibration_2.dmp']
    assert contents['CameraParam.dmp']==contents['CameraParam_2.dmp']
    assert contents['NIKON001.DSC']==b' '*512
    declared={key:int(value,16) for key,value in re.findall(r'(\w+)\s*=\s*(0x[0-9a-fA-F]+)',contents['NANDPartition.txt'].decode('ascii'))}
    size_fields={'BootCode.dmp':'uwSize_BootCode','Calibration.dmp':'uwSize_Calibration','CameraParam.dmp':'uwSize_CameraPara',
                 'NANDReserved.dmp':'uwSize_Reserved','MainCode.dmp':'uwSize_HexMain'}
    assert all(len(contents[name])==declared[key]*0x4000 for name,key in size_fields.items())
    item_text=[(int(i),int(n)) for i,n in re.findall(r'id: (\d+), size: (\d+)',contents['CalibrationItem.txt'].decode('ascii'))]
    cal=contents['Calibration.dmp'];assert cal.startswith(b'InfoMgr ID\0')
    count=struct.unpack_from('<H',cal,0x68)[0];offset=0x6c;items=[]
    for index in range(count):
        assert offset+8<=len(cal)
        ident,padding,size=struct.unpack_from('<HHI',cal,offset);assert padding==0xffff and offset+8+size<=len(cal)
        items.append(dict(id=ident,size=size,record_offset=hex(offset),data_offset=hex(offset+8),data_sha256=sha(cal[offset+8:offset+8+size])))
        offset+=8+((size+3)&~3)
    assert [(r['id'],r['size']) for r in items]==item_text and count==16
    reserved_items=[dict(id=int(i,16),start_sector=int(s),size=int(n)) for i,s,n in re.findall(r'id: (0x[0-9a-fA-F]+), start: (\d+), size: (\d+)',contents['ReservedItem.txt'].decode('ascii'))]
    assert len(reserved_items)==6 and reserved_items[:3]==reserved_items[3:]
    for item in reserved_items:
        item['byte_offset']=item['start_sector']*512
        assert item['byte_offset']+item['size']<=len(reserved)
    assert reserved_items[1]['byte_offset']==512 and reserved_items[1]['size']>=res_size
    config={key:int(value,16) for key,value in re.findall(r'(\w+)\s*=\s*(0x[0-9a-fA-F]+)',contents['BFNSetting.txt'].decode('ascii'))}
    assert config['DDR_SIZE_ID_Variable_09']==0x120
    nand=contents['NANDP1.dmp'];assert len(nand)%2112==0
    packed=b''.join(nand[i:i+2048] for i in range(0,len(nand),2112))
    offsets={}
    for name in ['BootCode.dmp','Calibration.dmp','CameraParam.dmp']:
        found=packed.find(contents[name]);assert found>=0
        offsets[name]=dict(data_projection_offset=hex(found),length=len(contents[name]),full_match=True)
    # The boot base uses a distinct observed packing at the beginning; do not apply this globally.
    base=contents['BootNANDBase.dmp'];boot_base=b''.join(nand[i:i+512] for i in range(0,16*528,528))
    assert len(base)==8192 and boot_base==base
    main_at=0x1240000;main_prefix=0x6c0000
    assert packed[main_at:main_at+main_prefix]==main[:main_prefix]
    assert packed[main_at+main_prefix:main_at+main_prefix+512]!=main[main_prefix:main_prefix+512]
    reserved_at=0x23a0000;reserved_prefix=0x4c0000
    assert packed[reserved_at:reserved_at+reserved_prefix]==reserved[:reserved_prefix]
    windows=[(0x3000e8,0x30017c),(0x1ed37c,0x1ed3fc),(0x1ed3f4,0x1ed440)]
    (out/'gnu_verified.txt').write_text('\n'.join(disasm(a,b) for a,b in windows))
    categories={
        'MainCode.dmp':('01_programma_principale','Contenitore TBM/RHIR installato: identico al candidato SD; coda FF di capacità partizione.','alta'),
        'BootCode.dmp':('02_avvio','TBIB originale completo, header e somma validi; coda FF. Non include da solo il boot NAND iniziale.','alta'),
        'BootNANDBase.dmp':('02_avvio','Base di avvio NAND, distinta da TBIB; 8192byte ricostruiti dalle prime sottounità del NANDP1.','alta per identità; esecuzione non verificata'),
        'Calibration.dmp':('03_calibrazioni','Archivio InfoMgr:16record con ID/dimensione corrispondenti a CalibrationItem.txt. Significato dei valori non decodificato.','alta per struttura'),
        'Calibration_2.dmp':('03_calibrazioni','Duplicato esatto di Calibration.dmp; il nome non prova una seconda banca fisica.','alta'),
        'CalibrationItem.txt':('03_calibrazioni','Indice testuale dei16record di calibrazione; coincide con il binario.','alta'),
        'CameraParam.dmp':('04_parametri_fotocamera','Area persistente parametri con header InfoMgr ID e nomi ADC/KEY_SCAN/StereoCali/EFA; schema interno non interamente decodificato.','alta per identità archivio; semantica parziale'),
        'CameraParam_2.dmp':('04_parametri_fotocamera','Duplicato esatto di CameraParam.dmp; origine fisica della copia non dimostrata.','alta'),
        'NANDReserved.dmp':('05_risorse_riservate','Area riservata con metadati e P1RES originale completo a offset512; contiene risorse software, non soltanto byte liberi.','alta'),
        'ReservedItem.txt':('05_risorse_riservate','Indice di3item ripetuti due volte: header512, area18MiB, item finale512; start in settori512 coerenti.','alta per tabella; tipi ID non decodificati'),
        'NANDP1.dmp':('06_export_nand','Esportazione NANDP1 con20736record da2112byte; lettore incrementa il buffer di2112. Dati aggiuntivi e rimappatura/ECC non decodificati.','alta per stride e corrispondenze; copertura fisica ignota'),
        'NANDPartition.txt':('07_configurazione_memoria','Dimensioni dichiarate di5aree, coerenti con i dump in unità16KiB; ProductID6113 e partition version1009. Non è una mappa RAM.','alta per contenuto e rapporti dimensionali'),
        'BFNSetting.txt':('07_configurazione_memoria','Impostazioni BFN per DDR e clock/PLL, comprese DDR_SIZE_ID=0120 e versioni. ID e divisori non sono capacità o frequenze già decodificate.','alta per campi; interpretazione hardware parziale'),
        'NIKON001.DSC':('08_segnaposto','512spazi ASCII e nessun altro contenuto; non è un JPEG o un dump di stato informativo. Scopo non dimostrato.','alta per byte; scopo ignoto')}
    rows=[];groups=defaultdict(list)
    for name,data in contents.items():
        category,description,confidence=categories.get(name,('99_non_identificato','File aggiuntivo da analizzare.','ignota'))
        digest=sha(data);groups[digest].append(name)
        rows.append(dict(file=name,category=category,size=len(data),sha256=digest,confidence=confidence,description=description,head_hex=data[:32].hex()))
    result=dict(status='PASS_CLASSIFICATION_AND_BYTE_RELATIONSHIPS',source=str(source.relative_to(ROOT)),files=rows,
        duplicate_groups=[names for names in groups.values() if len(names)>1],
        installed_main=dict(tbm_bytes=tbm_size,sha256=sha(main[:tbm_size]),candidate_path=str(candidate_path.relative_to(ROOT)),candidate_sha256=sha(candidate),
            matches_candidate_tbm=True,ff_padding_bytes=len(main)-tbm_size,blocks=block_checks,khir_valid=True),
        boot=dict(matches_original_tbib=True,tbib_bytes=tbib_size,body_bytes=tbib_length,base=hex(tbib_base),entry=hex(tbib_entry),sum_valid=True,ff_padding_bytes=len(boot)-tbib_size),
        resources=dict(matches_original_p1res=True,dump_offset=512,size=res_size,sha256=sha(reserved[512:512+res_size]),items=reserved_items),
        calibration=dict(items=items,count=count,end_exclusive=hex(offset),matches_text_index=True),
        partitions=dict(fields=declared,derived_size_unit=0x4000,size_fields=size_fields),bfn_settings=config,
        nand=dict(record_stride=2112,record_count=len(nand)//2112,data_projection_bytes=len(packed),projection='2048data +64additional bytes per record; no ECC or bad-block correction',
            exact_full_matches=offsets,boot_base_matches_first_16_subunits_512_of_528=True,
            main_projection_prefix=dict(offset=hex(main_at),matching_bytes=main_prefix,diverges_after=True),
            resources_projection_prefix=dict(offset=hex(reserved_at),matching_bytes=reserved_prefix,diverges_after=True)),
        original_firmware_sha256=EXPECTED,script_sha256=sha(Path(__file__).read_bytes()),gnu_windows=len(windows),
        limits=['Classifies supplied files; the acquisition process and physical completeness are not independently observed',
            'No full raw NAND reconstruction, ECC, bad-block map or restore procedure verified',
            'Matching installed TBM proves bytes in the supplied dump; does not measure runtime ownership or full boot',
            'No RAM dump identified among these exports; DDR_SIZE_ID0120 is not a decoded capacity',
            'Calibration values and camera parameter semantics remain mostly undecoded',
            'REA signature scan unavailable because caller-supplied Binwalk command is not configured; direct byte/structure checks used',
            'No dump modified, camera command issued, GNU tree modified or flash image rebuilt'])
    assert all((source/name).read_bytes()==data for name,data in contents.items())
    assert ORIGINAL.read_bytes()==original and candidate_path.read_bytes()==candidate
    view=out.parent/'Categorie'
    for row in rows:
        link=view/row['category']/row['file'];link.parent.mkdir(parents=True,exist_ok=True)
        if link.is_symlink():assert link.resolve()==source/row['file']
        else:
            assert not link.exists()
            link.symlink_to(os.path.relpath(source/row['file'],link.parent))
        assert link.resolve()==source/row['file'] and sha(link.read_bytes())==row['sha256']
    result['categorized_view']=str(view.relative_to(ROOT))
    result['categorized_view_is_links_not_independent_backups']=True
    (out/'classifier.py.snapshot').write_bytes(Path(__file__).read_bytes())
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    with (out/'catalogo.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=['file','category','size','sha256','confidence','description']);writer.writeheader()
        writer.writerows({k:r[k] for k in writer.fieldnames} for r in rows)
    (out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT)),'catalog':str((out/'catalogo.csv').relative_to(ROOT))},indent=2)+'\n')
    print('PASS:',len(rows),'files classified;16TBM sums,TBIB,P1RES,16calibration records,5partition sizes,duplicates and NAND relationships;input unchanged;',out)


if __name__=='__main__':main()
