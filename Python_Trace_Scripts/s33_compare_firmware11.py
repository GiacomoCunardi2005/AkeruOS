#!/usr/bin/env python3
"""Compare every byte and primary listing row of the verified CMP3/CMP1 images."""
from pathlib import Path
from itertools import zip_longest
import hashlib
import json
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'Ghidra_Results/ghidra_reports/firmware11_comparison'
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from audit_patch import audit
from s33_disassemble_firmware11 import ROW, OUTPUT


def listing_rows(path,data,state):
    state.update(offset=0,rows=0,hash=hashlib.sha256())
    with path.open(encoding='utf-8') as stream:
        for lineno,line in enumerate(stream,1):
            state['hash'].update(line.encode('utf-8'))
            if not line.startswith('F'):continue
            m=ROW.match(line.rstrip('\n'));assert m,(path,lineno)
            pos=int(m[1],16);value=bytes.fromhex(m[3])
            assert pos==state['offset'] and value==data[pos:pos+len(value)],(path,lineno)
            state['offset']+=len(value);state['rows']+=1
            yield dict(line=lineno,offset=pos,va=m[2],bytes=value,assembly=m[4],text=line.rstrip('\n'))
    assert state['offset']==len(data)


def main():
    OUT.mkdir(exist_ok=True,parents=True)
    audit_result=audit()
    (OUT/'patch_audit.json').write_text(json.dumps(audit_result,indent=2)+'\n')
    manifests=[json.loads((ROOT/'Ghidra_Results/ghidra_reports'/name/'verified_evidence.json').read_text())
               for name in ['firmware11_full','firmware11_cmp1_full']]
    for meta,variant in zip(manifests,['CMP3','CMP1']):assert meta['variant']==variant
    data=[Path(m['input']['path']).read_bytes() for m in manifests]
    changes=[];rows=0;states=[{},{}]
    for left,right in zip_longest(listing_rows(Path(manifests[0]['output']['path']),data[0],states[0]),
                                 listing_rows(Path(manifests[1]['output']['path']),data[1],states[1])):
        assert left is not None and right is not None
        assert (left['offset'],left['va'],len(left['bytes']))==(right['offset'],right['va'],len(right['bytes']))
        rows+=1
        if left['bytes']!=right['bytes'] or left['assembly']!=right['assembly']:
            changes.append(dict(file_offset=hex(left['offset']),va=left['va'],
                                cmp3_line=left['line'],cmp1_line=right['line'],
                                cmp3_bytes=left['bytes'].hex(' '),cmp1_bytes=right['bytes'].hex(' '),
                                cmp3_assembly=left['assembly'],cmp1_assembly=right['assembly']))
    assert rows==manifests[0]['output']['rows']==manifests[1]['output']['rows']
    for state,meta in zip(states,manifests):
        assert state['hash'].hexdigest()==meta['output']['sha256']
        assert hashlib.sha256(data[manifests.index(meta)]).hexdigest()==meta['input']['sha256']
    assert len(changes)==3,changes
    instructions=[r for r in changes if not r['cmp3_assembly'].startswith('.byte ')]
    assert len(instructions)==1
    assert instructions[0]['file_offset']=='0xcfeae' and instructions[0]['va']=='001353F6'
    assert instructions[0]['cmp3_assembly']=='cmp_s\tr0,0x3' and instructions[0]['cmp1_assembly']=='cmp_s\tr0,0x1'
    region_pairs=[]
    for left,right in zip_longest(manifests[0]['regions'],manifests[1]['regions']):
        assert left is not None and right is not None
        for key in ['name','start','end','base','rows','candidate_rows','undecoded_bytes']:
            assert left[key]==right[key],(left['name'],key)
        region_pairs.append(dict(name=left['name'],file_start=hex(left['start']),file_end=hex(left['end']),
                                 cmp3_sha256=left['sha256'],cmp1_sha256=right['sha256'],
                                 identical=left['sha256']==right['sha256']))
    assert [r['name'] for r in region_pairs if not r['identical']]==['DATA_00044C38','TBM_00']
    diff_path=OUTPUT.with_name('Firmware1.1_CMP3_vs_CMP1.diff')
    with diff_path.open('w') as stream:
        proc=subprocess.run(['diff','-u','--label','CMP3/Firmware1.1.asm','--label','CMP1/Firmware1.1_CMP1.asm',
                              manifests[0]['output']['path'],manifests[1]['output']['path']],
                             stdout=stream,stderr=subprocess.PIPE,text=True,timeout=180)
    assert proc.returncode==1 and not proc.stderr,proc.stderr
    result=dict(scope='Complete binary and whole listing comparison; no boot/hardware execution',
                inputs={v:m['input'] for v,m in zip(['CMP3','CMP1'],manifests)},
                outputs={v:m['output'] for v,m in zip(['CMP3','CMP1'],manifests)},
                bytes_compared=len(data[0]),binary_changes=audit_result['changes'],
                primary_rows_compared=rows,primary_rows_changed=len(changes),
                primary_rows_identical=rows-len(changes),instruction_rows_changed=len(instructions),
                row_changes=changes,regions=region_pairs,
                diff=dict(path=str(diff_path),sha256=hashlib.sha256(diff_path.read_bytes()).hexdigest()),
                script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                limits=['Identical instructions do not imply identical dynamic reachability',
                        'Linear assembly candidates are not an exhaustive executable CFG',
                        'Checksum agreement and byte equality do not prove surviving reset recovery'])
    (OUT/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    print(f'PASS: {len(data[0]):,} bytes and {rows:,} listing rows compared;4 byte differences,3 primary rows,1 instruction; all other regions identical')
    for r in changes:print(json.dumps(r))

if __name__=='__main__':main()
