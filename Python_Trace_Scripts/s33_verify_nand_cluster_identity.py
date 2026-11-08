#!/usr/bin/env python3
"""Cross-check the cluster previously called lens wire against original NAND users."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, re, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, u32, disasm


def main():
    out=ROOT/'Risultati/Storage/NAND_Cluster_Identity'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    assert raw(0x376170,9)==b'DEVNAND:\0'
    assert u32(0x37619c)==0x168f24
    spans=[(0x168f24,0x168f90),(0x168eac,0x168f24),(0x168cec,0x168db0),(0x168bbc,0x168c68),
           (0x1ecb0c,0x1ecba4),(0x12ad58,0x12adf0),(0x1eea4c,0x1eeab4),(0x1ee982,0x1ee994),
           (0x25f338,0x25f3f4),(0x29ddd4,0x29de78)]
    listing=''.join(disasm(a,b) for a,b in spans)
    edges={0x168f76:0x168eac,0x168f18:0x168cec,0x168d3a:0x168bbc,0x168c1e:0x25f338,
           0x1ecb52:0x25f338,0x12ad9c:0x1eea4c,0x12adbc:0x1ecd6c,0x1eeaa4:0x1ee730,0x1ee990:0x1eded8}
    for site,target in edges.items():
        rows=[s for s in listing.splitlines() if re.match(rf'^\s*{site:x}:',s)]
        assert len(rows)==1 and f';0x{target:x}' in rows[0],(hex(site),hex(target),rows)
        assert re.search(r'\bbl(?:_s)?(?:\.d)?\s',rows[0]),rows[0]
    proof=ROOT/'Risultati/Dump_fotocamera/Partizioni_Logiche/20261020T155718Z/verified_evidence.json'
    old=json.loads(proof.read_text())
    assert old['status']=='PASS_COMPLETE_LOGICAL_PARTITION_EXPORT_RECONSTRUCTION'
    mapping=proof.with_name('partition_mapping.json')
    raw_path=ROOT/'DUMPS/NANDP1.dmp';nand=raw_path.read_bytes()
    assert any(Path(path).name=='NANDP1.dmp' and digest==hashlib.sha256(nand).hexdigest() for path,digest in old['input_hashes'].items())
    samples=[]
    for partition in json.loads(mapping.read_text()):
        if partition['file'] not in ['BootCode.dmp','MainCode.dmp','NANDReserved.dmp']:continue
        export=(ROOT/'DUMPS'/partition['file']).read_bytes()
        assert hashlib.sha256(export).hexdigest()==partition['sha256']
        first=partition['mapping'][0];assert not first['generated_FF']
        page=nand[first['physical']*64*2112:first['physical']*64*2112+2048]
        assert page==export[:2048]
        samples.append(dict(file=partition['file'],physical_group=first['physical'],logical=first['logical'],bytes=2048,sha256=hashlib.sha256(page).hexdigest()))
    assert len(samples)==3
    (out/'gnu_verified.txt').write_text(listing)
    (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
    result=dict(status='PASS_ORIGINAL_NAND_USERS_NOT_LENS_ATTRIBUTION',scope='Static original bytes; historical dump reconstruction is cited, not rerun',
        payload_hashes={str(b['index']):b['sha256'] for b in BS},windows=len(spans),
        raw_identity=dict(table='376168',name='DEVNAND:',callback_at='37619C',callback='168F24'),
        call_edges={hex(a):hex(b) for a,b in edges.items()},
        prior_reconstruction=dict(path=str(proof.relative_to(ROOT)),sha256=hashlib.sha256(proof.read_bytes()).hexdigest()),
        current_dump_samples=samples,nand_dump_sha256=hashlib.sha256(nand).hexdigest(),
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        conclusions=['Original DEVNAND callback reaches 25F338 through original branch/call sites',
                     'Original Main updater requests 1EEA4C and readback1ECD6C; 1EE730 nonzero selector uses1EDED8',
                     'Port and command bytes do not justify interpreting NAND data as lens coordinates or commands'],
        limits=['No hardware execution, electrical identification, or proof that a peripheral has no other use',
                'Static paths have runtime predicates; no claim that every call site executes in every mode',
                'Historical reconstruction not rerun; no new physical NAND reads or writes',
                'Separate iris GPIO and MCUCTRL service-request evidence not invalidated by this attribution audit'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print('PASS',out)


if __name__=='__main__':main()
