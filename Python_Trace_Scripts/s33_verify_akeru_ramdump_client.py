#!/usr/bin/env python3
"""Verify the offline AkeruRAM client, synthetic server and CLI artifacts."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zlib
ROOT=Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    out=ROOT/'Risultati/AkeruUSB_RAM_Debug/Client'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False);print('Evidence:',out,flush=True)
    sources=[Path(__file__)]+[ROOT/'Python_Trace_Scripts'/name for name in
        ['akeru_ramdump.py','test_akeru_ramdump.py','akeru-ramdump']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())

    def run(name,args):
        cmd=[sys.executable,*map(str,args)]
        (out/(name+'.command.json')).write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60)
        (out/(name+'.log')).write_text(r.stdout)
        assert r.returncode==0,r.stdout[-4000:]
        return r.stdout

    tests=run('unit',['-m','unittest','discover','-s','Python_Trace_Scripts','-p','test_akeru_ramdump.py','-v'])
    assert 'Ran 21 tests' in tests and tests.strip().endswith('OK')
    cli=ROOT/'Python_Trace_Scripts/akeru-ramdump'
    for name in ['info','map','status','abort']:
        json.loads(run('cli_'+name,[cli,'--simulate','--'+name]))
    image=out/'synthetic_ram.bin'
    run('cli_dump',[cli,'--simulate','--dump','--output',image])
    before=image.read_bytes()
    run('cli_resume',[cli,'--simulate','--dump','--output',image,'--resume'])
    assert image.read_bytes()==before
    report=json.loads(image.with_name(image.name+'.json').read_text())
    assert report['complete'] and report['identity']['synthetic'] and not report['identity']['full_map']
    assert report['identity']['regions']==[[0x1000,9000],[0x8000,513]]
    expected=b''.join(bytes((address^(address>>8))&255 for address in range(a,a+n))
        for a,n in [(0x1000,9000),(0x8000,513)])
    assert before==expected and len(before)==9513 and len(report['blocks'])==4
    for block in report['blocks']:
        data=before[block['offset']:block['offset']+block['length']]
        assert block['status']==0 and f'{zlib.crc32(data):08x}'==block['crc32']
    assert all(sha((ROOT/p).read_bytes())==digest for p,digest in inputs.items())
    result=dict(status='PASS_AKERURAM_V1_CLIENT_AND_SYNTHETIC_DEVICE',unit_tests=21,
        cli_runs=6,synthetic_ram_bytes=9513,blocks=4,synthetic_sha256=sha(before),sources=inputs,
        hardware_tested=False,firmware_service_integrated=False,installable=False,
        limits=['Simulator is a Python bulk byte-stream model, not a USB device/gadget or ARC firmware',
            'PyUSB selection/claim/packet-buffer path tested with fake API; no physical USB transactions',
            'New wire protocol design, not an existing Nikon protocol; firmware C implementation and endpoint binding pending',
            'Resume checks epoch/map/capabilities and all committed block CRCs; preserves unexplained trailing bytes by refusing resume',
            'Live RAM snapshots non-atomic; synthetic map is not physical Nikon RAM; NON_INSTALLARE'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print(result['status'],out)


if __name__=='__main__':main()
