#!/usr/bin/env python3
"""Check raw BL target extraction against retained original-code GNU execution."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from s33_verify_custom_aux_cfg import call_at


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('atlas',type=Path);ap.add_argument('output',type=Path)
    args=ap.parse_args();atlas=args.atlas.resolve();out=args.output.resolve()
    source=atlas/'evidence/firmware_aux_trace.json';trace=json.loads(source.read_text())
    firmware_path=Path(trace['firmware_path']);fw=firmware_path.read_bytes();assert sha(firmware_path)==trace['firmware_sha256']
    inputs={str(p):sha(p)for p in [source,firmware_path,Path(__file__),Path(__file__).with_name('s33_verify_custom_aux_cfg.py')]}
    checks=[];forms=Counter();runs=[]
    pattern=re.compile(r'^(0x[0-9a-f]+)\s+(bl(?:\.d|_s)?)\s+.*?pc <- (0x[0-9a-f]+)')
    for run in trace['runs']:
        segments=run.get('original_firmware_segment_identity')
        if not segments:continue
        path=Path(run['path']);assert sha(path)==run['sha256'];inputs[str(path)]=sha(path);count=0
        with path.open()as handle:
            for lineno,line in enumerate(handle,1):
                m=pattern.match(line)
                if not m:continue
                pc,target=int(m[1],16),int(m[3],16)
                segment=next((s for s in segments if s['address']<=pc and pc+4<=s['address']+s['size']),None)
                assert segment is not None,(run['name'],hex(pc))
                offset=segment['firmware_offset']+pc-segment['address']
                actual=call_at(fw,offset,pc-offset)
                assert actual and actual['target']==target,(run['name'],lineno,m[0],actual)
                checks.append(dict(run=run['name'],trace_line=lineno,pc=hex(pc),target=hex(target),
                                   encoding=actual['encoding'],original_bytes=fw[offset:offset+actual['size']].hex(),
                                   firmware_offset=offset,evidence='guest_branch_pc_semantic_result'))
                forms[actual['encoding']]+=1;count+=1
        runs.append(dict(name=run['name'],records=count,trace=str(path),sha256=sha(path)))
    assert checks and forms['bl_s'] and forms['bl_simm25']
    assert all(sha(Path(p))==h for p,h in inputs.items())
    result=dict(status='PASS_RAW_BL_DECODER_GUEST_CROSSCHECK',date='2026-10-25',runs=runs,
                records=len(checks),distinct_pc=len({(c['run'],c['pc'])for c in checks}),encodings=dict(forms),checks=checks,
                input_sha256=inputs,hardware_access=False,gnu_modified=False,
                limits=['Reuses retained byte-bound original firmware guest traces; no new hardware execution.',
                        'Branch PC semantic results validate extraction for this corpus, not all possible BL encodings.',
                        'This does not turn raw BL-shaped data or LIMM halfwords into executable calls.'])
    out.write_text(json.dumps(result,indent=2)+'\n');print({k:v for k,v in result.items()if k in ['status','records','distinct_pc','encodings']})


if __name__=='__main__':main()
