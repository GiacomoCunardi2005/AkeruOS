#!/usr/bin/env python3
"""Audit FE6 effective addresses against original opcodes, caller domain and trace."""
import argparse,hashlib,json,re
from pathlib import Path
from collections import Counter

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FE6_COMPUTED_ACCESSOR_DOMAINS'
    assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items())
    info=d['payload'];fw=Path(__file__).resolve().parents[1]/'OriginalSoftware_NikonS33_V1.1/firmware.bin';raw=fw.read_bytes();body=Path(info['path']).read_bytes();assert body==raw[info['firmware_offset']:info['firmware_offset']+info['size']]
    inputs={str(p):sha(p)for p in [fw,Path(__file__),src/'verified_evidence.json',src/'original_windows.txt']};instructions={}
    for line in (src/'original_windows.txt').read_text().splitlines():
        m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
        if not m:continue
        pc=int(m[1],16);b=b''.join(bytes.fromhex(w)[::-1] for w in m[2].split());assert body[pc-info['base']:pc-info['base']+len(b)]==b
        instructions[pc]=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=b.hex(),firmware_offset=info['firmware_offset']+pc-info['base'])
    # Byte-bound software bounds and transforms, not a physical bank definition.
    for pc,op,arg in [(0x2c5db0,'cmp_s','r13,0x20'),(0x2c5db6,'cmp_s','r13,0x33'),(0x2c5dc8,'cmp_s','r13,0x40'),(0x2c5dce,'cmp_s','r13,0x43'),(0x2c5dbe,'asl_s','r13,r13,0x4'),(0x2c5dd8,'asl_s','r13,r13,0x4'),(0x2c5da4,'or_s','r0,r0,r1'),(0x2c5ea6,'bset','r10,r10,r2'),(0x2c5ed2,'bclr','r10,r10,r2'),(0x2c5ea0,'mov_s','r2,0x8'),(0x2c5f16,'and','r0,r0,512')]:
        assert instructions[pc]['opcode']==op and instructions[pc]['operands']==arg,(hex(pc),instructions[pc])
    domain=list(range(32,52))+list(range(64,68));cells={0xfe60000+16*s+off for s in domain for off in [0,4,8,12]};assert len(cells)==96
    checks=[];addresses=set();total=0;counts=Counter()
    for c in d['cases']:
        if not c['observer_enabled']:continue
        events=c['completed_memory_events'];pcs={e['pc']for e in events};path=src/(c['name']+'.trace');inputs[str(path)]=sha(path);rows=[]
        for line in path.read_text().splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
            if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
        assert len(rows)==len(events)
        for row,e in zip(rows,events):
            assert row==(e['pc'],e['operation'],e['value'])and e['width_bytes']==2
            insn=instructions[e['pc']];assert insn['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
            assert e['address']in cells;addresses.add(e['address']);total+=1;counts[hex(e['address'])]+=1
        assert c['exit_code']==0 and c['full_selected_paths_completed']
        ref=src/(c['name'].replace('_observed','_reference')+'.trace');assert ref.read_bytes()==path.read_bytes()
        # Bound each observed group to its declared selector and original routine.
        cursor=0
        for call in c['original_calls']:
            selector=int(call['arguments'][0],0);expected=call['expected_events'];actual=events[cursor:cursor+len(expected)]
            assert [(e['pc'],e['operation'],e['address'],e['value'])for e in actual]==[tuple(e)for e in expected]
            cursor+=len(expected)
            if selector not in domain:assert not expected
            else:
                origin=0xfe60000+16*selector
                assert all(origin<=e['address']<=origin+12 and (e['address']-origin)%4==0 for e in actual)
            if int(call['entry'],0)==0x2c5f74:assert len(expected)==int(selector==41)
        assert cursor==len(events)
        if c['scenario']=='invalid':assert not events and len(c['original_calls'])==64
        else:assert len(events)==265 and len(c['original_calls'])==192
        checks.append(dict(case=c['name'],events=len(events),original_calls=len(c['original_calls']),trace_results_per_event=1,valid_domain_or_negative_boundaries=True))
    assert addresses==cells and total==530 and len(checks)==3
    assert len(d['pairs'])==3 and all(p['trace_identical']for p in d['pairs'])
    result=dict(status='PASS_FE6_EFFECTIVE_ADDRESS_AND_BYTE_AUDIT',date='2026-10-25',checks=checks,addresses=list(map(hex,sorted(addresses))),completed_memory_events=total,per_address_events=dict(counts),independently_bound_instructions={hex(k):v for k,v in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=['Exhaustive over the24 bounded selector inputs of these original accessors, not all firmware/SoC or real caller values.','MMIO seeds and caller operands are explicit fixtures; no physical reset, IRQ, timing or cache side effect proof.','The helper that sets bit8 and getter that masks bit9 are recorded separately.'])
    assert all(sha(Path(p))==h for p,h in inputs.items());args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS96 effective addresses,530 events,3 byte-identical pairs; bounded24 selectors and8 negatives')
if __name__=='__main__':main()
