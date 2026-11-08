#!/usr/bin/env python3
"""Independent byte/trace/domain audit for the second FE6 bank."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);a=ap.parse_args();src=a.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FE6_SECOND_BANK_AND_ORIGINAL_CALLER'
    assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items())
    fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';info=d['payload'];body=Path(info['path']).read_bytes();assert body==fw.read_bytes()[info['firmware_offset']:info['firmware_offset']+info['size']]
    inputs={str(p):sha(p)for p in [Path(__file__),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
    def decode(pc):
        if pc in instructions:return instructions[pc]
        text=aligned_window(body,info['base'],pc,pc+8)
        m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)for line in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+r':',line))
        raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert body[pc-info['base']:pc-info['base']+len(raw)]==raw
        i=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);instructions[pc]=i;return i
    for pc,op,arg in [(0x2c6764,'cmp_s','r0,0x34'),(0x2c676a,'cmp_s','r0,0x3d'),(0x2c677c,'cmp_s','r0,0x44'),(0x2c6782,'cmp_s','r0,0x4c'),(0x2c6772,'asl_s','r0,r0,0x4'),(0x2c678c,'asl_s','r0,r0,0x4'),(0x2c6774,'add_s','r0,r0,0xfe64340'),(0x2c678e,'add_s','r0,r0,0xfe64440'),(0x2c6854,'mov_s','r2,0x8'),(0x2c68ca,'and','r0,r0,512'),(0x2c692a,'cmp_s','r0,0x4a'),(0x2c6932,'cmp_s','r0,0x4c')]:assert decode(pc)['opcode']==op and decode(pc)['operands']==arg
    for pool,value in [(0x2c693c,0xfe644a8),(0x2c6940,0xfe644c8)]:assert struct.unpack_from('<I',body,pool-info['base'])[0]==value
    domain=list(range(52,62))+list(range(68,77));cells={0xfe64000+16*s+off for s in domain for off in [0,4,8,12]};ids={0xfef0020,0xfe800bc,0xfed3000,0xfed3800}
    checks=[];seen=set();total=0;domain_cells=set()
    for c in d['cases']:
        if not c['observer_enabled']:continue
        events=c['completed_memory_events'];pcs={e['pc']for e in events};path=src/(c['name']+'.trace');inputs[str(path)]=sha(path);rows=[]
        for line in path.read_text().splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
            if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
        assert len(rows)==len(events)
        for row,e in zip(rows,events):
            assert row==(e['pc'],e['operation'],e['value'])and e['width_bytes']==2
            assert decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di');assert e['address']in cells|ids
            if e['address']in cells:domain_cells.add(e['address'])
            seen.add(e['address']);total+=1
        assert c['exit_code']==0 and c['full_selected_paths_completed'];assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        cursor=4 if c['original_caller']else 0
        for call in c['original_calls']:
            s=int(call['arguments'][0],0);expected=call['expected_events'];actual=events[cursor:cursor+len(expected)]
            assert [(e['pc'],e['operation'],e['address'],e['value'])for e in actual]==[tuple(e)for e in expected];cursor+=len(expected)
            if s not in domain:assert not expected
            else:assert all(0xfe64000+16*s<=e['address']<=0xfe64000+16*s+12 and e['address']%4==0 for e in actual)
            if int(call['entry'],0)==0x2c6928:assert len(expected)==int(s in [74,76])
        assert cursor==len(events)
        if c['original_caller']:
            assert len(c['original_calls'])==19 and len(events)==118
            cache=bytes.fromhex(c['fixtures']['0x423f00']['after']);assert struct.unpack_from('<I',cache,8)[0]==0x20002
            assert sum(e['pc']==0x2c6794 for e in events)==19
        elif c['scenario']=='invalid':assert not events and len(c['original_calls'])==64
        else:assert len(events)==211 and len(c['original_calls'])==152
        checks.append(dict(case=c['name'],events=len(events),original_calls=len(c['original_calls']),original_higher_caller=c['original_caller'],trace_results_per_event=1))
    assert seen==cells|ids and domain_cells==cells and len(cells)==76 and total==540 and len(checks)==4
    assert len(d['pairs'])==4 and all(p['trace_identical']for p in d['pairs'])
    result=dict(status='PASS_FE6_SECOND_BANK_BYTE_TRACE_DOMAIN_AUDIT',date='2026-10-25',checks=checks,new_domain_addresses=list(map(hex,sorted(cells))),distinct_observed_addresses=80,completed_memory_events=total,original_higher_caller_invocations=19,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=['These19 selectors are the bounded software domain, not a physical count or proof of actual Nikon runtime arguments.','Original higher caller completes because bit9 is explicitly seeded; bit8 writes do not demonstrate hardware completion.','Mode producer uses declared raw/flag/cache fixture inputs; no physical identity or mode inferred.'])
    assert all(sha(Path(p))==h for p,h in inputs.items());a.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS76 domain addresses,540events,4pairs,19higher original calls')
if __name__=='__main__':main()
