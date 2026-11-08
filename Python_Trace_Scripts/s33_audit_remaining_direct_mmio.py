#!/usr/bin/env python3
"""Independently bind completed MMIO accesses to original bytes and full-run traces."""
import argparse,hashlib,json,re
from pathlib import Path

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args()
    src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_REMAINING_DIRECT_MMIO_ORIGINAL_PATHS'
    assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items())
    fw=Path(__file__).resolve().parents[1]/'OriginalSoftware_NikonS33_V1.1/firmware.bin';raw=fw.read_bytes();info=d['payload'];body=Path(info['path']).read_bytes();base=info['base'];off=info['firmware_offset']
    assert body==raw[off:off+info['size']] and sha(Path(info['path']))==info['sha256']
    inputs={str(p):sha(p) for p in [Path(__file__),fw,src/'verified_evidence.json',src/'original_windows.txt']};instructions={}
    for line in (src/'original_windows.txt').read_text().splitlines():
        m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
        if not m:continue
        pc=int(m[1],16);b=b''.join(bytes.fromhex(w)[::-1] for w in m[2].split());assert body[pc-base:pc-base+len(b)]==b
        instructions[pc]=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=b.hex(),firmware_offset=off+pc-base)
    checks=[];addresses=set();total=0
    for c in d['cases']:
        if not c['observer_enabled']:continue
        events=c['completed_memory_events'];pcs={e['pc'] for e in events};path=src/(c['name']+'.trace');inputs[str(path)]=sha(path)
        trace=[]
        for line in path.read_text().splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
            if m and int(m[1],16) in pcs:trace.append((int(m[1],16),'read' if m[2].startswith('ld') else 'write',int(m[3],16)&65535))
        assert len(trace)==len(events),(c['name'],trace,events)
        for row,e in zip(trace,events):
            assert row==(e['pc'],e['operation'],e['value']) and e['width_bytes']==2
            insn=instructions[e['pc']];assert insn['opcode']==('ldh.di' if e['operation']=='read' else 'sth.di')
            assert int(re.search(r'\[(0x[0-9a-f]+)\]',insn['operands'])[1],16)==e['address']
            addresses.add(e['address']);total+=1
        reference=c['name'].replace('_observed','_reference');assert path.read_bytes()==(src/(reference+'.trace')).read_bytes()
        assert c['full_selected_path_completed'] and c['exit_code']==0
        checks.append(dict(case=c['name'],events=len(events),trace_rows=len(trace),trace_records_per_event=1,selected_original_path_completed=True))
    assert len(checks)==10 and total==18 and addresses=={0xfef000c,0xfef0050,0xfef00e8,0xfef00f8,0xfef0328}
    assert len(d['pairs'])==10 and all(p['trace_identical'] for p in d['pairs'])
    result=dict(status='PASS_REMAINING_DIRECT_MMIO_BYTES_AND_TRACE_AUDIT',date='2026-10-25',checks=checks,addresses=list(map(hex,sorted(addresses))),completed_memory_events=total,
        independently_bound_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,
        limits=['Full-run traces have one result per observed transfer here; earlier step-run duplicate rule does not apply.',
                'Software bit0 RMW does not prove W1C/IRQ acknowledgement or hardware access permissions.',
                'Synthetic ilink/context/vector base and saved stack allow selected original paths; no physical interrupt dispatch verified.'])
    assert all(sha(Path(p))==h for p,h in inputs.items());args.output.write_text(json.dumps(result,indent=2)+'\n')
    print('PASS five addresses,18 completed events,ten byte-identical pairs; original bytes and transfer widths bound')
if __name__=='__main__':main()
