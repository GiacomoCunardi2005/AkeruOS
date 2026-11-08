#!/usr/bin/env python3
"""Bind step-frontend memory events to original bytes and audit trace duplicates."""
import argparse,hashlib,json,re
from pathlib import Path


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path)
    args=ap.parse_args();src=args.source.resolve();out=args.output.resolve();d=json.loads((src/'verified_evidence.json').read_text())
    assert d['status']=='PASS_DIRECT_MMIO_SEQUENCE_EXTERNAL_FIXTURES'
    assert all(sha(Path(p))==h for p,h in d['input_hashes'].items())
    assert all(sha(src/p)==h for p,h in d['files'].items())
    payload=Path(d['payloads']['0']['path']).read_bytes();base=d['payloads']['0']['base']
    fw=Path(__file__).resolve().parents[1]/'OriginalSoftware_NikonS33_V1.1/firmware.bin'
    raw=fw.read_bytes();off=d['payloads']['0']['firmware_offset'];assert payload==raw[off:off+len(payload)]
    inputs={str(p):sha(p)for p in [src/'verified_evidence.json',src/'original_sequence_disassembly.txt',fw,Path(__file__)]}
    instructions={}
    for line in (src/'original_sequence_disassembly.txt').read_text().splitlines():
        m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
        if not m:continue
        pc=int(m[1],16);b=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert payload[pc-base:pc-base+len(b)]==b
        instructions[pc]=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=b.hex(),firmware_offset=off+pc-base)
    checks=[];addresses=set();full_events=0;all_events=0
    for c in d['cases']:
        if not c['observer_enabled']:continue
        events=c['completed_memory_events'];pcs={e['pc']for e in events};path=src/(c['name']+'.trace');inputs[str(path)]=sha(path)
        trace=[];sign_extended=0
        for line in path.read_text().splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
            if not m or int(m[1],16)not in pcs:continue
            value=int(m[3],16);sign_extended+=int(value>0xffff)
            trace.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',value&0xffff))
        assert len(trace)==2*len(events)
        for i,e in enumerate(events):
            assert trace[2*i]==trace[2*i+1]==(e['pc'],e['operation'],e['value'])
            insn=instructions[e['pc']];assert insn['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
            assert e['width_bytes']==2
            operand=re.search(r'\[(0x[0-9a-f]+)\]',insn['operands'])
            if operand:assert int(operand[1],16)==e['address']
            else:assert e['pc']in [0x178f62,0x178f6c]and e['address']in [0xfe20144,0xfe2013c]
            addresses.add(e['address']);all_events+=1
            if c['full_routine_completed']:full_events+=1
        if c['full_routine_completed']:assert c['exit_code']==0
        else:assert c['exit_code']==75
        checks.append(dict(case=c['name'],memory_events=len(events),trace_memory_records=len(trace),
                           trace_records_per_event=2,sign_extended_trace_records=sign_extended,
                           memory_values_compared_at_proven_width_bits=16,profile_counter=c['instructions'],frontend_steps=c['step_stop']['steps'],
                           full_routine_completed=c['full_routine_completed']))
    assert len(addresses)==22 and full_events==483 and all_events==614
    assert all(p['trace_identical']for p in d['pairs'])and len(d['pairs'])==5
    result=dict(status='PASS_DIRECT_MMIO_BYTES_AND_STEP_TRACE_AUDIT',date='2026-10-25',checks=checks,
                addresses=list(map(hex,sorted(addresses))),positive_completed_memory_events=full_events,
                all_observed_memory_events=all_events,independently_bound_instructions={hex(k):v for k,v in instructions.items()},
                input_sha256=inputs,gnu_modified=False,hardware_access=False,
                limits=['Trace memory records are paired duplicates for each observed event; profile counters are not retirement counts.',
                        'Trace store operands may be sign-extended; compare low16 only after independent opcode/access-width proof.',
                        'Dynamic descriptor targets are synthetic caller data; all22 admitted addresses also have direct absolute original accesses.',
                        'Fixture transitions are explicitly separate from guest memory operations; physical timing, aliases and peripheral semantics unproved.'])
    assert all(sha(Path(p))==h for p,h in inputs.items())
    out.write_text(json.dumps(result,indent=2)+'\n');print('PASS22addresses,483positive/614total memoryevents; paired trace duplicates verified')


if __name__=='__main__':main()
