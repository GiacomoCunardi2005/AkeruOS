#!/usr/bin/env python3
"""Bind original mode/loop transfers to bytes, literals, trace order and selectors."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_verify_sensor_mmio_dialog import aligned_window

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path);args=ap.parse_args();src=args.source.resolve();d=json.loads((src/'verified_evidence.json').read_text());assert d['status']=='PASS_FE6_ORIGINAL_LOOP_AND_MODE_PRODUCER'
    assert all(sha(Path(p))==h for p,h in d['input_hashes'].items());assert all(sha(src/p)==h for p,h in d['files'].items())
    fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';info=d['payload'];body=Path(info['path']).read_bytes();assert body==fw.read_bytes()[info['firmware_offset']:info['firmware_offset']+info['size']]
    inputs={str(p):sha(p)for p in [Path(__file__),fw,src/'verified_evidence.json',ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']};instructions={}
    def decode(pc):
        if pc in instructions:return instructions[pc]
        text=aligned_window(body,info['base'],pc,pc+8)
        m=next(re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)for line in text.splitlines()if re.match(r'\s*'+f'{pc:x}'+r':',line))
        raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert body[pc-info['base']:pc-info['base']+len(raw)]==raw
        insn=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=info['firmware_offset']+pc-info['base']);instructions[pc]=insn;return insn
    pools=[]
    for load,pool,value,pc in [(0x1f08e4,0x1f08f0,0xfef0020,0x1f08f4),(0x1f0920,0x1f092c,0xfe800bc,0x1f0930),(0x1f0940,0x1f0944,0xfed3000,0x1f0948),(0x1f0958,0x1f095c,0xfed3800,0x1f0960)]:
        assert struct.unpack_from('<I',body,pool-info['base'])[0]==value
        i=decode(load);assert i['opcode']=='ld_s'and i['operands'].endswith(';'+hex(pool));assert decode(pc)['opcode']=='ldh.di'
        pools.append(dict(load_pc=hex(load),pool=hex(pool),address=hex(value),access_pc=hex(pc),firmware_offset=info['firmware_offset']+pool-info['base']))
    for pc,op,arg in [(0x239f10,'mov_s','r14,0x1'),(0x239f12,'mov_s','r13,0x1c'),(0x239f14,'extw_s','r0,r14'),(0x239f1e,'sub_s','r13,r13,0x1'),(0x239f22,'add_s','r14,r14,0x1'),(0x2c5d32,'asl_s','r0,r0,0x4'),(0x2c5d34,'add_s','r0,r0,0xfe60000')]:assert decode(pc)['opcode']==op and decode(pc)['operands']==arg
    checks=[];addresses=set();total=0;loop_cases=0
    for c in d['cases']:
        if not c['observer_enabled']:continue
        ev=c['completed_memory_events'];pcs={e['pc']for e in ev};path=src/(c['name']+'.trace');inputs[str(path)]=sha(path);rows=[]
        for line in path.read_text().splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(ldw\.di|stw\.di).*? - .*?<- (0x[0-9a-f]+)',line)
            if m and int(m[1],16)in pcs:rows.append((int(m[1],16),'read'if m[2].startswith('ld')else'write',int(m[3],16)&65535))
        assert len(rows)==len(ev)
        for row,e in zip(rows,ev):
            assert row==(e['pc'],e['operation'],e['value'])and e['width_bytes']==2
            assert decode(e['pc'])['opcode']==('ldh.di'if e['operation']=='read'else'sth.di')
            addresses.add(e['address']);total+=1
        loops=[e for e in ev if e['pc']==0x2c5d50]
        if c['entry']=='0x239f00'and int(c['expected_mode_word'],0)>>16==2:
            assert [e['address']for e in loops]==[0xfe60000+16*s for s in range(1,29)]
            assert {e['value']for e in loops}=={(c['caller_argument']&3)<<12};loop_cases+=1
        else:assert not loops
        cache=bytes.fromhex(c['fixtures']['0x423f00']['after']);assert struct.unpack_from('<I',cache,8)[0]==int(c['expected_mode_word'],0)and cache[4]==1
        assert c['exit_code']==0 and c['full_original_caller_completed']
        assert path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        checks.append(dict(case=c['name'],events=len(ev),loop_writes=len(loops),mode_word=c['expected_mode_word'],original_caller_completed=True,trace_results_per_event=1))
    assert len(checks)==11 and total==208 and loop_cases==6
    assert addresses=={0xfe60000+16*s for s in range(1,29)}|{0xfef0020,0xfe800bc,0xfed3000,0xfed3800,0xfe60240,0xfe60244}
    assert len(d['pairs'])==11 and all(p['trace_identical']for p in d['pairs'])
    result=dict(status='PASS_FE6_ORIGINAL_LOOP_BYTE_AND_TRACE_AUDIT',date='2026-10-25',checks=checks,distinct_addresses=len(addresses),addresses=list(map(hex,sorted(addresses))),completed_memory_events=total,original_loop_cases=loop_cases,original_loop_writes=168,source_pools=pools,independently_redecoded_instructions={hex(pc):i for pc,i in instructions.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=['PC-anchored fresh decoding skips embedded pool words that can misalign a linear window.','Raw fixture input and cache-ready/flag state are not physical identification/configuration/reset evidence.','Original mode/loop control executes on CPU; no peripheral timing or real status-bit completion verified.'])
    assert all(sha(Path(p))==h for p,h in inputs.items());args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS34 addresses,208events,11pairs; six original28-iteration loops; four source pools byte-bound')
if __name__=='__main__':main()
