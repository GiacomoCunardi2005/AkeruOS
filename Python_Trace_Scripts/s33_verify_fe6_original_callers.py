#!/usr/bin/env python3
"""Bind original conditional FE6 callers and literal selectors, without execution claims."""
import argparse,hashlib,json,re
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('output',type=Path);a=ap.parse_args();out=a.output.resolve();out.mkdir(exist_ok=False)
    blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate'];fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';offset=fw.read_bytes().find(body);assert offset>=0
    inputs={str(p):sha(p)for p in [Path(__file__),fw,directory/info['file'],ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']}
    windows=[];insns={}
    for entry,end in [(0x239f2c,0x239fc8),(0x239fc8,0x23a008),(0x23a008,0x23a048),(0x23a270,0x23a2b0)]:
        text=aligned_window(body,base,entry,end);windows.append(text)
        for line in text.splitlines():
            m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            if not m:continue
            pc=int(m[1],16);raw=b''.join(bytes.fromhex(w)[::-1]for w in m[2].split());assert body[pc-base:pc-base+len(raw)]==raw
            insns[pc]=dict(opcode=m[3],operands=m[4].strip(),bytes_hex=raw.hex(),firmware_offset=offset+pc-base)
        assert insns[entry]['opcode']=='push_s'and insns[entry]['operands']=='blink'
    rows=[]
    for pc,selector,move,target,delay in [(0x239ff0,0x2c,0x239fea,0x2c5de8,0x239ff4),(0x239ffc,0x33,0x239ff6,0x2c5de8,0x23a000),(0x23a030,0x2c,0x23a02a,0x2c5de8,0x23a034),(0x23a03c,0x33,0x23a036,0x2c5de8,0x23a040),(0x23a280,0x24,0x23a27e,0x2c5e80,0x23a284),(0x23a286,0x24,0x23a28a,0x2c5ee0,0x23a28a),(0x23a29e,0x24,0x23a290,0x2c5d58,0x23a2a2),(0x23a2a6,0x24,0x23a2a4,0x2c5e80,0x23a2aa)]:
        call=call_at(body,pc-base,base);assert call['target']==target
        assert insns[pc]['opcode']=='bl.d'and insns[pc]['operands'].endswith(';'+hex(target))
        assert insns[move]['opcode']=='mov_s'and insns[move]['operands']=='r0,'+hex(selector)
        assert not insns[delay]['operands'].startswith('r0,')or delay==move
        rows.append(dict(call_pc=hex(pc),target=hex(target),selector=hex(selector),selector_move_pc=hex(move),delay_pc=hex(delay),kind='original_conditional_static_call',runtime_reachability_verified=False))
    # Higher wrapper forwards a caller parameter after an original mode gate and range checks.
    for pc,op,arg in [(0x239f32,'mov_s','r14,r0'),(0x239f3e,'cmp_s','r0,0x2'),(0x239f42,'cmp_s','r14,0x20'),(0x239f46,'cmp_s','r14,0x33'),(0x239f4a,'cmp_s','r14,0x40'),(0x239f50,'cmp_s','r14,0x43')]:assert insns[pc]['opcode']==op and insns[pc]['operands']==arg
    (out/'original_callers_disassembly.txt').write_text('\n\n'.join(windows));(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
    d=dict(status='PASS_FE6_ORIGINAL_CONDITIONAL_CALLERS',date='2026-10-25',literal_selector_calls=rows,literal_selectors=['0x24','0x2c','0x33'],parameter_forwarding_wrapper='0x239f2c',original_mode_gate='return_from_1F0A6C_equals2',instructions={hex(pc):i for pc,i in insns.items()},input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=['Static conditional call/value evidence, not observed runtime selector values or global reachability.','Other accepted selector values are exercised only by explicit synthetic callers in the CPU domain proof.','Do not infer a peripheral identity or physical register implementation from these calls.'])
    assert all(sha(Path(p))==h for p,h in inputs.items());(out/'verified_evidence.json').write_text(json.dumps(d,indent=2)+'\n');print('PASS eight original conditional calls; literal selectors24/2C/33hex; parameter forwarding wrapper bounded')
if __name__=='__main__':main()
