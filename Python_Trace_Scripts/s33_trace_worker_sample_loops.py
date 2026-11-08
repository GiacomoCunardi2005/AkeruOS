#!/usr/bin/env python3
"""Offline S33 V1.1 worker sample loops, parameter setters and request status reset."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x1FD38C,0x1FD4E4,'FallbackParameterSetter'),
 (0x1FE960,0x1FEAA0,'PreferredParameterSetter'),
 (0x1FD614,0x1FD65C,'FallbackInputBuffers'),
 (0x1FEAA0,0x1FEAF6,'PreferredInputBuffers'),
 (0x1FE2C6,0x1FE33A,'FallbackModeOneSampleLoop'),
 (0x20047E,0x2004FE,'PreferredModeOneSampleLoop'),
 (0x1FE394,0x1FE43A,'FallbackModeTwoThreeBoundaryLoop'),
 (0x20054A,0x2005EA,'PreferredModeTwoThreeBoundaryLoop'),
 (0x247310,0x247336,'RequestResultResetInDelaySlot'),
 (0x247338,0x247398,'WaitAndResponseHandler'),
 (0x1FE0FA,0x1FE10E,'FallbackModeRefresh'),
 (0x20046A,0x20047E,'PreferredSharedHelperCall')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/worker_sample_loops';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-release-') as td:
  elf,back=Path(td)/'0.elf',Path(td)/'0.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc',
   '--rename-section','.data=.text,alloc,load,readonly,code,contents',
   '--change-section-vma',f'.data={info[0]["load_address_candidate"]:#x}',
   '--strip-all',bd/info[0]['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==ps[0]
  for a,b,label in WINDOWS:
   t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',elf])
   assert 'out of bounds' not in t.lower(),label
   listings.append('WINDOW '+label+'\n'+t.replace(str(elf),'verified-block0.elf'))
 listing='\n'.join(listings)
 def line(a):
  hits=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
  assert len(hits)==1,(hex(a),hits)
  return hits[0]
 edges=[(2089216, 2086116), (2098296, 2086116), (2388784, 2970156), (2388804, 1412356), (2388816, 1412320), (2388864, 2357816), (2388876, 1412284)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={2085774: 'ldb\tr10,[sp,4]', 2085778: 'mov\tr9,0x3695dc', 2085786: 'mov\tr8,0x369620', 2085798: 'stb\tr10,[r8]', 2086042: 'st\tr0,[r9,8]', 2086082: 'cmp\tr4,r6', 2086092: 'cmp\tr5,r7', 2086098: 'mov_s\tr0,0', 2086104: 'mov_s\tr0,0x2711', 2091360: 'mov\tr7,0x3695dc', 2091380: 'stb\tr6,[r8]', 2091626: 'sth\tr0,[r7,14]', 2091658: 'cmp_s\tr2,r4', 2091666: 'cmp_s\tr3,r5', 2091670: 'j_s.d\t[blink]', 2091672: 'mov_s\tr0,0', 2091674: 'j_s.d\t[blink]', 2091676: 'mov_s\tr0,0x1', 2086470: 'st_s\tr1,[sp,0x4]', 2086476: 'mov_s\tr13,r0', 2091744: 'mov_s\tr18,r0', 2091748: 'st_s\tr1,[sp,0x4]', 2089670: 'ld_s\tr2,[sp,0x54]', 2089672: 'cmp_s\tr2,0x1', 2089726: 'ld\tr5,[sp,4]', 2089734: 'add1\tr6,r13,r1', 2089742: 'ldh\tr2,[r6,2]', 2089758: 'asr_s\tr2,r2', 2089760: 'sth\tr2,[r5,2]', 2089764: 'ldh.ab\tr2,[r6,4]', 2089768: 'asr_s\tr2,r2', 2089770: 'sth.ab\tr2,[r5,4]', 2098302: 'ldb\tr0,[0x369620]', 2098314: 'cmp_s\tr0,0x1', 2098366: 'ld_s\tr3,[sp,0x4]', 2098372: 'add1\tr6,r18,r5', 2098380: 'ldh\tr2,[r6,2]', 2098390: 'asr_s\tr2,r2', 2098392: 'stw_s\tr2,[r3,0x2]', 2098394: 'ldh.ab\tr1,[r6,4]', 2098398: 'asr_s\tr1,r1', 2098400: 'sth.ab\tr1,[r3,4]', 2089934: 'sth\tr11,[r9,2]', 2089998: 'sth.ab\tr11,[r9,4]', 2098560: 'sth\tr9,[r1,2]', 2098622: 'sth.ab\tr9,[r1,4]', 2388752: 'mov_s\tr2,0', 2388754: 'mov_s\tr3,0x36ad54', 2388760: 'stb_s\tr2,[r3,0]', 2388788: 'st_s\tr2,[r3,0x4]', 2388824: 'mov_s\tr0,0x36ad54', 2388834: 'stb_s\tr1,[r0,0]', 2388856: 'mov_s\tr0,0x36ad58', 2388862: 'st_s\tr1,[r0,0]', 2089218: 'ldb\tr0,[0x369620]', 2089226: 'st_s\tr0,[sp,0x54]'}
 for a,n in checks.items():assert n in line(a),line(a)
 references=[]
 for block in bs:
  idx=block['index']
  if idx>10:continue
  for target in (0x36AD54,0x36AD58):
   for pattern,kind in ((struct.pack('<I',target),'pool_le'),(struct.pack('<HH',target>>16,target&0xffff),'arc_limm')):
    offset=0
    while True:
     offset=ps[idx].find(pattern,offset)
     if offset<0:break
     references.append(dict(block=idx,address=hex(block['load_address_candidate']+offset),value=hex(target),encoding=kind))
     offset+=1
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  bounded_exact_pointer_search=dict(blocks=list(range(11)),references=references,limitation='raw byte matches; aliases and instruction attribution require separate audit'),
  sample_buffers={'fallback':{'source':'entry r0 saved r13','destination':'entry r1 saved stack+4'},
   'preferred':{'source':'entry r0 saved r18','destination':'entry r1 saved stack+4'}},
  mode_one_sample_operation='selected halfword read, shift right one, halfword store; no format label assigned',
  parameter_setters={'fallback':'0x1fd38c','preferred':'0x1fe960','shared_control':'0x3695dc','mode_byte':'0x369620'},
  request_reset={'site':'0x247334','address':'0x36ad58','value':0,'delay_slot_of':'0x247330'},
  observations=['Both lower routines contain CPU halfword writes into destination derived from entry r1',
   'Mode-one tails halve selected zero-extended 16-bit samples before writing',
   'Parameter setters mutate shared fields before returning validation errors',
   'New request clears result 0x36ad58 in branch delay slot before mailbox producer',
   'Wait wrapper sets byte flag but does not read the saved result'],
  limits=['No buffer allocation size, overlap contract or physical lifetime proof',
   'No JPEG format or complete resampling algorithm attribution',
   'Readers through aliases and other blocks may remain; exact pointer search is not a proof of no readers',
   'No runtime execution, event correctness or persistence test'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
