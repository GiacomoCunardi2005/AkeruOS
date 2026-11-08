#!/usr/bin/env python3
"""Static evidence for consumer task event clearing, self-signals and bypass bits."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x15D02C,0x15D030,'ControlBase'),(0x15D1AC,0x15D1C0,'NormalClearAndAdmission'),
 (0x15D2DC,0x15D2FC,'ModeAndAlternateSubmission'),(0x15D364,0x15D3BE,'ConditionalBitsAndModeBypass'),
 (0x15D40C,0x15D416,'SkippedStageSignal'),(0x15D496,0x15D4B8,'SubmissionAndFinalWaitBranch'),
 (0x15D4B8,0x15D4FE,'AlternatePathPreSignals'),(0x15D5FC,0x15D62E,'IntermediateWaitsAndClear'),
 (0x15D7DC,0x15D7E6,'AllBitsSoftwarePrefill'),(0x15D8D2,0x15D8E8,'FinalAllBitsWait'),
 (0x2444A0,0x2444AA,'Bit800CallbackStub'),(0x2444CC,0x2444E4,'Bit1000And2000Stubs'),
 (0x15F0EE,0x15F0F8,'InitializationClearAll')]
CHECKS={0x15D02C:';0x15cfa8',0x15D1AE:'mov_s\tr1,0x73',0x15D1B4:'asl_s\tr1,r1,0x7',
 0x15D1BC:';0x15d7dc',0x15D2DC:'ldb\tr0,[r14,168]',0x15D2E2:';0x15d4b8',
 0x15D2E6:'ld\tr0,[r14,140]',0x15D2F4:'mov\tr1,512',
 0x15D364:'ldb\tr0,[r14,93]',0x15D374:'mov\tr1,512',0x15D378:'ldb\tr0,[r14,94]',
 0x15D382:'ld_s\tr0,[r0,0x74]',0x15D38E:'mov\tr1,1024',
 0x15D392:'ld\tr0,[r14,132]',0x15D398:';0x15d39e',0x15D39C:';0x15d3be',
 0x15D3A6:'bset_s\tr1,r1,0xd',0x15D3B0:'bset_s\tr1,r1,0xb',0x15D3BA:'bset_s\tr1,r1,0xc',
 0x15D414:'bset_s\tr1,r1,0xd',0x15D4BE:'mov\tr1,512',0x15D4C8:'mov\tr1,1024',
 0x15D4D2:'mov\tr1,256',0x15D4DE:'bset_s\tr1,r1,0xb',0x15D4FA:'bset_s\tr1,r1,0xc',
 0x15D600:'mov_s\tr2,0',0x15D606:'mov_s\tr3,r2',0x15D60C:'bset_s\tr1,r1,0xc',
 0x15D61A:'bset_s\tr1,r1,0xd',0x15D626:'mov_s\tr1,0x61',0x15D62C:'asl_s\tr1,r1,0x7',
 0x15D7DE:'mov_s\tr1,0x7f',0x15D7E4:'asl_s\tr1,r1,0x7',
 0x15D8D6:'asl_s\tr1,r1,0x7',0x15D8D8:'mov_s\tr2,0x1',
 0x15D8E0:'ld\tr0,[r14,212]',0x2444A8:'bset_s\tr1,r1,0xb',
 0x2444D6:'bset_s\tr1,r1,0xc',0x2444E2:'bset_s\tr1,r1,0xd',0x15F0F4:'mov\tr1,-1'}
SET_SITES=[0x15D2F0,0x15D370,0x15D38A,0x15D3A2,0x15D3AC,0x15D3B6,0x15D410,
 0x15D4BA,0x15D4C4,0x15D4CE,0x15D4DA,0x15D4EC,0x15D4F6,0x15D7E0,0x2444A4,0x2444D2,0x2444DE]
EDGES=[(a,0x158CBC) for a in SET_SITES]+[(0x15D1B0,0x158CE0),(0x15D628,0x158CE0),
 (0x15F0F0,0x158CE0),(0x15D4A8,0x24863C),(0x15D602,0x158D04),(0x15D610,0x158D04),
 (0x15D61E,0x158D04),(0x15D8DA,0x158D04)]
# Bounded straightline sequences replayed from actual decoded instructions.
SEQUENCES=[(0x15D1AC,0x15D1B6,'clear_normal',0x3980,'clear'),
 (0x15D39E,0x15D3BC,'mode_bypass',0x3800,'set'),
 (0x15D4B8,0x15D4E0,'alternate_prefill',0xF00,'set'),
 (0x15D624,0x15D62E,'clear_intermediate',0x3080,'clear'),
 (0x15D7DC,0x15D7E6,'prefill_all',0x3F80,'set'),
 (0x15F0EE,0x15F0F8,'clear_all',0xFFFFFFFF,'clear')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={0x15CFA8:0x367490,0x15D33C:0x08200011,0x15D6A0:0x391E68,
  0x15D6A4:0x08200011,0x15DA5C:0x08200011,0x15F2A0:0x08200011,0x2444C8:0x08200011}
 for a,v in literals.items():assert word(a)==v
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-event-protocol-') as td:
  elf,back=Path(td)/'0.elf',Path(td)/'0.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc','--rename-section',
   '.data=.text,alloc,load,readonly,code,contents','--change-section-vma',
   f'.data={info[0]["load_address_candidate"]:#x}','--strip-all',bd/info[0]['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==ps[0]
  for a,b,label in WINDOWS:
   t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',elf])
   assert 'out of bounds' not in t.lower(),label
   listings.append('WINDOW '+label+'\n'+t.replace(str(elf),'verified-block0.elf'))
 listing='\n'.join(listings);lines={}
 for l in listing.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\t([^\t]+)\t(\S+)\t?(.*)$',l)
  if m:lines[int(m[1],16)]=(len(m[2].split())*2,m[3],m[4],l)
 for a,b in EDGES:assert f';0x{b:x}' in lines[a][3],lines[a]
 for a,n in CHECKS.items():assert n in lines[a][3],lines[a]
 def replay(start,end,bits):
  regs={};pc=start;pending=None;signals=[]
  while pc<end:
   size,op,args,_=lines[pc];parts=args.split(';')[0].strip().split(',');old_pending=pending;pending=None
   if op in ('ld_s','ld'):
    assert parts[1].startswith('[pcl');addr=int(re.search(r';0x([0-9a-f]+)',args)[1],16)
    regs[parts[0]]=word(addr)
   elif op in ('mov_s','mov'):regs[parts[0]]=int(parts[1],0)&0xFFFFFFFF
   elif op=='asl_s':regs[parts[0]]=(regs[parts[1]]<<int(parts[2],0))&0xFFFFFFFF
   elif op=='bset_s':regs[parts[0]]=regs[parts[1]]|(1<<int(parts[2],0))
   elif op in ('bl.d','b.d'):pending=int(re.search(r';0x([0-9a-f]+)',args)[1],16)
   else:raise AssertionError((hex(pc),op,args))
   if old_pending is not None:
    assert regs['r0']==0x08200011;mask=regs['r1'];signals.append((old_pending,mask))
    if old_pending==0x158CBC:bits|=mask
    elif old_pending==0x158CE0:bits&=~mask
    else:raise AssertionError(old_pending)
    bits&=0xFFFFFFFF;regs['r0']=0
   pc+=size
  assert pending is None
  return bits,signals
 tests=0
 for a,b,label,mask,operation in SEQUENCES:
  for subset in range(128):
   original=(subset<<7)|0x80000001
   actual,signals=replay(a,b,original)
   expected=(original|mask) if operation=='set' else (original&~mask)
   assert actual==expected&0xFFFFFFFF,(label,subset,hex(actual),hex(expected))
   assert signals;tests+=1
 assert 0x3F80&~0x3980==0x600
 assert 0x3F80&~0x3080==0xF00
 out=ROOT/'Ghidra_Results/ghidra_reports/event_protocol_masks';out.mkdir(parents=True,exist_ok=True)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in EDGES],checked_instructions=len(CHECKS),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},decoded_replay_cases=tests,
  sequences=[dict(start=hex(a),end=hex(b),label=l,mask=hex(m),operation=o) for a,b,l,m,o in SEQUENCES],
  observations=['Normal clear0x3980 leaves0x600 from final wait mask0x3f80',
   'Task can self-signal every final-mask bit through condition-dependent paths',
   'Mode1/2 self-signals0x3800; alternate admission path self-signals all0x3f80',
   'Intermediate path waits0x80/0x1000/0x2000 then clears0x3080',
   'Initialization caller can clear all event bits'],
  limits=['No whole-task temporal model or runtime mode proof',
   'Self-signals may mark skipped work; semantic names of stages remain unassigned',
   'Callback stubs0x2444a0/cc/d8 are decoded but complete registration chains remain open',
   'Other writers, race behavior, final physical buffer use and JPEG persistence unproven'])
 (out/'gnu_verified.txt').write_text(listing);(out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS:16 hashes, block0 roundtrip, {len(WINDOWS)} windows, {len(EDGES)} edges, {len(CHECKS)} instructions, {tests} decoded replay cases')
if __name__=='__main__':main()
