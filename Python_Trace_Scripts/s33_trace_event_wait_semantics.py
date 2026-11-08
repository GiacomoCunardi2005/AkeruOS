#!/usr/bin/env python3
"""Offline ARC evidence: all/any event waits, configured persistence, explicit clear."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x158C30,0x158C8C,'EventInitialization'),
 (0x158C8C,0x158CBC,'EventResolver'),(0x158CBC,0x158D04,'SetAndClearWrappers'),
 (0x158D04,0x158E1E,'WaitWrapper'),(0x23C674,0x23C71E,'LowerEventInitialization'),
 (0x23C758,0x23C8AA,'SetBitsAndWakeWaiters'),(0x23C8AC,0x23C902,'ExplicitClearBits'),
 (0x23C938,0x23C940,'WaitTrampoline'),(0x2C9994,0x2C9ADE,'LowerWaitAllOrAny'),
 (0x15D8D2,0x15D8E8,'ConsumerWait')]
EDGES=[(0x158C62,0x23C674),(0x158CD0,0x23C758),(0x158CF4,0x23C8AC),
 (0x158D2A,0x158C8C),(0x158DB8,0x23C938),(0x23C938,0x2C9994),
 (0x2C9AC2,0xB2C74),(0x15D8DA,0x158D04)]
CHECKS={0x158C50:'bmsk_s\tr14,r14,0',0x158C66:'mov_s\tr1,r14',
 0x158D1E:'mov_s\tr16,r2',0x158D20:'mov_s\tr14,r3',0x158D92:'cmp_s\tr14,0',
 0x158DB4:'mov_s\tr3,0',0x158DBC:'mov_s\tr2,r16',0x158DBE:'mov_s\tr16,r0',
 0x23C69A:'st_s\tr15,[r0,0x18]',0x23C6A0:'st_s\tr1,[r0,0x1c]',
 0x23C786:'or_s\tr3,r3,r1',0x23C7A4:'and.f\tr2,r2,128',
 0x23C7B6:';0x23c7cc',0x23C7C6:'tst\tr2,r3',0x23C854:';0x23c862',
 0x23C866:'bic_s\tr3,r3,r2',0x23C868:'st_s\tr3,[r0,0x18]',
 0x23C8CE:'bic_s\tr2,r2,r1',0x23C8D0:'st_s\tr2,[r0,0x18]',
 0x23C93C:'mov\tr4,0',0x2C99E0:';0x2c99ee',0x2C99EA:';0x2c99fa',
 0x2C99EE:';0x2c9a28',0x2C99F8:';0x2c9a28',0x2C99FC:';0x2c9a08',
 0x2C9A00:'bic\tr5,r5,r1',0x2C9A2C:'st\tr1,[r15,196]',
 0x2C9A34:'or\tr0,r0,128',0x2C9A3A:'and\tr0,r0,-129',
 0x2C9A6E:';0x2c9ac2',0x15D8D8:'mov_s\tr2,0x1',0x15D8DE:'mov_s\tr3,0',
 0x15D8E0:'ld\tr0,[r14,212]'}

def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 def word(a):
  for b in bs:
   off=a-b['load_address_candidate']
   if 0<=off<=len(ps[b['index']])-4:return struct.unpack_from('<I',ps[b['index']],off)[0]
  raise ValueError(hex(a))
 literals={0x158E48:0x372A48,0x158E4C:0x200307,0x158E50:0x200304,0x158E70:0x200306}
 for a,v in literals.items():assert word(a)==v
 records=[]
 for i in range(86):
  a=0x372A48+56*i; vals=[word(a+4*j) for j in range(14)]
  if i==85:assert vals==[0]*14;break
  assert vals[0]==0x45564E4C and vals[1]!=0
  if vals[1] in (0x08200011,0x03F00002):
   assert vals[2]==2 and vals[3:]==[0]*11
   records.append(dict(index=i,address=hex(a),event=hex(vals[1]),flags=vals[2],
    lower_object=hex(a+12),bits_cell=hex(a+36),auto_clear_cell=hex(a+40),initial_auto_clear=vals[2]&1))
 assert len(records)==2
 listings=[];tools=ROOT/'work/build-arc/binutils'
 with tempfile.TemporaryDirectory(prefix='s33-event-semantics-') as td:
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
 lines={}
 for l in listing.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\t[^\t]+\t(\S+)\t?(.*)$',l)
  if m:lines[int(m[1],16)]=(m[2],m[3],l)
 for a,b in EDGES:assert f';0x{b:x}' in lines[a][2],lines[a]
 for a,n in CHECKS.items():assert n in lines[a][2],lines[a]
 # Execute the actual decoded predicate/control-flow slice, stopping at matched/queue.
 def decoded_predicate(bits,mask,option):
  r={'r1':mask,'r2':option,'r5':bits};pc=0x2C99E0
  for _ in range(12):
   if pc in (0x2C99FA,0x2C9A28):return pc==0x2C99FA
   op,args,_=lines[pc];parts=args.split(';')[0].strip().split(',')
   if op=='ld':assert parts==['r5','[r13','24]'];pc+=4
   elif op=='and':r[parts[0]]=r[parts[1]]&r[parts[2]];pc+=4
   elif op=='tst':zero=(r[parts[0]]&r[parts[1]])==0;pc+=4
   elif op in ('breq_s','brne_s','breq'):
    if op=='breq':condition=r[parts[0]]==r[parts[1]];size=4
    else:condition=(r[parts[0]]==0) if op=='breq_s' else (r[parts[0]]!=0);size=2
    target=int(re.search(r';0x([0-9a-f]+)',args)[1],16);pc=target if condition else pc+size
   elif op=='beq_s':pc=int(re.search(r';0x([0-9a-f]+)',args)[1],16) if zero else pc+2
   else:raise AssertionError((hex(pc),op,args))
  raise AssertionError('predicate did not terminate')
 count=0
 for subset in range(128):
  bits=subset<<7
  for option in (0,1):
   actual=decoded_predicate(bits,0x3F80,option)
   expected=(bits&0x3F80)==0x3F80 if option else bool(bits&0x3F80)
   assert actual==expected,(subset,option);count+=1
 for bit in (0x80,0x100,0x180):assert not decoded_predicate(bit,0x3F80,1)
 assert decoded_predicate(0x3F80,0x3F80,1)
 out=ROOT/'Ghidra_Results/ghidra_reports/event_wait_semantics';out.mkdir(parents=True,exist_ok=True)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in EDGES],checked_instructions=len(CHECKS),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},event_records=records,
  decoded_predicate_cases=count,wait_option_nonzero='all requested bits',wait_option_zero='any requested bit',
  observations=['Task option1 reaches all-bits comparison unchanged',
   'Wait mask0x3f80 has seven bits; 0x80 and0x100 alone or together do not satisfy it',
   'Initial event config flags2 yields auto-clear0; set ORs bits; explicit clear uses BIC',
   'r3=0 skips deadline construction and selects lower scheduler call without local timeout',
   'Task does not compare wait return before loading next field'],
  limits=['Static configured path; no proof of all runtime writers to flags or event object',
   'Other five bit producers and explicit clearing callers remain untraced',
   'Scheduler correctness, runtime wait success and final physical buffer-use are not established'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block0 roundtrip, {len(WINDOWS)} windows, {len(EDGES)} edges, {len(CHECKS)} instructions, 2 records, {count} decoded predicates')
if __name__=='__main__':main()
