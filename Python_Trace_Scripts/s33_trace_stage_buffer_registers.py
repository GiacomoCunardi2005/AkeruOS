#!/usr/bin/env python3
"""Offline conditional stage buffer routing and split-halfword register programming."""
import json,re,struct,tempfile,random
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
# Every helper splits a 32-bit argument into two halfword stores.
PAIRS=[(0x2E2E00,0x0FFC2028,0x0FFC202C,'2000',0),
 (0x2E2EB4,0x0FFC2050,0x0FFC2054,'2000',4),(0x2E2F68,0x0FFC207C,0x0FFC2080,'2000',8),
 (0x2E3A74,0x0FFC4070,0x0FFC4074,'800',4),(0x2E3AE8,0x0FFC40C0,0x0FFC40C4,'800',8),
 (0x2E3B5C,0x0FFC40DC,0x0FFC40E0,'800',12),
 (0x2E3DC4,0x0FFC3070,0x0FFC3074,'1000',4),(0x2E3E38,0x0FFC30C0,0x0FFC30C4,'1000',8),
 (0x2E3EAC,0x0FFC30DC,0x0FFC30E0,'1000',12),(0x2E3ED4,0x0FFC3100,0x0FFC3104,'1000',16),
 (0x2E3F48,0x0FFC311C,0x0FFC3120,'1000',20)]
WINDOWS=[];LITERALS={};CHECKS={}
for fn,low,high,stage,offset in PAIRS:
 WINDOWS.extend([(fn,fn+12,f'Split{fn:x}Prologue'),(fn+16,fn+28,f'Split{fn:x}Low'),(fn+32,fn+40,f'Split{fn:x}High')])
 LITERALS[fn+12]=low;LITERALS[fn+28]=high
 CHECKS.update({fn+4:'mov_s\tr13,r0',fn+8:'extw_s\tr0,r0',fn+16:'sth.di\tr0,[r1]',
  fn+22:'lsr_s\tr13,r13,0x10',fn+32:'sth.di\tr13,[r0]'})
WINDOWS.extend([(0x24A6CC,0x24A6F4,'Runtime2000RecordAndConfigBinding'),(0x15D02C,0x15D048,'TaskRecordBindings'),(0x15D3BE,0x15D416,'Runtime2000BankOrSkip'),
 (0x15D416,0x15D490,'Runtime800And1000FieldRouting'),(0x24A732,0x24A74A,'Runtime2000Copy'),
 (0x24A84C,0x24A87E,'Runtime2000ThreeEnabledPointers'),(0x24B230,0x24B280,'Runtime800Setters'),
 (0x24BA5C,0x24BACC,'Runtime1000Setters')])
LITERALS.update({0x15CFA8:0x367490,0x15D310:0x445318,0x15D30C:0x4453CC,0x15D304:0x445358,
 0x15D308:0x445368,0x15D6A8:0x392288,0x15D6AC:0x4457B0,0x15D6B0:0x4453C0,
 0x15D6B4:0x444FB4,0x15D6B8:0x445338,0x24A8D8:0x50C1F8,0x24A8EC:0x2E2EB4,
 0x24B2AC:0x50C254,0x24BAF8:0x50C254})
CHECKS.update({0x24A6D4:'mov_s\tr14,r0',0x24A6F0:';0x24a8d8',
 0x15D3C4:';0x15d40c',0x15D032:'ld.as\tr16,[pcl,183]',0x15D036:'ld.as\tr20,[pcl,180]',
 0x15D03A:'ld.as\tr18,[pcl,180]',0x15D3BE:'ld\tr0,[r14,144]',0x15D3C6:'ldb\tr0,[r14,81]',
 0x15D3CE:'asl_s\tr0,r0,0x2',0x15D3D0:'add1_s\tr0,r0,r0',0x15D3D2:'ld.aw\tr2,[r0,r12]',
 0x15D3D6:'st.as\tr2,[r1,-249]',0x15D3DC:'st.as\tr2,[r1,-248]',0x15D3E4:'st.as\tr1,[r0,-247]',
 0x15D3EC:'stb_s\tr0,[r1,0x18]',0x15D3EE:'stb_s\tr0,[r1,0x19]',0x15D3F0:'stb_s\tr0,[r1,0x1a]',
 0x15D400:'mov_s\tr0,r16',0x15D414:'bset_s\tr1,r1,0xd',0x15D426:';0x15d45a',
 0x15D42A:'ld.as\tr0,[r0,243]',0x15D432:'ld.as\tr0,[r0,244]',0x15D43A:'ld.as\tr0,[r0,248]',
 0x15D442:'ld.as\tr0,[r0,249]',0x15D44A:'ld.as\tr0,[r0,253]',0x15D452:'ld.as\tr0,[r0,254]',
 0x15D464:'ld.aw\tr1,[r0,r12]',0x15D46A:'st_s\tr1,[r13,0x48]',0x15D470:'st_s\tr1,[r13,0x4c]',
 0x15D472:'st_s\tr2,[r13,0x58]',0x15D474:'st_s\tr1,[r13,0x5c]',0x15D476:'st_s\tr0,[r13,0x60]',
 0x15D478:'st_s\tr1,[r13,0x64]',0x15D47E:'mov_s\tr0,r20',0x15D48C:'mov_s\tr0,r18',
 0x24A73A:'add2\tr0,r13,0x13',0x24A744:'mov_s\tr2,0x10',
 0x24A86C:'ld_s\tr0,[r13,0x4c]',0x24A86E:'jl_s.d\t[r14]',0x24A870:'ld_s\tr0,[r13,0x50]',
 0x24A876:'ld_s\tr0,[r13,0x54]',0x24B26C:'ld_s\tr0,[r13,0x4]',0x24B272:'ld_s\tr0,[r13,0x8]',
 0x24B27E:'ld_s\tr0,[r13,0xc]',0x24BA98:'ld_s\tr0,[r13,0x4]',0x24BA9E:'ld_s\tr0,[r13,0x8]',
 0x24BAB8:'ld_s\tr0,[r13,0xc]',0x24BAB0:'ld_s\tr0,[r13,0x10]',0x24BACA:'ld_s\tr0,[r13,0x14]'})
EDGES=[(0x15D3FC,0x24A6CC),(0x15D410,0x158CBC),(0x15D47A,0x24B230),(0x15D488,0x24BA5C),
 (0x24A740,0x128C20),(0x24A868,0x2E2E00),(0x24A872,0x2E2F68),
 (0x24B268,0x2E3A74),(0x24B26E,0x2E3AE8),(0x24B27A,0x2E3B5C),
 (0x24BA94,0x2E3DC4),(0x24BA9A,0x2E3E38),(0x24BAB4,0x2E3EAC),
 (0x24BAAC,0x2E3ED4),(0x24BAC0,0x2E3ED4),(0x24BAC6,0x2E3F48)]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 for a,v in LITERALS.items():assert word(a)==v,hex(a)
 # Recompute scaled PCL references explicitly; GNU comments for these loads are unscaled.
 bindings={0x15D032:(183,0x4453CC),0x15D036:(180,0x445358),0x15D03A:(180,0x445368)}
 for site,(scale,value) in bindings.items():assert word((site&~3)+4*scale)==value
 aliases=[(0x4457B0-249*4,0x4453CC),(0x4457B0-248*4,0x4453D0),(0x4457B0-247*4,0x4453D4),
 (0x445318+0x48,0x445358+8),(0x445318+0x4C,0x445358+12),
 (0x445318+0x58,0x445368+8),(0x445318+0x5C,0x445368+12),
 (0x445318+0x60,0x445368+16),(0x445318+0x64,0x445368+20)]
 for a,b in aliases:assert a==b
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-stage-pointers-') as td:
  elf,back=Path(td)/'0.elf',Path(td)/'0.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc','--rename-section',
   '.data=.text,alloc,load,readonly,code,contents','--change-section-vma',
   f'.data={info[0]["load_address_candidate"]:#x}','--strip-all',bd/info[0]['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==ps[0]
  for a,b,label in WINDOWS:
   t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',elf])
   assert 'out of bounds' not in t.lower(),label
   listings.append('WINDOW '+label+'\n'+t.replace(str(elf),'verified-block0.elf'))
 listing='\n'.join(listings);decoded={}
 for l in listing.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\t([^\t]+)\t(\S+)\t?(.*)$',l)
  if m:decoded[int(m[1],16)]=(len(m[2].split())*2,m[3],m[4],l)
 for a,b in EDGES:assert f';0x{b:x}' in decoded[a][3],decoded[a]
 for a,n in CHECKS.items():assert n in decoded[a][3],decoded[a]
 def emulate(fn,pointer):
  regs={'r0':pointer};stores=[];pc=fn
  while pc<fn+40:
   size,op,args,_=decoded[pc];parts=args.split(';')[0].strip().split(',')
   if op=='push_s':pass
   elif op=='mov_s':regs[parts[0]]=regs[parts[1]]
   elif op=='extw_s':regs[parts[0]]=regs[parts[1]]&0xFFFF
   elif op=='ld_s':regs[parts[0]]=word(int(re.search(r';0x([0-9a-f]+)',args)[1],16))
   elif op=='lsr_s':regs[parts[0]]=regs[parts[1]]>>int(parts[2],0)
   elif op=='b_s':pc=int(re.search(r';0x([0-9a-f]+)',args)[1],16);continue
   elif op=='sth.di':stores.append((regs[parts[1].strip('[]')],regs[parts[0]]&0xFFFF))
   elif op=='b':break # common register restore, after both stores
   elif op=='nop_s':pass
   else:raise AssertionError((hex(pc),op,args))
   pc+=size
  return stores
 rng=random.Random(33);pointers=[0,1,0xFFFF,0x10000,0xFFFFFFFF,0x12345678]+[rng.getrandbits(32) for _ in range(250)]
 tests=0
 for fn,low,high,stage,offset in PAIRS:
  for pointer in pointers:
   stores=emulate(fn,pointer);assert stores==[(low,pointer&0xFFFF),(high,pointer>>16)]
   assert stores[0][1]|stores[1][1]<<16==pointer;tests+=1
 out=ROOT/'Ghidra_Results/ghidra_reports/stage_buffer_registers';out.mkdir(parents=True,exist_ok=True)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],script_sha256=sha(Path(__file__).read_bytes()),
 block_sha256={str(b['index']):b['sha256'] for b in bs},windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
 checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in EDGES],checked_instructions=len(CHECKS),
 checked_literals={hex(a):hex(v) for a,v in LITERALS.items()},pointer_setters=[dict(function=hex(f),low=hex(l),high=hex(h),stage=s,runtime_offset=hex(o)) for f,l,h,s,o in PAIRS],
 runtime_records=dict(stage2000='0x4453cc',stage800='0x445358',stage1000='0x445368'),
 decoded_pointer_cases=tests,scaled_aliases=[dict(a=hex(a),b=hex(b)) for a,b in aliases],
 observations=['BankB(i)=0x392288+12*byte(C+0x51), C=0x367490',
 'In the selected task branch after earlier guards, C+0x90==0 starts2000 with bank triple; C+0x90!=0 skips it and posts bit2000',
 'Later runtime800/1000 fields use config-backed cells for C+0x90==0, bank triple otherwise',
 'Eleven low-level setters split value into lower16 then upper16 without local pointer guards or polling'],
 limits=['No read/write direction or physical stage names assigned solely from pointer register order',
 'Untraced origin of runtime+4 and config-backed pointer cells; buffer capacity/index bounds still open',
 'Full-three-flags2000 mapping is conditional; other flag combinations multiplex register selection',
 'No atomicity, address translation, cache coherence or final hardware-use proof'])
 (out/'gnu_verified.txt').write_text(listing);(out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS:16 hashes, block0 roundtrip, {len(WINDOWS)} windows, {len(EDGES)} edges, {len(CHECKS)} instructions, {len(LITERALS)} pools, 11 setters, {tests} pointer cases')
if __name__=='__main__':main()
