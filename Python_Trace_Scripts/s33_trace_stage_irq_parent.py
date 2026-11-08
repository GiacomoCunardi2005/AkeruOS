#!/usr/bin/env python3
"""Offline: group6000 parent090d, bitmap enable/disable, runtime9 CPU chain."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x266170,0x266234,'GroupEnableDisableParentAndBitmap'),
 (0x2660E8,0x26611E,'GroupMaskLookup'),(0x266124,0x26616E,'GroupSourceWriteAndMaskToggle'),
 (0x16D7E8,0x16D840,'EnableVarargsSentinel'),(0x16D840,0x16D898,'DisableVarargsSentinel'),
 (0x16D610,0x16D614,'OuterMaskTableSelection'),(0x16D6EC,0x16D728,'OuterMaskEnableLookup'),
 (0x16D7CC,0x16D7E6,'OuterMaskDisableWrite'),
 (0x16D8F0,0x16D906,'OuterRegistrarTableSelection'),(0x16D988,0x16D9AE,'OuterRegistrarStore'),
 (0x264308,0x2643C0,'OuterDispatcher0900'),(0x26627C,0x26628A,'InnerDispatcherBinding'),
 (0x2662A0,0x266300,'InnerDispatcher6000'),(0x16D3F0,0x16D428,'RuntimeSlot9Installation'),
 (0x231428,0x23148A,'RuntimeRegistrar'),(0xB2FF2,0xB3000,'CpuStub9'),
 (0xB3150,0xB31AA,'CommonEntryRuntimeRecordCall')]
EDGES=[(0x26619A,0x16D898),(0x2661A2,0x16D7E8),(0x2661C8,0x2660E8),
 (0x26621A,0x16D840),(0x266224,0x2660E8),(0x16D82A,0x16D5BC),(0x16D882,0x16D5BC),
 (0xB2FFA,0xB3054)]
CHECKS={0x266190:'ldw_s\tr0,[r0,0]',0x266194:';0x266198',
 0x266198:';0x266294',0x26619E:';0x266298',0x2661A6:'mov_s\tr1,0xff',
 0x2661B6:';0x266290',0x2661B8:'bmsk\tr1,r14,0x4',0x2661BC:'sub_s\tr1,r1,0x1',
 0x2661C0:'bset\tr0,r0,r1',0x2661C4:'stw_s\tr0,[r2,0]',0x2661CC:'mov_s\tr1,0x1',
 0x2661FE:'bmsk\tr0,r13,0x4',0x266202:'sub_s\tr0,r0,0x1',0x266206:'bset\tr1,r1,r0',
 0x26620C:'bic_s\tr2,r2,r1',0x26620E:'stw_s\tr2,[r3,0]',0x266212:';0x266218',
 0x26621E:'mov_s\tr1,0xff',0x266228:'mov_s\tr1,0',
 0x266128:'ld.di\tr2,[r14]',0x266138:'sth.di\tr0,[r2]',
 0x26613E:'ld.di\tr1,[r14,4]',0x26614E:'bset\tr10,r10,r0',0x26615E:'bclr\tr10,r10,r0',
 0x16D824:'cmp\tr0,255',0x16D828:';0x16d836',0x16D82E:'mov_s\tr1,0x1',
 0x16D87C:'cmp\tr0,255',0x16D886:'mov_s\tr1,0',
 0x16D610:';0x16d6d8',0x16D902:';0x16db30',0x16D9A6:'st.di\tr1,[r14,16]',
 0x16D71C:'bset\tr10,r10,r0',0x16D7D0:'bclr\tr10,r10,r0',
 0x26430E:'[0x424c34]',0x26431E:'[0x424c30]',0x26434A:';0x2643a6',
 0x264352:';0x2643a6',0x264376:'jl\t[r0]',0x26439A:'sth.di\tr0,[r2]',
 0x266282:';0x26629c',0x2662D8:'jl_s\t[r0]',
 0x16D422:'mov_s\tr0,0x9',0x16D424:'jl_s.d\t[r13]',
 0x231444:'ld.as\tr13,[r1,142]',0x23146C:'st_s\tr15,[r13,0]',
 0xB2FFE:'mov_s\tr1,0x9',0xB3196:'ld\tr1,[r3,4]',0xB31A4:'jl_s.d\t[r1]'}
LITERALS={0x266290:0x36B330,0x266294:0x26627C,0x266298:0x090D,0x26629C:0x424E00,
 0x266120:0x424E00,0x16D6D8:0x424C30,0x16DB30:0x424C30,
 0x16D51C:0x264308,0x16D510:0x231428}
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 def raw(a,n):
  for b in bs:
   off=a-b['load_address_candidate']
   if 0<=off<=len(ps[b['index']])-n:return ps[b['index']][off:off+n]
  raise ValueError(hex(a))
 for a,v in LITERALS.items():assert struct.unpack('<I',raw(a,4))[0]==v,hex(a)
 assert struct.unpack('<H',raw(0x36B330,2))[0]==0
 tables=[]
 for base,count,reg0,reg1 in [(0x424C30,14,0x0FEF0040,0x0FEF002C),(0x424E00,16,0x0FEF0228,0x0FEF022C)]:
  buf=raw(base,12+8*count);assert struct.unpack_from('<IIH',buf)==(reg0,reg1,count)
  rows=[]
  for i in range(count):
   ident,b0,b1,cb=struct.unpack_from('<HBBI',buf,12+8*i)
   assert cb==0
   rows.append(dict(index=i,id=hex(ident),source_bit=b0,mask_bit=b1,callback_cell=hex(base+16+8*i)))
  tables.append(dict(base=hex(base),source=hex(reg0),mask=hex(reg1),rows=rows))
 parent=next(r for r in tables[0]['rows'] if r['id']=='0x90d')
 assert parent['index']==3 and parent['source_bit']==parent['mask_bit']==12 and parent['callback_cell']=='0x424c58'
 for ident in (0x600A,0x600B,0x600C):
  row=next(r for r in tables[1]['rows'] if int(r['id'],16)==ident)
  assert ((ident&31)-1)==row['source_bit']==row['mask_bit']
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-stage-parent-') as td:
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
 def bitmap_slice(start,end,ident,bitmap):
  regs={'r14':ident,'r13':ident,'r2':bitmap,'r0':0,'r1':0};pc=start;stored=None
  while pc<end:
   size,op,args,_=decoded[pc];parts=args.split(';')[0].strip().split(',')
   if op=='ld_s':pass # pool address only; validated independently
   elif op=='ldw_s':regs[parts[0]]=bitmap
   elif op=='bmsk':regs[parts[0]]=regs[parts[1]]&((1<<(int(parts[2],0)+1))-1)
   elif op=='sub_s':regs[parts[0]]=(regs[parts[1]]-int(parts[2],0))&0xFFFFFFFF
   elif op=='mov_s':regs[parts[0]]=int(parts[1],0)
   elif op=='bset':regs[parts[0]]=regs[parts[1]]|(1<<(regs[parts[2]]&31))
   elif op=='extw_s':regs[parts[0]]=regs[parts[1]]&0xFFFF
   elif op=='bic_s':regs[parts[0]]=regs[parts[1]]&~regs[parts[2]]
   elif op=='stw_s':stored=regs[parts[0]]&0xFFFF
   else:raise AssertionError((hex(pc),op,args))
   pc+=size
  assert stored is not None
  return stored
 tests=0
 for bitmap in (0,1,0x200,0x400,0x800,0x600,0xE00,0xFFFF):
  for ident in (0x600A,0x600B,0x600C):
   bit=1<<((ident&31)-1)
   assert bitmap_slice(0x2661B6,0x2661C6,ident,bitmap)==(bitmap|bit)
   assert bitmap_slice(0x2661FE,0x266210,ident,bitmap)==(bitmap&~bit)&0xFFFF
   tests+=2
 out=ROOT/'Ghidra_Results/ghidra_reports/stage_irq_parent';out.mkdir(parents=True,exist_ok=True)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],script_sha256=sha(Path(__file__).read_bytes()),
 block_sha256={str(b['index']):b['sha256'] for b in bs},windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
 checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in EDGES],checked_instructions=len(CHECKS),
 checked_literals={hex(a):hex(v) for a,v in LITERALS.items()},tables=tables,bitmap_cell='0x36b330',decoded_bitmap_cases=tests,
 parent=dict(id='0x090d',handler='0x26627c',callback_cell='0x424c58',runtime_slot=9,cpu_stub='0xb2ff2'),
 observations=['First empty-bitmap enable requests parent090d registration and enable',
 'Logical IDs600a/b/c use bitmap bits9/10/11 matching inner table',
 'Disabling final bitmap bit requests parent090d disable',
 '0xff is varargs terminator in enable/disable wrappers, not a hardware mask',
 'CPU stub9 and runtime slot9 dispatcher264308 connect conditionally to parent090d and inner group6000'],
 limits=['Bitmap is not a per-client reference count; no whole-system ownership or race proof',
 'Parent registrar result is not checked before enable; runtime guards can reject installation',
 'Absolute vector base and actual installed callbacks not observed on hardware',
 'No proof of final physical buffer use or complete interrupt timing'])
 (out/'gnu_verified.txt').write_text(listing);(out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS:16 hashes, block0 roundtrip, {len(WINDOWS)} windows, {len(EDGES)} edges, {len(CHECKS)} instructions, {len(LITERALS)} pools, 30 records, {tests} decoded bitmap cases')
if __name__=='__main__':main()
