#!/usr/bin/env python3
"""Offline S33 V1.1 source-table threshold readers and decoded selection branch model."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x252B34,0x252D60,'SelectorZeroThresholdsAndSelection'),
 (0x14941C,0x149438,'StateReaderAndCurveWrapper'),
 (0x149EAC,0x149EB0,'HardwareReaderAlias'),
 (0x148250,0x14828E,'CurveHardwareAndStateReaders'),
 (0x149362,0x14936E,'CurveWrapperReturn'),
 (0x23300C,0x233022,'HardwareHalfwordReader'),
 (0x233798,0x2337A0,'ThresholdRegimeByteReader'),
 (0xD0528,0xD0530,'FamilyStateByteReader'),
 (0xDE254,0xDE260,'AlternateFamilyStateReader')]
def selection_reference(current,category,thresholds,markers,family,cached,lower_marker=1):
 base,t1,t2,t3=thresholds;k1,k2,k3=markers
 candidates=([0x8c8210,0x8d1040,0x8d9e70,0x8e2ca0] if family=='A'
             else [0x89bb20,0x8a4950,0x8ad780,0x8b65b0])
 if (base<=current<t1 and category<=k1) or category==0:return candidates[0]
 if t1<=current<t2 and lower_marker<=category<=k2:return candidates[1]
 if t2<=current<t3 and k1<=category<=k3:return candidates[2]
 if current>=t3 and category>=k2:return candidates[3]
 return cached

def verify_selection_model(listing,literals):
 import random
 decoded={}
 for raw in listing.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\t[^\t]+\t(\S+)\t?(.*)$',raw)
  if m and 0x252c9e<=int(m[1],16)<0x252d54:decoded[int(m[1],16)]=(m[2],m[3])
 addresses=sorted(decoded);following=dict(zip(addresses,addresses[1:]+[0x252d54]))
 def execute(current,category,thresholds,markers,family,cached):
  base,t1,t2,t3=thresholds;k1,k2,k3=markers
  regs={22:current,13:category,24:base,16:t1,21:t2,14:t3,20:k1,17:k2,19:k3,15:0x8996e0}
  mem={0x8996e0:1,0x899704:cached,0x899708:cached};cmp=0
  pc=0x252c9e if family=='A' else 0x252cfa
  for _ in range(150):
   if pc==0x252d54:return regs[0]
   op,args=decoded[pc];nextpc=following[pc]
   if op=='mov_s':
    a,b=map(lambda x:int(x[1:]),args.split(','));regs[a]=regs[b]
   elif op=='cmp_s':
    a,b=args.split(',');cmp=regs[int(a[1:])]-(regs[int(b[1:])] if b.startswith('r') else int(b,0))
   elif op.startswith('b'):
    target=int(re.search(r';0x([0-9a-f]+)',args)[1],16)
    take={'b_s':True,'blt_s':cmp<0,'bge_s':cmp>=0,'ble_s':cmp<=0,'bgt_s':cmp>0,'bne_s':cmp!=0,'beq_s':cmp==0}[op]
    if take:nextpc=target
   elif op=='ld_s' and '[pcl,' in args:
    regs[int(args.split(',')[0][1:])]=literals[int(re.search(r';0x([0-9a-f]+)',args)[1],16)]
   elif op in ('ld_s','ldb_s','st_s'):
    rr,base_reg,off=re.fullmatch(r'r(\d+),\[r(\d+),(0x[0-9a-f]+|\d+)\]',args).groups()
    rr,addr=int(rr),regs[int(base_reg)]+int(off,0)
    if op=='st_s':mem[addr]=regs[rr]
    else:regs[rr]=mem[addr]
   else:raise AssertionError((hex(pc),op,args))
   pc=nextpc
  raise AssertionError('Selection did not return')
 rng=random.Random(0x533252);n=0;cache_hits=0
 for thresholds in [(-347,99,182,265),(-347,62,153,222)]:
  values=set(range(-400,401,13))
  for boundary in thresholds:values.update((boundary-1,boundary,boundary+1))
  for family in ('A','B'):
   for category in range(8):
    for current in sorted(values):
     cached=0xdead0000+category
     expected=selection_reference(current,category,thresholds,(2,3,4),family,cached)
     assert execute(current,category,thresholds,(2,3,4),family,cached)==expected
     cache_hits+=expected==cached;n+=1
 for _ in range(2000):
  thresholds=(-347,*sorted(rng.sample(range(-100,401),3)))
  category=rng.randrange(8);current=rng.randrange(-500,600);family=rng.choice(('A','B'));cached=0xdeadbeef
  expected=selection_reference(current,category,thresholds,(2,3,4),family,cached)
  assert execute(current,category,thresholds,(2,3,4),family,cached)==expected
  cache_hits+=expected==cached;n+=1
 return dict(comparisons=n,cached_returns=cache_hits,assumptions='bounded signed values, markers 2/3/4, lower marker1; no helpers or firmware runtime')

def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/source_table_selection';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={1344056: 3737836, 1344144: 3567378, 2306068: 267517976, 2308000: 3580864, 853296: 3561416, 2435868: 9017056, 2436452: 1348644, 2436448: 9026336, 2436456: 9208336, 2436460: 9244736, 2436464: 9281136, 2436468: 9317536, 2436472: 9062736, 2436476: 9099136, 2436480: 9135536}
 for a,v in literals.items():assert word(a)==v
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
 edges=[(1348636, 1344136), (1348658, 1344080), (1351340, 1344120), (1344122, 2306060), (2435924, 1348636), (2435930, 1351340), (2435936, 2307992), (2436110, 853288), (2436248, 909908)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={1344090: 'cmp_s\tr0,0x6', 1344094: 'mov_s\tr1,0x6', 1344100: 'ldh.as.x\tr0,[r0,r1]', 1344104: 'sub\tr0,r0,750', 1344108: 'sexw_s\tr0,r0', 1344126: 'sub\tr0,r0,750', 1344130: 'sexw_s\tr0,r0', 1344138: 'ldb_s\tr0,[r0,0]', 2306072: 'ldh.di\tr0,[r0]', 2306076: 'sexw_s\tr0,r0', 2307994: 'ldb_s\tr0,[r0,0]', 853290: 'ldb_s\tr0,[r0,0]', 2435948: 'cmp_s\tr0,0x1', 2436012: 'asl\tr0,r18,0x3', 2436054: 'asl\tr0,r18,0x3', 2436096: 'asl\tr0,r18,0x3', 2436150: 'add2\tr0,r18,r18', 2436192: 'asl\tr0,r18,0x2', 2436234: 'add1\tr0,r18,r18', 2436114: 'cmp_s\tr0,0x6a', 2436342: 'ld_s\tr0,[r15,0x24]', 2436434: 'ld_s\tr0,[r15,0x28]'}
 for a,n in checks.items():assert n in line(a),line(a)
 def initial(a,n):
  candidates=[b for b in bs if b['load_address_candidate']<=a and a+n<=b['load_address_candidate']+len(ps[b['index']])]
  assert len(candidates)==1
  b=candidates[0];off=a-b['load_address_candidate'];return ps[b['index']][off:off+n]
 curve=list(struct.unpack('<7h',initial(0x3908ec,14)));assert curve==[403,750,874,947,1033,1138,1317]
 shifted=[v-750 for v in curve];assert shifted==[-347,0,124,197,283,388,567]
 initial_thresholds={name:[shifted[m-1]+weight*(shifted[m]-shifted[m-1])//10 for m,weight in zip((2,3,4),weights)] for name,weights in [('regime1',(8,8,8)),('other',(5,4,3))]}
 assert initial_thresholds=={'regime1':[99,182,265],'other':[62,153,222]}
 model=verify_selection_model(listing,literals)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  initial_curve=dict(address='0x3908ec',raw=curve,after_subtract750=shifted),
  initial_markers=list(initial(0x8996e1,3)),
  model_validation=model,initial_thresholds=initial_thresholds,
  state_sources={'category_byte':'0x366f12','hardware_halfword':'0x0ff20018','regime_byte':'0x36a3c0','family_byte_regime1':'0x3657c8'},
  threshold_weights={'regime1':[8,8,8],'other':[5,4,3],'denominator':10},
  observations=['Category read is a byte; current comparator is signed hardware halfword minus750',
   'Curve getter clamps upper indices to6 but has no local lower-bound clamp',
   'Two arithmetic regimes use 8/10 for all thresholds or 5/10,4/10,3/10 respectively',
   'Decoded selection branches agree with independent predicate model, including cached-pointer holes'],
  limits=['Physical meaning, timing and writers of state sources remain unresolved',
   'Initial curve and markers are payload values, not runtime snapshots',
   'Bounded model does not execute helpers, MMIO or firmware',
   'No photographic mode attribution, source lifetime or JPEG persistence proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
