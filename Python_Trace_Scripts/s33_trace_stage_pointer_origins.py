#!/usr/bin/env python3
"""Offline origins of six shared pointer cells, workspace arena and default optional fields."""
import json,re,struct,tempfile,random
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x15EE60,0x15EE68,'ClearPointerConfig'),(0x15EFF0,0x15F032,'BuilderInputsAndWorkspaceBinding'),
 (0x15F062,0x15F09A,'BuildAndInstallPointerConfig'),(0x243FA2,0x243FE4,'QueryRegionsAndCombineCapacity'),
 (0x24405C,0x244078,'WorkspaceFirstBase'),(0x2440EA,0x2440F8,'WorkspaceNextBases'),
 (0x2441EE,0x244224,'AlternateWorkspaceBasesAndCapacityCheck'),
 (0x244234,0x244258,'PointerPairZeroPrefix'),(0x244270,0x244274,'PointerPairZeroAlternate'),
 (0x244290,0x24429A,'PointerPairOne'),(0x2442B4,0x2442BE,'PointerPairTwo'),
 (0x243FE4,0x243FEC,'Default800OptionalDisabled'),(0x24407C,0x244084,'Default1000OptionalDisabled'),
 (0x1774C8,0x1774E6,'RegionQueryDispatch'),(0x17750C,0x177532,'Region3And4Cases'),
 (0x177598,0x1775A2,'RegionQueryReturn'),(0x2696F4,0x269710,'FixedRegionBases'),
 (0x15EAF4,0x15EB4A,'FourTriplesSeparateBank'),(0x15EB84,0x15EB9C,'SeparateBankCapacityGuard')]
EDGES=[(0x15F024,0x243F48),(0x15F082,0x244234),(0x15F08E,0x24A488),
 (0x243FA8,0x1774C8),(0x243FBE,0x1774C8)]
CHECKS={0x1774E0:';0x1775fc',0x177516:'mov_s\tr0,0',0x17751A:'st_s\tr0,[r14,0]',
 0x17752A:'mov_s\tr0,0x3',0x17752E:'st_s\tr0,[r14,0]',0x243FE8:'mov_s\tr0,0',0x244080:'mov_s\tr0,0',0x15EE60:';0x15f230',0x15EE66:'mov_s\tr1,0x4c',
 0x15EFF0:'ld.as\tr17,[pcl,142]',0x15EFF4:'ld.as\tr18,[pcl,142]',0x15F002:'ld.as\tr16,[pcl,149]',
 0x15F022:'mov_s\tr0,r17',0x15F028:'mov\tr7,r16',0x15F06E:';0x15f230',
 0x15F070:'mov_s\tr1,r16',0x15F072:'mov_s\tr2,r17',0x15F07E:'mov_s\tr3,r18',
 0x243FA6:'mov_s\tr0,0x3',0x243FC2:'mov_s\tr0,0x4',0x243FD0:'add_s\tr0,r0,r1',
 0x243FD2:'st_s\tr0,[sp,0x10]',0x244074:'st\tr18,[r13,16]',
 0x2440EC:'st_s\tr1,[r13,0x14]',0x2440F0:'st_s\tr1,[r13,0x18]',
 0x244200:'st_s\tr1,[r13,0x10]',0x24421C:'cmp_s\tr0,r1',0x24421E:';0x24422c',
 0x244240:'ld_s\tr15,[r1,0x10]',0x24424E:'st_s\tr15,[r0,0]',
 0x244250:'ld_s\tr13,[r1,0x8]',0x244256:'st_s\tr15,[r0,0x4]',0x244272:'st_s\tr13,[r0,0x4]',
 0x244290:'ld_s\tr13,[r1,0x14]',0x244292:'st_s\tr13,[r0,0x14]',
 0x244298:'st_s\tr2,[r0,0x18]',0x2442B4:'ld_s\tr13,[r1,0x18]',0x2442B6:'st_s\tr13,[r0,0x28]',
 0x2442BC:'st_s\tr2,[r0,0x2c]',0x243FEA:'st_s\tr0,[r15,0x4]',0x244082:'st_s\tr0,[r14,0x4]',
 0x1774DC:'ldb.x\tr0,[r12,r0]',0x1774E2:'add1_s\tr12,r12,r0',
 0x17750E:'mov_s\tr0,0x1',0x177510:'add3\tr0,r0,1584',0x177518:'bset_s\tr0,r0,0xc',
 0x177520:'mov_s\tr0,0x1',0x177522:'add_s\tr0,r0,0x4180',0x17752C:'asl_s\tr0,r0,0xc',
 0x269702:';0x26982c',0x15EAFC:'mov_s\tr15,0x4',0x15EB48:'add_s\tr13,r13,0xc',
 0x15EB8E:'ld\tr1,[r16,8]',0x15EB94:';0x15eb9c'}
LITERALS={0x15F228:0x4452CC,0x15F22C:0x445308,0x15F230:0x445380,0x15F254:0x4453DC,
 0x1775FC:0x2696F4,0x26982C:0x0F798000,0x15EDAC:0x392288}
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 def raw(a,n):return ps[0][a-info[0]['load_address_candidate']:a-info[0]['load_address_candidate']+n]
 def word(a):return struct.unpack('<I',raw(a,4))[0]
 for a,v in LITERALS.items():assert word(a)==v,hex(a)
 scaled={0x15EFF0:(142,0x4452CC),0x15EFF4:(142,0x445308),0x15F002:(149,0x4453DC)}
 for a,(imm,v) in scaled.items():assert word((a&~3)+4*imm)==v
 jumps=raw(0x1774E6,12)
 assert 0x1774E6+2*jumps[3]==0x17750C and 0x1774E6+2*jumps[4]==0x17751E
 region_base=word(0x26982C);region3=region_base+8*1584;region4=region_base+0x4180
 assert region3==0x0F79B180 and region3+0x1000==region4==0x0F79C180
 assert region4+0x3000==0x0F79F180
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-stage-origins-') as td:
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
 # Only three pointer-building slices are interpreted; geometry multiplies are outside them.
 def pointer_slices(p0,p1,p2,d0,d1,mode):
  reg={'r0':0x445380,'r1':0x4453DC,'r2':0,'r13':mode};mem={0x4453EC:p0,0x4453F0:p1,0x4453F4:p2,0x4453E4:d0,0x4453E8:d1};out={};zero=False
  for start,end in [(0x244240,0x244258),(0x244290,0x24429A),(0x2442B4,0x2442BE)]:
   pc=start
   while pc<end:
    if pc==0x244274:break
    size,op,args,_=decoded[pc];parts=args.split(';')[0].strip().split(',')
    if op in ('ld_s','st_s'):
     m=re.search(r'\[(r\d+),(0x[0-9a-f]+|\d+)\]',args);addr=reg[m[1]]+int(m[2],0)
     if op=='ld_s':reg[parts[0]]=mem[addr]
     else:out[addr]=reg[parts[0]]&0xFFFFFFFF
    elif op=='lsr_s':reg[parts[0]]=reg[parts[1]]>>1
    elif op=='sr':assert '[aux_macmode]' in args
    elif op=='cmp_s':zero=reg[parts[0]]==int(parts[1],0)
    elif op=='bne_s':
     if not zero:
      pc=int(re.search(r';0x([0-9a-f]+)',args)[1],16);end=0x244274;continue
    elif op=='add_s':reg[parts[0]]=(reg[parts[1]]+reg[parts[2]])&0xFFFFFFFF
    else:raise AssertionError((hex(pc),op,args))
    pc+=size
  return out
 rng=random.Random(3303);cases=0
 for i in range(1024):
  values=[rng.getrandbits(32) for _ in range(5)] if i else [0x0F79B180,0x0F79B980,0x0F79BD80,0x100,0x80]
  p0,p1,p2,d0,d1=values
  expected={0x445380:p0,0x445384:(p0+d0)&0xFFFFFFFF,0x445394:p1,0x445398:(p1+d1)&0xFFFFFFFF,0x4453A8:p2,0x4453AC:(p2+d1)&0xFFFFFFFF}
  for mode in (0,1):assert pointer_slices(*values,mode)==expected;cases+=1
 out=ROOT/'Ghidra_Results/ghidra_reports/stage_pointer_origins';out.mkdir(parents=True,exist_ok=True)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],script_sha256=sha(Path(__file__).read_bytes()),
 block_sha256={str(b['index']):b['sha256'] for b in bs},windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
 checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in EDGES],checked_instructions=len(CHECKS),checked_literals={hex(a):hex(v) for a,v in LITERALS.items()},
 pointer_config='0x445380',workspace_descriptor='0x4453dc',decoded_pointer_build_cases=cases,
 region_queries=[dict(selector=3,base=hex(region3),size='0x1000'),dict(selector=4,base=hex(region4),size='0x3000')],
 observations=['Six runtime source cells are fields of stage2000 config produced by0x244234',
 'Three workspace bases plus two offsets form the six pointer cells identically in both local mode branches',
 'Region queries3/4 return consecutive spans totaling0x4000; constructor compares consumed amount with combined capacity',
 'Selected default builders write config+4=0 for800/1000, disabling their optional runtime+4 setter paths initially',
 'Separate bank0x392288 producer loops four times; capacity check follows its construction'],
 limits=['Pointer slices do not model geometry or the complete builder retry loop',
 'Region identity is a static address layout, not proof of physical RAM or current ownership',
 'No global proof of later config writers, all index bounds, direction or last physical buffer use'])
 (out/'gnu_verified.txt').write_text(listing);(out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS:16 hashes, block0 roundtrip, {len(WINDOWS)} windows, {len(EDGES)} edges, {len(CHECKS)} instructions, {len(LITERALS)} pools, {cases} decoded pointer builds')
if __name__=='__main__':main()
