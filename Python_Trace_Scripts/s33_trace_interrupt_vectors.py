#!/usr/bin/env python3
"""Offline S33 V1.1 interrupt table bootstrap, generated vectors and common CPU dispatch."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x29F628,0x29F656,'BootstrapRequestsSlotsZeroToFifteen'),
 (0x2F6E68,0x2F6F04,'AllocateAndInitializeInterruptTable'),
 (0x2F6F04,0x2F6F4C,'GenerateSixteenAbsoluteJumpVectors'),
 (0x29F19C,0x29F1A8,'ReadAndAlignVectorBase'),
 (0xB2F74,0xB3054,'SixteenNumberedStubs'),
 (0xB3054,0xB3096,'CommonEntryCpuStatusAndInterruptLinks'),
 (0xB3096,0xB30CE,'SaveKernelAndInterruptNumber'),
 (0xB3150,0xB31AA,'SelectRuntimeTableHandlerAndInvoke'),
 (0x29F60C,0x29F628,'BootstrapVectorBase800'),
 (0x29F1A8,0x29F1BC,'VectorBaseSetterReturnsPreviousBase'),
 (0x1F0C72,0x1F0C7E,'AlternativeVectorBaseFromKernelConfiguration'),
 (0x265244,0x265298,'RewriteVectorFourTargetAndInvalidate'),
 (0x265F90,0x265FE4,'RewriteVectorFiveTargetAndInvalidate'),
 (0xB320E,0xB32BC,'SelectedRestoreAndExceptionReturn'),
 (0xB32BC,0xB32F0,'AdditionalRegisterRestoreBranch')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/interrupt_vectors';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={0x265210:0x2646A0,0x265F5C:0x2655D4}
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
  vec,vecelf=Path(td)/'vectors.bin',Path(td)/'vectors.elf'
  vec.write_bytes(b''.join(struct.pack('<HHHH',0x2020,0x0F80,(0xB2F74+14*i)>>16,(0xB2F74+14*i)&0xFFFF) for i in range(16)))
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc',
   '--rename-section','.data=.text,alloc,load,readonly,code,contents',vec,vecelf])
  vt=run([tools/'objdump','-d','-m','arc:ARC700','-EL',vecelf])
  for i in range(16):
   assert re.search(rf'^\s*{i*8:x}:.*\tj\t0x{0xB2F74+14*i:x}\s*$',vt,re.M),vt
  listings.append('SYNTHETIC vector bytes generated from verified builder, base zero for decoding only\n'+vt.replace(str(vecelf),'synthetic-vectors.elf'))
 listing='\n'.join(listings)
 def line(a):
  hits=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
  assert len(hits)==1,(hex(a),hits)
  return hits[0]
 edges=[(2750028, 3108456), (3108550, 2526948), (3108614, 2748828), (733052, 733268), (733066, 733268), (733080, 733268), (733094, 733268), (733108, 733268), (733122, 733268), (733136, 733268), (733150, 733268), (733164, 733268), (733178, 733268), (733192, 733268), (733206, 733268), (733220, 733268), (733234, 733268), (733248, 733268), (733262, 733268)]
 edges += [(0x29F628,0x29F1A8),(0x1F0C72,0x29F1A8)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={2750026: 'mov_s\tr0,r15', 2750032: 'mov_s\tr1,0xf', 2749996: 'mov_s\tr15,0', 3108534: 'st.as\tr2,[r17,137]', 3108544: 'st.as\tr14,[r17,138]', 3108556: 'st.as\tr0,[r17,142]', 3108560: 'st.as\tr13,[r17,139]', 3108564: 'st.as\tr16,[r17,140]', 3108578: 'st_s\tr14,[r0,0]', 3108580: 'st_s\tr1,[r0,0x8]', 3108584: 'add_s\tr0,r0,0xc', 3108640: 'mov\tlp_count,0x10', 3108656: 'sth\tr5,[r0]', 3108660: 'sth\tr4,[r0,2]', 3108672: 'add_s\tr0,r0,0x8', 2748828: 'lr\tr0,[int_vector_base]', 2748834: 'and\tr0,r0,-1024', 733268: 'sub\tsp,sp,164', 733300: 'lr\tr0,[status32_l2]', 733318: 'lr\tr0,[status32_l1]', 733368: 'mov_s\tr4,r1', 733544: '0x234', 733590: 'ld\tr1,[r3,4]', 733594: 'add1_s\tr2,r2,r2', 733596: 'add2\tr2,r1,r2', 733600: 'ld_s\tr1,[r2,0]', 733602: 'ld_s\tr0,[r2,0x8]', 733604: 'jl_s.d\t[r1]', 733056: 'mov_s\tr1,0', 733070: 'mov_s\tr1,0x1', 733084: 'mov_s\tr1,0x2', 733098: 'mov_s\tr1,0x3', 733112: 'mov_s\tr1,0x4', 733126: 'mov_s\tr1,0x5', 733140: 'mov_s\tr1,0x6', 733154: 'mov_s\tr1,0x7', 733168: 'mov_s\tr1,0x8', 733182: 'mov_s\tr1,0x9', 733196: 'mov_s\tr1,0xa', 733210: 'mov_s\tr1,0xb', 733224: 'mov_s\tr1,0xc', 733238: 'mov_s\tr1,0xd', 733252: 'mov_s\tr1,0xe', 733266: 'mov_s\tr1,0xf'}
 checks.update({0x29F622:'mov_s\tr0,0x800',0x29F1A8:'lr\tr1,[int_vector_base]',
  0x29F1B0:'and\tr0,r0,-1024',0x29F1B4:'sr\tr0,[int_vector_base]',
  0x29F1BA:'mov_s\tr0,r1',0x1F0C76:'ld.as\tr0,[r13,94]',
  0x265248:'add\tr0,r0,0x20',0x26524C:'0x265210',0x265270:'st.di\tr1,[r0,4]',
  0x265274:'[dc_ivdc]',0x26527C:'[ivic]',0x265F94:'add\tr0,r0,0x28',
  0x265F98:'0x265f5c',0x265FBC:'st.di\tr1,[r0,4]',0x265FC0:'[dc_ivdc]',0x265FC8:'[ivic]',
  0xB3212:'[aux_macmode]',0xB325A:'[lp_start]',0xB3268:'[lp_end]',
  0xB3276:'mov\tlp_count,r0',0xB32AA:'[status32_l2]',0xB32B4:'add\tsp,sp,164',
  0xB32B8:'j.f\t[r30]',0xB32EA:'ld\tgp,[sp,132]'})
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  generated_vectors=[dict(slot=i,offset=hex(i*8),stub=hex(0xB2F74+14*i)) for i in range(16)],
  observations=['Bootstrap requests inclusive runtime interrupt range 0..15',
   'Initializer allocates 16*12 bytes and publishes kernel+0x238; default handler 0x319018 and datum equal to index',
   'Vector builder reads int_vector_base aligned down to 1024 bytes and writes 16 absolute jumps, stride8',
   'Numbered stubs save r1 and pass index to common entry 0xb3054',
   'Common entry reads runtime table via kernel+0x238 and invokes selected handler with datum+8',
   'Bootstrap requests int_vector_base=0x800 through aligned setter returning previous base',
   'Conditional code rewrites vector4/5 target words to 0x2646a0/0x2655d4 and writes cache invalidation auxiliaries',
   'Selected return restores CPU accumulator/loop state and frame, writes status32_l2 and uses j.f r30; alternate scheduler branches remain',
   'Allocation return is stored and used without a local null check in selected initializer body'],
  limits=['Actual runtime base and allocation not observed; bootstrap sets 0x800 but other code can replace base or rewrite vectors 4/5',
   'Reset-to-bootstrap execution, interrupt enablement and exception return coverage remain incomplete',
   'Synthetic decoding verifies generated instruction format, not hardware execution'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
