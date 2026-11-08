#!/usr/bin/env python3
"""Offline S33 V1.1 worker pointer origins, state-indexed banks and initializer area carving."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x15C4F0,0x15C4FC,'IntermediateAndDescriptorBases'),
 (0x15C586,0x15C592,'SourceGetterReturnPublication'),
 (0x15C5DA,0x15C60E,'StateIndexedPointerBankSelection'),
 (0x15C612,0x15C644,'WorkerDescriptorPointerBuilder'),
 (0x247398,0x2473C6,'ThreePointerAndGeometryCopy'),
 (0x2526A2,0x2526C8,'GetterInstallationInFifthDescriptorWord'),
 (0x15E582,0x15E594,'GetterDescriptorToConfiguration'),
 (0x15E314,0x15E31E,'PointerBankInitializationBase'),
 (0x15E614,0x15E686,'FourSlotAreaCarving'),
 (0x25283C,0x2528BC,'SourceGetterDispatcher')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/worker_buffer_origins';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={1427212: 3743928, 1427216: 3744076, 1427220: 3744552, 1427228: 3568784, 1435072: 3743928, 2434760: 2435132, 2435260: 2438512, 2434704: 9017056}
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
 edges=[(0x15E318,0xAD90C),(0x15E622,0x15E664)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={1426672: ';0x15c710', 1426674: ';0x15c714', 1426824: 'ld_s\tr0,[r0,0x40]', 1426830: 'jl_s\t[r0]', 1426832: 'st_s\tr0,[r13,0]', 1426906: ';0x15c70c', 1426908: 'ld\tr0,[r2,144]', 1426912: 'ldb\tr1,[r2,140]', 1426918: 'add2_s\tr2,r2,r1', 1426922: 'ld\tr16,[r2,32]', 1426926: 'ld_s\tr1,[r2,0x40]', 1426934: 'ld\tr16,[r2,48]', 1426938: 'ld_s\tr1,[r2,0x50]', 1426942: 'ld\tr16,[r2]', 1426946: 'ld_s\tr1,[r2,0x10]', 1426948: 'mov_s\tr18,r1', 1426962: 'ld_s\tr0,[r13,0]', 1426964: 'st\tr16,[r14]', 1426968: 'st_s\tr0,[r14,0x10]', 1427008: 'st\tr18,[r14,4]', 2388902: 'st.di\tr1,[r2,64]', 2388910: 'ld_s\tr1,[r0,0x4]', 2388912: 'st.di\tr1,[r2,68]', 2388916: 'ld_s\tr1,[r0,0x10]', 2388918: 'st.di\tr1,[r2,80]', 2434740: ';0x2526c8', 2434742: 'st\tr15,[r5,16]', 1435018: 'ld_s\tr1,[r1,0x10]', 1435026: 'st_s\tr1,[r0,0x40]', 1434388: ';0x15e5c0', 1435166: 'mov\tlp_count,0x4', 1435180: 'st_s\tr13,[r14,0x20]', 1435182: 'mov_s\tr13,0x8c28', 1435198: 'st_s\tr0,[r14,0x30]', 1435210: 'st_s\tr1,[r14,0x40]', 1435222: 'st_s\tr1,[r14,0x50]', 1435232: 'add_s\tr14,r14,0x4', 1435240: 'st_s\tr13,[r14,0]', 1435242: 'mov_s\tr1,0x40c08', 1435256: 'st_s\tr2,[r14,0x10]', 1435268: 'add_s\tr14,r14,0x4', 2435134: 'ld.as\tr0,[pcl,-107]', 2435138: 'ldw_s\tr1,[r0,0x18]', 2435140: ';0x2528bc', 2435158: 'jl_s\t[r2]', 2435254: 'jl_s\t[r2]'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  scaled_pcl_pool=dict(site='0x25283e',scaled_offset=-107,computed_pool=hex((0x25283e&~3)-107*4),value=hex(word((0x25283e&~3)-107*4))),
  pointer_banks={'base':'0x3920b8','index_byte':'0x392144','state_word':'0x392148',
   'state0_offsets':['0x20','0x40'],'state1_offsets':['0x30','0x50'],'other_state_offsets':['0','0x10'],
   'entry_stride':4,'initializer_slots':4},
  area_carving={'special':{'areas_per_slot':4,'bytes_per_area':0x8c28},
   'other':{'areas_per_slot':2,'bytes_per_area':0x40c08},'alignment':8},
  observations=['Grid and destination pointers come from state-indexed address banks, not new allocation per worker request',
   'Source pointer is the return of configuration+0x40 callback saved in intermediate 0x39214c',
   'Second concrete descriptor installs getter 0x25283c, which calls dispatcher 0x253570 selected by halfword at 0x8996f8',
   'Initializer carves four slots using fixed sizes and alignment, then later admission remains outside this window'],
  limits=['Index is a byte; local selection has no bound check proving index below four',
   'Carving arithmetic does not prove backing allocation or capacity of the complete input region',
   'Source dispatcher final pointer, full buffer ownership and post-worker destination consumer remain unresolved',
   'No runtime mode, concurrency or JPEG persistence proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
