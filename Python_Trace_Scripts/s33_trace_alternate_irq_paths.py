#!/usr/bin/env python3
"""Offline S33 V1.1 alternate interrupt entries, callback tables and vector writers."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x2646A0,0x2646DC,'AlternateFourInterruptFrame'),
 (0x264750,0x2647F8,'AlternateFourCallbackScan'),
 (0x2655D4,0x265610,'AlternateFiveInterruptFrame'),
 (0x265684,0x26572C,'AlternateFiveCallbackScan'),
 (0x16DA28,0x16DA68,'FixedVectorWritersAndContextAccessors'),
 (0x16D3D8,0x16D3F0,'WriteAbsoluteJumpToSuppliedAddress'),
 (0x265244,0x265298,'RelativeVectorFourRetarget'),
 (0x265F90,0x265FE4,'RelativeVectorFiveRetarget'),
 (0x159ABA,0x159AFA,'FirstCallerPreservesEntryAndPreparesVector'),
 (0x159D2A,0x159D6A,'SecondCallerPreservesEntryAndPreparesVector'),
 (0x265214,0x265244,'FirstEntryStackSelection'),
 (0x265F60,0x265F90,'SecondEntryStackSelection'),
 (0x337218,0x33723A,'FirstEntryReadyHandshake'),
 (0x23FB10,0x23FB30,'SecondEntryReadyHandshake')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/alternate_irq_paths';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={1497924: 4340480, 1497932: 1056, 1497936: 2511380, 1497940: 2508448, 1497944: 5160, 1497948: 2514784, 1497952: 2512340, 1496328: 260055072, 2511376: 2508448, 2514780: 2512340}
 for a,v in literals.items():assert word(a)==v
 tables=[]
 for a,head,ids in [(0x427C00,(0x0FEF0050,0x0FEF007C,4),[8,0,1,6]),(0x427F8C,(0x0FEF0328,0x0FEF0314,4),[2,3,4,5])]:
  o=a-info[1]['load_address_candidate'];d=ps[1][o:o+44]
  assert struct.unpack_from('<IIH',d)==head
  rows=[]
  for i in range(4):
   selector,b0,b1,cb=struct.unpack_from('<HBBI',d,12+8*i)
   assert selector==ids[i] and cb==0
   rows.append(dict(selector=selector,bits=[b0,b1],initial_callback=cb,record=hex(a+12+8*i)))
  tables.append(dict(base=hex(a),registers=[hex(head[0]),hex(head[1])],rows=rows))
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
 edges=[(0x16DA2A,0x16D3D8),(0x16DA32,0x16D3D8),(0x16DA4A,0x16D3D8),(0x16DA52,0x16D3D8)]
 edges += [(0x159AC0,0x16DA38),(0x159AD6,0x16DA28),(0x159AE0,0x16DA68),
  (0x159D30,0x16DA58),(0x159D46,0x16DA48),(0x159D50,0x16DA68)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={2508448: 'sub\tsp,sp,164', 2508474: '[status32_l2]', 2508494: '[status32_l1]', 2512340: 'sub\tsp,sp,164', 2512366: '[status32_l2]', 2512386: '[status32_l1]', 2508624: '0x427c04', 2508640: '0x427c00', 2508696: 'ld.di\tr0,[r1,4]', 2508728: 'jl\t[r0]', 2508764: 'sth.di\tr0,[r2]', 2512516: '0x427f90', 2512532: '0x427f8c', 2512588: 'ld.di\tr0,[r1,4]', 2512620: 'jl\t[r0]', 2512656: 'sth.di\tr0,[r2]', 1497660: 'st.di\tr0,[r2]', 1497664: 'st.di\tr1,[r2,8]', 1497692: 'st.di\tr0,[r2,4]', 1497696: 'st.di\tr1,[r2,12]', 1496032: 'st.di\tr3,[r0]', 1496042: 'st.di\tr1,[r0,4]', 2511472: 'st.di\tr1,[r0,4]', 2514876: 'st.di\tr1,[r0,4]'}
 checks.update({0x16DA2A:'b.d',0x16DA2E:';0x16db50',0x16DA32:'b.d',0x16DA36:';0x16db54',
  0x16DA4A:'b.d',0x16DA4E:';0x16db5c',0x16DA52:'b.d',0x16DA56:';0x16db60',
  0x159ABA:'0x337218',0x159AC4:'ld.di\tr1,[r14]',0x159ACE:'st.di\tr15,[r13]',
  0x159AF2:'cmp_s\tr0,0x2',0x159AF4:';0x159aee',
  0x159D2A:'0x23fb10',0x159D34:'ld.di\tr1,[r13]',0x159D3E:'st.di\tr15,[r13]',
  0x159D62:'cmp_s\tr0,0x2',0x159D64:';0x159d5e',
  0x265234:'0x423b08',0x265240:'mov\tsp,r0',0x265F80:'0x423b0c',0x265F8C:'mov\tsp,r0',
  0x337234:'mov_s\tr0,0x2',0x337236:'st.di\tr0,[r13]',
  0x23FB2A:'mov_s\tr0,0x2',0x23FB2C:'st.di\tr0,[r14]'})
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  alternate_tables=tables,
  observations=['Alternate targets create their own 164-byte interrupt frame and scan four-entry tables',
   'Callbacks are gated by two bit tests and followed by halfword bit writeback',
   'Fixed-address writers construct absolute jumps at 0x420 and 0x1428; they differ from base-relative retarget code',
   'Delay slots make entries 0x16da28/48 select default targets 0x265214/0x265f60 and entries 0x16da2e/4e select alternate targets',
   'Actual setter calls enter 0x16da38/58 after the preceding literal load and preserve caller r0/r1 into 0x423b00 structure',
   'Callers supply entry 0x337218/0x23fb10 and previously prepared pointer; vector paths may select sp from that pointer',
   'Ready state changes from one to two at the alternate execution entry while original callers poll for two'],
  limits=['Two setter/install call paths are resolved; complete lifecycle, restoration callers and table writers remain open',
   'No proof alternate paths preserve all notifications of initial SD dispatch tables',
   'No actual vector RAM values, runtime interrupt or persistence observed'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
