#!/usr/bin/env python3
"""Offline S33 V1.1 selected source-table dispatcher and manifest-backed numerical grid extraction."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x25283C,0x2528BC,'ConcreteSourceGetter'),
 (0x253570,0x2535E0,'SourceDispatcher'),
 (0x252B34,0x252D60,'SelectorZeroSourceTablesAndCachedPointer'),
 (0x252AAA,0x252AB8,'SharedDispatcherReturn'),
 (0x1FD514,0x1FD60C,'SourcePairReadsAndGridInterpolation')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/source_numeric_grids';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={2435260: 2438512, 2435868: 9017056, 2436448: 9026336, 2436452: 1348644, 2436456: 9208336, 2436460: 9244736, 2436464: 9281136, 2436468: 9317536, 2436472: 9062736, 2436476: 9099136, 2436480: 9135536}
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
 edges=[(0x253592,0x252B34),(0x2535DA,0x252AAA),(0x252B4E,0x252D54)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={2438540: 'cmp_s\tr14,0', 2438544: 'mov_s\tr0,r13', 2435908: 'ld\tr15,[pcl,-40]', 2435912: 'ldb_s\tr0,[r15,0xe]', 2435914: 'cmp_s\tr0,0x1', 2435922: ';0x252d60', 2436272: ';0x252d68', 2436274: 'st_s\tr0,[r15,0x24]', 2436298: ';0x252d6c', 2436300: 'st_s\tr0,[r15,0x24]', 2436322: ';0x252d70', 2436324: 'st_s\tr0,[r15,0x24]', 2436336: ';0x252d74', 2436338: 'st_s\tr0,[r15,0x24]', 2436342: 'ld_s\tr0,[r15,0x24]', 2436364: ';0x252d60', 2436366: 'st_s\tr0,[r15,0x28]', 2436390: ';0x252d78', 2436392: 'st_s\tr0,[r15,0x28]', 2436414: ';0x252d7c', 2436416: 'st_s\tr0,[r15,0x28]', 2436428: ';0x252d80', 2436430: 'st_s\tr0,[r15,0x28]', 2436434: 'ld_s\tr0,[r15,0x28]', 2086240: 'ldw_s\tr1,[r13,0x4]', 2086248: 'ldw_s\tr3,[r13,0]', 2086330: 'ldw_s\tr0,[r13,0x6]', 2086332: 'ldw_s\tr1,[r13,0x2]'}
 for a,n in checks.items():assert n in line(a),line(a)
 grids=[];block=info[5];payload=ps[5];width,height=130,70;size=width*height*4
 addresses=sorted({v for v in literals.values() if 0x89bb20<=v<=0x8e2ca0})
 assert len(addresses)==8 and min(b-a for a,b in zip(addresses,addresses[1:]))==size
 assert all((address-addresses[0])%size==0 for address in addresses)
 for address in addresses:
  offset=address-block['load_address_candidate'];data=payload[offset:offset+size]
  assert len(data)==size
  pairs=list(struct.iter_unpack('<HH',data))
  resets=[i+1 for i in range(len(pairs)-1) if pairs[i+1][1]<pairs[i][1]]
  assert resets==[width*i for i in range(1,height)],hex(address)
  filename=f'grid_{address:08x}.bin';(out/filename).write_bytes(data)
  grids.append(dict(address=hex(address),block=5,block_offset=hex(offset),bytes=size,
   file=filename,sha256=sha(data),observed_layout=dict(columns=width,rows=height,pair_format='two little-endian uint16'),
   second_component_decreases_at=resets,
   first_component_range=[min(x for x,y in pairs),max(x for x,y in pairs)],
   second_component_range=[min(y for x,y in pairs),max(y for x,y in pairs)],
   first_pairs=pairs[:4]))
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  extracted_grids=grids,
  cached_pointer_cells=['0x899704','0x899708'],
  observations=['Dispatcher selector0 calls 0x252b34, which returns fixed firmware table addresses or a cached pointer',
   'Two selection families update shared record+0x24 or +0x28, and unmatched branches can reuse previous value',
   'Eight selected source ranges in verified block05 each contain 9100 halfword pairs with 130-column periodic resets',
   'The interpolator reads these pairs as numerical components; color, calibration and scene meanings remain unassigned'],
  limits=['Only dispatcher selector0 target body is followed here; other selector tables remain open',
   '130 by70 is an observed storage arrangement, not a sensor or output-image resolution claim',
   'State readers, thresholds and table provenance within Nikon algorithms remain unresolved',
   'No runtime selector observation, JPEG content or photographic correctness proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
