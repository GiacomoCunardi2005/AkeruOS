#!/usr/bin/env python3
"""Offline S33 V1.1 runtime interrupt slots and grouped SD callback dispatch."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x16D3F0,0x16D428,'RuntimeInterruptHandlerInstall'),
 (0x231428,0x23148A,'RuntimeHandlerSlotRegistrar'),
 (0x265FE8,0x266030,'EnableGroupAndInstall0904'),
 (0x2660A8,0x2660CC,'CallDedicatedHandlersInOrder'),
 (0x16D902,0x16D906,'Select0900Table'),
 (0x16D988,0x16D9AE,'LogicalHandlerStore'),
 (0x264308,0x26437A,'Grouped0900Dispatch')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/transfer_irq_dispatch';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={1496332: 2506976, 1496336: 2298920, 1496348: 2507528, 2515152: 3584800, 2515156: 2515112, 2515160: 2308, 1497904: 4344880}
 for a,v in literals.items():assert word(a)==v
 o=0x424C30-info[1]['load_address_candidate'];data=ps[1][o:o+12+14*8]
 assert len(data)==124
 assert struct.unpack_from('<IIH',data)==(0x0FEF0040,0x0FEF002C,14)
 rows=[]
 for i in range(14):
  ident,b0,b1,cb=struct.unpack_from('<HBBI',data,12+8*i)
  rows.append(dict(index=i,id=hex(ident),bits=[b0,b1],initial_callback=hex(cb)))
 assert rows[10]==dict(index=10,id='0x904',bits=[3,3],initial_callback='0x0')
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
 edges=[(2298978, 1541864), (2298990, 1545044), (2514958, 1497240), (2514966, 1497064), (2514978, 1545044), (2507530, 1541864)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={1496074: 'mov_s\tr0,0x4', 1496076: 'jl_s.d\t[r13]', 1496078: 'mov_s\tr2,0', 1496098: 'mov_s\tr0,0x9', 1496100: 'jl_s.d\t[r13]', 2298948: 'ld.as\tr13,[r1,142]', 2298956: 'ld.as\tr3,[r1,139]', 2298964: 'ld.as\tr2,[r1,140]', 2298974: 'asl_s\tr0,r0,0x2', 2298976: 'add1_s\tr0,r0,r0', 2298988: 'st_s\tr15,[r13,0]', 2298994: 'st_s\tr14,[r13,0x8]', 2514946: '0x2000', 2514982: 'stw_s\tr15,[r14,0]', 2515118: 'ld_s\tr0,[r13,0x4]', 2515124: 'jl_s\t[r0]', 2515126: 'ld_s\tr0,[r13,0x8]', 2515132: 'jl_s\t[r0]', 2515134: 'ld_s\tr0,[r13,0xc]', 2515140: 'jl_s\t[r0]', 2507550: '0x424c30', 2507606: 'ld.di\tr0,[r1,4]', 2507638: 'jl\t[r0]'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  logical_table=dict(base='0x424c30',selected_record='0x424c8c',callback_cell='0x424c90',rows=rows),
  observations=['Initializer installs 0x2640e0 in runtime slot 4 and 0x264308 in runtime slot 9',
   'Runtime registrar uses 12-byte records addressed by kernel+0x238 table and lower/upper bounds at +0x22c/+0x230',
   'Dedicated dispatcher 0x2660a8 loads 0x36b324/328/32c and conditionally invokes each in sequence',
   'First group enable registers that dispatcher for logical ID 0x0904',
   'Logical ID 0x0904 selects row 10, bits 3/3, callback word 0x424c90'],
  limits=['CPU vector-table address, exception entry and runtime enablement still unresolved',
   'Sequential callback calls are not proof all three represent active hardware conditions',
   'No hardware execution or persistence test'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
