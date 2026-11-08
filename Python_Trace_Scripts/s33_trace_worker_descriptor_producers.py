#!/usr/bin/env python3
"""Offline S33 V1.1 callback descriptor producers and selected concrete worker callbacks."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x1640A0,0x1640DC,'SecondBuilderZeroRegister'),
 (0x252694,0x2526C8,'SecondDescriptorFifthWordSetter'),
 (0x12F5AA,0x12F5E8,'FirstConfigurationAndAlias'),
 (0x12F65A,0x12F684,'FirstDescriptorPointerPublication'),
 (0x1FC48C,0x1FC4A4,'FirstDescriptorFifthWord'),
 (0x164760,0x164786,'SecondDescriptorCallbackSelection'),
 (0x164786,0x1647A4,'SecondDescriptorArgumentAndPoolLoad'),
 (0x164838,0x164846,'SecondDescriptorPointerPublication'),
 (0x12F776,0x12F786,'FirstInitializerCaller'),
 (0x1649A8,0x1649B4,'SecondInitializerCaller'),
 (0x15E570,0x15E594,'DescriptorToControlMapping'),
 (0x165338,0x165360,'FallbackEntry'),
 (0x1653C0,0x1653E8,'PreferredEntry')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/worker_descriptor_producers';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={1242624: 4465848, 1242632: 4465748, 1242636: 4466176, 1243408: 4466096, 1243420: 4465848, 2081956: 2082016, 1460160: 4479588, 1460260: 2091360, 1460264: 1463232, 1460268: 2085772, 1460272: 1463096, 1460276: 4479596, 1461136: 4478472, 1461140: 4478224}
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
 edges=[(1242744, 2081932), (1460126, 2434708), (1243004, 1433496), (1460654, 1433496)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={0x1640B6: 'mov_s\tr15,0', 0x2526B6: 'st\tr15,[r5,16]', 1242540: ';0x12f60c', 1242552: 'mov_s\tr3,r2', 1242714: ';0x12f910', 1242738: 'add\tr0,r2,0x30', 1242742: 'mov_s\tr20,r0', 1242748: ';0x12f910', 1242750: 'mov_s\tr0,r20', 1242754: 'st_s\tr0,[r1,0x18]', 2081940: ';0x1fc4a4', 2081942: 'st_s\tr1,[r0,0x10]', 1460064: 'ldb\tr0,[r14,38]', 1460070: ';0x16483e', 1460072: 'cmp_s\tr1,0x1', 1460074: ';0x164778', 1460076: ';0x164824', 1460078: ';0x1647c0', 1460080: 'st_s\tr1,[r0,0x8]', 1460082: ';0x164828', 1460084: 'st_s\tr1,[r0,0x10]', 1460088: ';0x1647c0', 1460090: ';0x16482c', 1460092: 'st_s\tr15,[r0,0x8]', 1460094: 'st_s\tr1,[r0,0xc]', 1460096: ';0x164830', 1460098: 'st_s\tr15,[r0,0x10]', 1460100: 'st_s\tr1,[r0,0x14]', 1460110: 'ld\tr16,[pcl,168]', 1460120: 'mov\tr5,r16', 1460280: ';0x164b90', 1460282: 'st\tr16,[r1,24]', 1434992: 'ld.as\tr1,[r16,68]', 1435010: 'ld_s\tr0,[r1,0x8]', 1435014: 'st_s\tr0,[r15,0x38]', 1435016: 'ld_s\tr0,[r1,0xc]', 1435022: 'st_s\tr0,[r15,0x3c]', 1463096: 'push_s\tblink', 1463232: 'push_s\tblink'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  descriptor_mapping=[dict(input='0x4424b8',field='0x4425c8',descriptor='0x442630',fifth_word='0x1fc4e0'),
   dict(input='0x445510',field='0x445620',descriptor='0x445a6c',preferred='0x1653c0',fallback='0x165338')],
  checked_address_arithmetic={
   'first_field':hex(0x4425b0+0x18), 'first_descriptor':hex(0x442600+0x30),
   'second_field':hex(0x445608+24), 'second_descriptor':hex(0x445a64+8),
   'preferred_slot':hex(0x445a6c+8), 'fallback_slot':hex(0x445a6c+12)},
  observations=['First selected path publishes 0x442630 into config+0x110 and initializes descriptor+0x10 to 0x1fc4e0',
   'Second selected path publishes 0x445a6c into config+0x110 after setup call',
   'Second inner branch writes preferred callback 0x1653c0 or fallback callback 0x165338 at descriptor+8/+12',
   'Common initializer copies those slots into controls 0x3674c8/cc'],
  limits=['First descriptor callback fields +8/+12 still unresolved',
   'Callback body semantics and all possible writers not yet reconstructed',
   'Selected path guards do not establish active runtime mode; other branches and rollback remain open',
   'Setup call receives descriptor pointer; its complete effects and later mutations not fully audited',
   'No runtime execution, buffer reuse or JPEG persistence proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
