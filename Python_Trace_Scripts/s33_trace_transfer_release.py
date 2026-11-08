#!/usr/bin/env python3
"""Offline S33 V1.1 transfer object publication and shared release alias."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x2BFF26,0x2BFF3C,'PublishTransferObjectFields'),
 (0x2C0C84,0x2C0CA0,'ReleaseLoadHandleAndSelectFirstObject'),
 (0x2C0CB0,0x2C0CC6,'FirstObjectDisableReadModifyWrite'),
 (0x2C0CD4,0x2C0CE8,'FirstObjectConditionalMaskUpdate'),
 (0x2C0CEC,0x2C0D00,'FirstObjectResetAndService'),
 (0x2C0D08,0x2C0D1C,'FirstObjectAdditionalMaskAndClearFlag'),
 (0x2C0D20,0x2C0D34,'FirstObjectStatusWriteAndCommonExit'),
 (0x2C0E58,0x2C0E74,'CommonReleaseClearsCallerCellAndAlias'),
 (0x2C0C7A,0x2C0C84,'ClearObjectSelectorAtReleaseTail'),
 (0x2C0B84,0x2C0BBC,'ChannelReleaseEntryAndFirstObject'),
 (0x2C0BC8,0x2C0BF0,'ChannelReleaseFirstRegister'),
 (0x2C0BF0,0x2C0C00,'ChannelReleaseSecondObjectSelection'),
 (0x2C0C08,0x2C0C32,'ChannelReleaseSecondRegister'),
 (0x2C0C32,0x2C0C42,'ChannelReleaseThirdObjectSelection'),
 (0x2C0C50,0x2C0C7A,'ChannelReleaseThirdRegister'),
 (0x1786E8,0x178718,'NestedCriticalSectionEntry'),
 (0x179354,0x179388,'NestedCriticalSectionExit')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/transfer_release';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={0x2C00A4:0x512C5C,0x2C00AC:0x512C80,0x2C00B4:0x512CA4,
  0x2C00BC:0xF4240,0x2C0CA8:0x512C5C,0x2C0CAC:0x0FEE0038,
  0x2C0CCC:0x10209,0x2C0CD0:0x0FF00020,0x2C0CE8:0x0FEE0034,
  0x2C0D04:0x0FF00028,0x2C0D1C:0x0FEE0508,
  0x178718:0x369348,0x2C0BBC:0x406AF4,0x2C0BC0:0x512C5C,
  0x2C0BC4:0x0FF00028,0x2C0C00:0x512C80,0x2C0C04:0x0FF00008,
  0x2C0C44:0x1E00001,0x2C0C48:0x512CA4,0x2C0C4C:0x0FF00048,
  0x2C0CA0:0x1E00002,0x2C0CA4:0x1E03D70}
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
 edges=[(0x2C0CF0,0x267BC4),(0x2C0D2E,0x2C0E58),
  (0x2C0E58,0x2C0AFC),(0x2C0E5E,0x179354),(0x2C0E62,0x2C0B84),
  (0x2C0E70,0x2C0C84),(0x2C0C7E,0x2C0B94),
  (0x2C0BB4,0x1786E8),(0x2C0BDA,0x179354),(0x2C0BF8,0x1786E8),
  (0x2C0C1A,0x179354),(0x2C0C3A,0x1786E8),(0x2C0C62,0x179354),
  (0x2C0BEC,0x2C0C7C),(0x2C0C22,0x2C0C7C),(0x2C0C2E,0x2C0C7C),
  (0x2C0C36,0x2C0C7A)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={0x2BFF28:'st_s\tr1,[r2,0]',0x2BFF2A:'st_s\tr15,[r2,0x4]',
  0x2BFF2C:'st_s\tr14,[r2,0x8]',0x2BFF2E:'st_s\tr13,[r2,0xc]',
  0x2BFF30:'st\tr2,[r16]',0x2C0C8A:'mov_s\tr15,r0',
  0x2C0C90:'ld_s\tr13,[r0,0]',0x2C0CB4:'bset\tr10,r10,r14',
  0x2C0CB8:'sth.di',0x2C0CD8:'bclr\tr10,r10,r0',
  0x2C0CF6:'0x10209',0x2C0D24:'bset\tr10,r10,r14',
  0x2C0D32:'stb_s\tr14,[r0,0]',0x2C0E68:'mov_s\tr1,0',
  0x2C0E6E:'st_s\tr1,[r15,0]',0x2C0C82:'st_s\tr1,[r14,0x4]',
  0x2C0B8C:'ld_s\tr2,[r14,0x4]',0x2C0B90:'mov_s\tr0,0',
  0x2C0B94:';0x334194',0x2C0BCC:'and\tr0,r0,-8',
  0x2C0BD0:'or\tr0,r0,0x7',0x2C0BD6:'sth.di',
  0x2C0C0C:'and\tr0,r0,-8',0x2C0C10:'or\tr0,r0,0x7',0x2C0C16:'sth.di',
  0x2C0C54:'and\tr0,r0,-8',0x2C0C58:'or\tr0,r0,0x7',0x2C0C5E:'sth.di',
  0x1786F4:'ld_s\tr2,[r2,0x68]',0x178704:'add_s\tr0,r0,0x1',
  0x178706:'st_s\tr0,[r2,0x68]',0x1786FC:'flag\tr0',
  0x179364:'sub.f\tr0,r0,0x1',0x17936C:'st_s\tr0,[r2,0x68]',
  0x179378:'flag\tr2',0x179380:'flag\tr3'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  observations=['0x2c0e70 is a direct alias to 0x2c0c84, also used on error paths',
   'Release takes pointer to caller handle cell and loads the transfer object from it',
   'First fixed object branch modifies MMIO and reaches common release tail',
   'Common tail calls release services and clears caller handle cell unconditionally in its delay slot',
   'Internal channel release handles three fixed objects, writes low bits 0..2 to one of three MMIO registers and converges to object+4 clear',
   'The paired helpers increment/decrement a nested critical-section counter and restore CPU flags, not hardware completion waits',
   'Internal release has no completion polling or register readback after its final MMIO write in these branches',
   'Object field0 set to 0xf4240; meaning is not assigned from value alone'],
  limits=['Outer disable routine second/third object branches and full resource allocator remain incomplete',
   'Caller-cell clear is not proof of engine quiescence, physical SD completion or safe reuse on all errors',
   'No new hardware observation or firmware modification'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
