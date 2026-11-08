#!/usr/bin/env python3
"""Offline S33 V1.1 selected worker destination flow to a split hardware address register."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x15D29E,0x15D2DC,'DestinationBankToConsumerRecord'),
 (0x15D02C,0x15D046,'ConsumerRecordRegisterBinding'),
 (0x15D496,0x15D4B8,'ReadyWaitThenConsumerCall'),
 (0x24868E,0x2486D8,'ConsumerSelectorOneRecordCopy'),
 (0x2487D4,0x2487EA,'SecondAddressSetterAndReturnMerge'),
 (0x2960B0,0x2960CC,'AddressSetterWrapper'),
 (0x2ED9FC,0x2EDA34,'NonzeroAlignedAddressSetter'),
 (0x2EE8F0,0x2EE924,'DeviceIndexToRegisterTable'),
 (0x2ED448,0x2ED450,'DeviceBooleanNormalization'),
 (0x3099C8,0x3099E4,'BankZeroSplitAddressWrite'),
 (0x309C0C,0x309C28,'BankOneSplitAddressWrite')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/worker_destination_mmio';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={1430272: 4477544, 1430304: 3743928, 1430340: 4477472, 3074648: 4246948, 3074652: 4247000, 3069948: 66060322, 3071036: 66060307}
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
 edges=[(1430688, 1429260), (1430696, 2393660), (2393772, 1215520), (2394078, 2711728), (2711736, 3070460), (3070490, 1541864), (3070498, 3074288), (3070504, 1545044), (3074298, 3069000), (3074314, 3185096), (3074328, 3185676)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={1429566: 'ld.as\tr19,[pcl,177]', 1430176: 'ldb\tr1,[r0,142]', 1430188: 'ld_s\tr1,[r0,0x40]', 1430210: 'ld_s\tr1,[r0,0x50]', 1430232: 'st_s\tr1,[r0,0x70]', 1430700: 'mov_s\tr0,r19', 2393742: 'cmp_s\tr0,0x1', 2393768: 'add\tr1,r14,0x20', 2393776: 'mov_s\tr2,0x20', 2394072: 'ld_s\tr1,[sp,0x8]', 2394076: 'mov_s\tr0,0x1', 2394082: 'mov_s\tr2,0', 2711730: 'cmp_s\tr0,0x1', 2711732: 'mov_s\tr0,r1', 2711740: 'mov_s\tr1,0x1', 3070466: 'mov.f\tr13,r0', 3070480: 'bmsk.f\t0,r13,0x2', 3070494: 'mov_s\tr0,0x2', 3070496: 'mov_s\tr1,r13', 3070502: 'mov_s\tr2,r14', 3070508: 'mov_s\tr0,0', 3074294: 'mov_s\tr13,r0', 3074296: 'mov_s\tr16,r1', 3074302: 'mov_s\tr0,r2', 3074324: 'add2_s\tr0,r0,r13', 3074326: 'ld_s\tr0,[r0,0]', 3074332: 'mov_s\tr1,r16', 3069002: 'mov.ne\tr0,0x1', 3185686: 'extw_s\tr0,r1', 3185688: 'sth.di\tr0,[r14]', 3185692: 'add_s\tr14,r14,0x4', 3185694: 'lsr_s\tr13,r13,0x10', 3185696: 'sth.di\tr13,[r14]'}
 for a,n in checks.items():assert n in line(a),line(a)
 def data_word(a):
  hits=[b for b in bs if b['load_address_candidate']<=a and a+4<=b['load_address_candidate']+len(ps[b['index']])]
  assert len(hits)==1
  b=hits[0];return struct.unpack_from('<I',ps[b['index']],a-b['load_address_candidate'])[0]
 bank0,bank1=data_word(0x40cda4+2*4),data_word(0x40cdd8+2*4)
 assert (bank0,bank1)==(0x0fe9011c,0x0fe9811c)
 assert 0x445220+0x70==0x445268+0x28
 assert (0x15d03e&~3)+177*4==0x15d300
 split_examples=[]
 for pointer in (0x1000,0x12345678,0x80000000,0xfffffff8):
  lo,hi=pointer&0xffff,pointer>>16
  assert (hi<<16)|lo==pointer
  split_examples.append(dict(pointer=hex(pointer),low=hex(lo),high=hex(hi)))
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  conditional_dataflow=['selected destination bank -> 0x445290 = consumer record0x445268+0x28',
   'consumer selector1 copies record+0x20 into stack; destination becomes stack+8',
   '0x2960b0 mode1 -> 0x2ed9fc pointer,bank1 -> generic register index2',
   'bank1 register table index2 -> low pointer16 at0x0fe9811c, high16 at0x0fe98120'],
  register_addresses={'bank0_index2':hex(bank0),'bank1_index2':hex(bank1)},
  split_examples=split_examples,
  observations=['Nonzero pointer must be aligned to8bytes before selected setter programs address',
   'Address split writer performs two halfword stores four bytes apart, without completion polling',
   'Selected setter enters and leaves critical section then returns zero, replacing inner setter result',
   'This is conditional static programming flow, not proof of physical read completion'],
  limits=['Consumer selector1 and all upstream state guards are not proven active at runtime',
   'Other consumer paths, register semantics and hardware completion remain incomplete',
   'Table and buffer fields can have other writers; concurrency and aliasing remain open',
   'No hardware access or JPEG persistence proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
