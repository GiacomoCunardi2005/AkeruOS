#!/usr/bin/env python3
"""S33 V1.1 offline base-path and filename-prefix setup evidence."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0xC7768,0xC776C,'NIKONDefaultGetterDelaySlot'),
 (0x210428,0x210548,'InitializeRootIndexTable'),
 (0x21055C,0x210634,'InitializeNamingDefaultsAndInvalidateCurrent'),
 (0x12B2B4,0x12B2E8,'RootCountGetterSetter'),
 (0x12B358,0x12B380,'RootStringSetter'),
 (0x12B0DC,0x12B11C,'RootStringGetter'),
 (0x12B29C,0x12B2B4,'CurrentRootIndexSetter'),
 (0x212654,0x2126DC,'ApplyFilenameConfiguration'),
 (0x212700,0x21276C,'UpdateFilenamePrefix'),
 (0x2127FC,0x212854,'GetFilenamePrefix'),
 (0x134EBA,0x134ECC,'CallerSuppliesDSCNDefault'),
 (0x219898,0x2198E4,'ApplyPrefixAndSelectCurrentRootCaller'),
]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/path_setup';out.mkdir(parents=True,exist_ok=True)
 tools=ROOT/'work/build-arc/binutils'
 def raw(i,a,n):
  off=a-info[i]['load_address_candidate'];assert 0<=off<=len(ps[i])-n
  return ps[i][off:off+n]
 def word(a):return struct.unpack('<I',raw(0,a,4))[0]
 assert word(0x21054C)==0x36974D and raw(1,0x36974D,3)==b'B:\0'
 assert word(0x210550)==0x369750 and raw(1,0x369750,3)==b'A:\0'
 assert word((0x12B36A&~3)-146*4)==0x44234C
 assert word(0x210640)==0x366B18 and word(0x21063C)==0x366B10
 assert word(0xC776C)==0x365681 and raw(1,0x365681,6)==b'NIKON\0'
 assert word(0x1350B0)==0x366AF2 and raw(1,0x366AF2,5)==b'DSCN\0'
 assert word(0x212620)==0x4BCFD8
 assert word(0x2126DC)==0x3E8EE5 and raw(1,0x3E8EE5,9)==b'%02d%02d\0'
 assert word(0x12B298)==0x366889
 listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-path-setup-') as td:
  elf,back=Path(td)/'0.elf',Path(td)/'0.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc',
   '--rename-section','.data=.text,alloc,load,readonly,code,contents','--change-section-vma',f'.data={info[0]["load_address_candidate"]:#x}',
   '--strip-all',bd/info[0]['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==ps[0]
  for a,b,label in WINDOWS:
   t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',elf])
   assert 'out of bounds' not in t.lower(),label
   listings.append(f'WINDOW {label}\n'+t.replace(str(elf),'verified-block0.elf'))
 listing='\n'.join(listings)
 def line(a):
  matches=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
  assert len(matches)==1,(hex(a),matches)
  return matches[0]
 edges=[(0x210450,0x12B2D0),(0x210486,0x12B358),(0x2104A6,0x12B358),
  (0x21059E,0x32DDD4),(0x210620,0x12B29C),(0x134EC2,0x21055C),
  (0x134EBE,0xC7768),(0x2126C6,0x128C20),(0x2126A8,0x12CE54),(0x2198D8,0x212654),(0x2198E0,0x12B084)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={0x21044E:'r0,0x2',0x210484:'r0,0x1',0x2104A4:'r0,r13',
  0x210496:'r13,0',0x21061E:'r0,0xff',0x21268A:'stb_s\tr0,[r13,0x6]',
  0x2126BE:'add_s\tr0,r13,0x7',0x2126C4:'r2,0x4',0x2126CC:'stb_s\tr0,[r13,0xb]',
  0x21273C:'add_s\tr0,r15,0x7',0x212748:';0x21275a',0x21275C:'stb_s\tr0,[r15,0xb]'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],script_sha256=sha(Path(__file__).read_bytes()),
  block_sha256={str(b['index']):b['sha256'] for b in bs},windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  initialized_roots={'0':'A:','1':'B:'},root_table=dict(base='0x44234c',stride=56,current_index='0x366889'),
  initial_names={'0x366b10':'NIKON','0x366b18':'DSCN'},default_file_prefix=dict(caller='0x134ec2',value='DSCN',copied_to='0x366b18',limit='Does not prove active prefix remains DSCN'),
  active_prefix=dict(context='0x4bcfd8',prefix_offset=7,length=4,terminator_offset=11,
   configuration_setter='0x212654',other_setter='0x212700',branches='Copy four incoming bytes, or generated prefix under mode guards'),
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],
  limits=['Root index order differs from lower 0x376018 volume-row order',
   'Runtime call occurrence and active selection are not observed',
   'Naming mode meanings and complete connection to normal capture remain partial'])
 (out/'gnu_verified.txt').write_text(listing);(out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges; A:/B: root setup and DSCN default source')
if __name__=='__main__':main()
