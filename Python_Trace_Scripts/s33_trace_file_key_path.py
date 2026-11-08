#!/usr/bin/env python3
"""Offline S33 V1.1 key fields, path formatting and current-volume evidence."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
from s33_decode_file_key import decode_key
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x210C08,0x210C5C,'DecodeAllKeyFields'),
 (0x210C5C,0x210F38,'FullPathConstructor'),
 (0x12B0DC,0x12B11C,'CopyCurrentVolumePrefix'),
 (0x12B290,0x12B298,'CurrentVolumeIndexGetter'),
 (0x12B29C,0x12B2B8,'CurrentVolumeIndexSetter'),
 (0x215724,0x2157F8,'DirectoryRecordAccess'),
 (0x2127FC,0x212854,'FilenamePrefixSelection'),
 (0x2156A8,0x21571C,'PathCacheProtocol'),
 (0x12CE54,0x12CE8C,'FormatterAdapter'),
]

def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/file_key_path';out.mkdir(parents=True,exist_ok=True)
 tools=ROOT/'work/build-arc/binutils'
 def raw(i,a,n):
  offset=a-info[i]['load_address_candidate'];assert 0<=offset<=len(ps[i])-n
  return ps[i][offset:offset+n]
 def word(a):return struct.unpack('<I',raw(0,a,4))[0]
 assert word(0x210F50)==0x3E8E94 and raw(1,0x3E8E94,16)==b'JPG\0AVI\0WAV\0MPO\0'
 assert word(0x210F44)==0x366B08 and raw(1,0x366B08,5)==b'DCIM\0'
 assert word(0x210F40)==0x369774
 assert raw(1,0x369774+15,7)==b'SYSTEM\0'
 assert raw(1,0x369774+28,5)==b'MISC\0'
 assert word(0x210F5C)==0x3E8EBA and raw(1,0x3E8EBA,15)==b'%s%s\\%s%04d.%s\0'
 assert word(0x12B120)==0x44234C
 assert word(0x12B298)==0x366889
 initial_index=raw(1,0x366889,1)[0]
 assert word(0x210F3C)==word((0x212814&~3)-125*4)==0x4BCFD8
 assert word(0x215800)==0x3E8EF0
 listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-key-path-') as td:
  elf,back=Path(td)/'0.elf',Path(td)/'0.bin'
  run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc',
       '--rename-section','.data=.text,alloc,load,readonly,code,contents',
       '--change-section-vma',f'.data={info[0]["load_address_candidate"]:#x}',
       '--strip-all',bd/info[0]['file'],elf])
  run([tools/'objcopy','--dump-section',f'.text={back}',elf]);assert back.read_bytes()==ps[0]
  for a,b,label in WINDOWS:
   t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',elf])
   assert 'out of bounds' not in t.lower(),label
   listings.append(f'WINDOW {label}\n'+t.replace(str(elf),'verified-block0.elf'))
 listing='\n'.join(listings)
 def line(a):
  hits=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
  assert len(hits)==1,(hex(a),hits)
  return hits[0]
 checks={0x210C20:'and\tr13,r0,0xc000',0x210C28:'lsr\tr14,r13,0xe',
  0x210C2C:'stb_s\tr14,[r1,0x2]',0x210C32:'lsr\tr3,r2,0x10',
  0x210C36:'bmsk\tr0,r3,0xb',0x210C3A:'lsr\tr13,r0,0xa',
  0x210C40:'bmsk_s\tr0,r0,0x9',0x210C44:'lsr\tr0,r3,0xc',
  0x210C48:'stb_s\tr0,[r1,0xd]',0x210E8E:'add2\tr6,r0,r1',
  0x210EC2:'ldh\tr5,[fp,-124]',0x12B0F2:'cmp\tr0,255',
  0x12B104:'add_s\tr1,r0,r12',0x12B2A8:'stb_s\tr0,[r1,0]'}
 for a,needle in checks.items():assert needle in line(a),line(a)
 edges=[(0x210CAC,0x210C08),(0x210C88,0x12B0DC),(0x12B0EC,0x12B290),
  (0x210CBC,0x215724),(0x210CCA,0x215724),(0x210D54,0x215724),
  (0x210E1E,0x2127FC),(0x210ED2,0x12CE54),(0x210F04,0x12CE54)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 fields=[dict(name='file_number',low_bit=0,width=14,output_offset='0'),
         dict(name='name_variant',low_bit=14,width=2,output_offset='2'),
         dict(name='directory_record_index',low_bit=16,width=10,output_offset='4'),
         dict(name='extension_index',low_bit=26,width=2,output_offset='12'),
         dict(name='namespace_selector',low_bit=28,width=4,output_offset='13')]
 mask=0
 for f in fields:
  bits=((1<<f['width'])-1)<<f['low_bit'];assert not mask&bits;mask|=bits
 assert mask==0xffffffff
 assert [decode_key(0xffffffff)[f['name']] for f in fields]==[16383,3,1023,3,15]
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),decoder_sha256=sha((ROOT/'Python_Trace_Scripts/s33_decode_file_key.py').read_bytes()),
  block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  key_fields=fields,extensions=['JPG','AVI','WAV','MPO'],current_volume=dict(index_byte='0x366889',sample_initial_index=initial_index,
    prefix_records='0x44234c',stride=56,invalid_index=255),
  path=dict(constructor='0x210c5c',full_numeric_filename_format='%s%s\\%s%04d.%s',
    limits='Conditional formatter, not a guaranteed path for every key; names and current volume require runtime state'),
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],
  limits=['Does not validate arbitrary keys or establish PTP object-handle equivalence',
   'Directory index does not by itself equal directory number',
   'Current-volume state and filename prefix are not encoded completely in the key',
   'No target execution, observed path trace or hardware V1.0 equivalence'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges; five disjoint fields cover 32 bits; initial volume index {initial_index}')
if __name__=='__main__':main()
