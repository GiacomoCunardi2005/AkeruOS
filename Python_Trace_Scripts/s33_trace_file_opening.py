#!/usr/bin/env python3
"""Offline S33 V1.1 open/create, logical registration and volume binding."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x217EFC,0x218048,'OpenLogicalKeyAndRegister'),
 (0x12CE8C,0x12D000,'OpenUnderlyingFileAndVolumeSlot'),
 (0x12DBFC,0x12DD24,'CreateUnderlyingFileAndVolumeSlot'),
 (0x1F2038,0x1F2064,'InstallFamilyForVolumePrefix'),
 (0x1F21F8,0x1F22C0,'OpenDeviceByPrefixAndCallback'),
 (0x1F19E0,0x1F1A8C,'ResolveVolumeByPrefix'),
 (0x1F3554,0x1F359E,'InstallKnownCallbackFamily'),
 (0x2A3DA2,0x2A3DC8,'DeviceCallbackSlotStores'),
 (0x218458,0x2184A4,'LogicalRegistrationResult'),
 (0x137ABC,0x137AD8,'OriginalOpenWrapper'),
]

def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/file_opening';out.mkdir(parents=True,exist_ok=True)
 tools=ROOT/'work/build-arc/binutils'
 def raw(i,a,n):
  offset=a-info[i]['load_address_candidate'];assert 0<=offset<=len(ps[i])-n
  return ps[i][offset:offset+n]
 def word(a):return struct.unpack('<I',raw(0,a,4))[0]
 assert word(0x12D004)==word(0x12DE24)==word(0x1F1DA4)==0x376018
 assert word((0x1F203A&~3)-165*4)==0x376018
 assert word(0x12D008)==0x3668D5 and raw(1,0x3668D5,5)==b'r\0r+\0'
 assert word(0x12DE34)==0x3668DE and raw(1,0x3668DE,10)==b'w\0w+\0n\0n+\0'
 assert (1+4*(1+4))*16==0x150==96+60*4
 volumes=[]
 for i,dev,pm,prefix in [(0,b'DEVSD:',b'PMSD:',b'B:'),(1,b'DEVNAND:',b'PMNAND:',b'A:')]:
  a=0x376018+i*0x150;d=raw(1,a,0x150)
  for off,value in [(8,dev),(19,pm),(30,prefix)]:assert d[off:off+len(value)+1]==value+b'\0'
  volumes.append(dict(index=i,record=hex(a),device=d[8:19].split(b'\0')[0].decode(),
     partition_manager=d[19:30].split(b'\0')[0].decode(),prefix=d[30:44].split(b'\0')[0].decode(),
     synchronization_id=hex(struct.unpack_from('<I',d,4)[0]),
     open_slot_count=60,open_slot_offset='0x60'))
 assert struct.unpack('<I',raw(1,0x376018+2*0x150,4))[0]==0
 listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-file-open-') as td:
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
 edges=[(0x137AD0,0x217EFC),(0x217F58,0x21828C),(0x217FF0,0x12DBFC),
        (0x218024,0x12CE8C),(0x218034,0x218458),(0x12CF22,0x1F21F8),
        (0x12DCA4,0x1F21F8),(0x1F205A,0x1F3554),(0x1F358A,0x2A3C5C)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={0x21802C:'bne_s',0x218038:'mov_s\tr0,r13',0x218484:'st_s\tr13,[r0,0x4]',
  0x1F2056:'add\tr1,r2,0x1e',0x1F205E:'mov_s\tr2,0x1',
  0x1F2288:'st_s\tr14,[r0,0]',0x1F228A:'ld_s\tr3,[r14,0xc]',0x1F2292:'jl_s.d',
  0x12CFBE:'st\tr16,[r17]',0x12DCC0:'st\tr0,[r17]',
  0x12CEFC:'cmp_s\tr13,0x3b',0x12DC70:'cmp_s\tr14,0x3b'}
 for a,needle in checks.items():assert needle in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  volume_table=dict(base='0x376018',record_stride='0x150',observed_initial_records=volumes,sample_sentinel_index=2),
  logical_open=dict(entry='0x217efc',mode_one='0x12dbfc called with 2, mode string w+',
      other_modes='0x12ce8c with 0x11 or 0x12, selecting r or r+',
      registration_site='0x218034',registration_return='Ignored locally; return is saved underlying-open status',
      limits='Paths, key allocation and admission invariants remain incomplete'),
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],
  observations=['Open generic allocates 32-byte file object and invokes registered device +0xc callback',
    'The row prefix at +30 is passed to known family installer, conditionally on row+0x58 guard',
    'Underlying open/create writes pointer both to output cell and volume open-slot table',
    'Logical registration has 30 total records; volume has 60 underlying slots per row; capacities are distinct'],
  limits=['Static B:/DEVSD: naming does not observe a mounted runtime SD instance',
    'No demonstrated descriptor-exhaustion or logical-map-exhaustion runtime case',
    'No global resource-leak or persistence proof; no target execution'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, two volume records and modes')
if __name__=='__main__':main()
