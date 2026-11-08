#!/usr/bin/env python3
"""Offline V1.1: PM lock controls, FS command 3 and null-private close."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x2A0A14,0x2A0A46,'PartitionControlDispatchBeforeByteTable'),
 (0x2A0A7A,0x2A0A88,'Partition2015AcquireAndSave'),
 (0x2A0AB0,0x2A0AB6,'Partition2016SelectLock'),
 (0x2A0AF2,0x2A0AFA,'PartitionRelease'),
 (0x2A0B0C,0x2A0B24,'PartitionDefaultForwardAndReturn'),
 (0x2A0C60,0x2A0CCC,'TransferAcquireAndPosition'),
 (0x2A0D18,0x2A0D34,'TransferReleaseResultNotPreserved'),
 (0x1F5792,0x1F57C8,'FilesystemCommand3Dispatch'),
 (0x1F59C0,0x1F59CE,'FilesystemCommand3Mode2AndStatus'),
 (0x1F617C,0x1F6188,'FilesystemControlReturnSlot'),
 (0x1F2348,0x1F237E,'GenericControlForwardForCommand3'),
 (0x1F46C4,0x1F46FC,'NullPrivateCloseBackendSelection'),
 (0x1F4710,0x1F4736,'NullPrivateCloseDiscardsCommand3Status'),
 (0x1F4834,0x1F48A4,'NullPrivateCloseCleanupAndZeroStatus'),
 (0x1F48A4,0x1F48E8,'CloseDispatchWithNullPrivateFile'),
 (0x1F19E0,0x1F1A8C,'VolumeResolverFlagAdmission'),
]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/storage_completion_controls';out.mkdir(parents=True,exist_ok=True)
 def raw(i,a,n):
  o=a-info[i]['load_address_candidate'];assert 0<=o<=len(ps[i])-n
  return ps[i][o:o+n]
 table=raw(0,0x2A0A46,12);assert table.hex()=='1a353b454e6363636363635a'
 targets={0x2015+i:0x2A0A46+2*struct.unpack('b',table[i:i+1])[0] for i in range(12)}
 assert targets[0x2015]==0x2A0A7A and targets[0x2016]==0x2A0AB0
 assert struct.unpack('<I',raw(0,0x1F1DAC,4))[0]==0x1A00010
 assert struct.unpack('<I',raw(0,0x1F1DA4,4))[0]==0x376018
 assert raw(1,0x376018+0x49,1)==raw(1,0x376168+0x49,1)==b'\0'
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-controls-') as td:
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
 edges=[(0x2A0A7A,0x23ECA4),(0x2A0AF2,0x23EE48),(0x2A0B0E,0x1F2348),
  (0x2A0C88,0x1F2348),(0x2A0D2E,0x1F2348),(0x1F59C6,0x2A1270),
  (0x1F4714,0x1F2348),(0x1F471C,0x2A12D8),(0x1F4724,0x2A45E4),
  (0x1F48B6,0x1F46C4)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={0x2A0A2C:'0x2015',0x2A0A3E:'ldb.x',0x2A0A42:'add1_s',
  0x2A0A7E:'add_s\tr0,r13,0x4',0x2A0A82:'st_s\tr0,[r13,0x20]',
  0x2A0AB0:'add\tr17,r13,0x4',0x2A0AF6:'mov_s\tr0,r17',
  0x2A0B22:'mov_s\tr0,r15',0x2A0D32:'mov_s\tr2,r15',
  0x1F579A:'cmp_s\tr1,0x3',0x1F579E:';0x1f59c0',
  0x1F59C2:'mov_s\tr1,0x2',0x1F59CA:';0x1f617e',
  0x1F617E:'st_s\tr0,[sp,0xc]',0x1F6180:'ld_s\tr0,[sp,0xc]',
  0x1F236A:'ld\tr4,[r4,28]',0x1F2372:'jl.d\t[r4]',
  0x1F46E6:';0x1f4710',0x1F4712:'mov_s\tr1,0x3',
  0x1F471A:'mov_s\tr0,r16',0x1F488E:'mov_s\tr13,0',
  0x1F489A:'mov_s\tr0,r13',0x1F48AC:'ld_s\tr0,[r0,0x4]',
  0x1F48B2:';0x1f48ba',0x1F1A4E:'ldb\tr0,[r1,73]',
  0x1F1A54:';0x1f1a5a',0x1F1A56:';0x1f1dac'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  partition_control_table={'base':'0x2a0a46','signed_byte_scaled_by':2,
   'targets':{hex(k):hex(v) for k,v in targets.items()}},
  observations=['PM 0x2015 acquires synchronization at private+4 and saves input first word to private+0x20',
   'PM 0x2016 releases same synchronization; selected branches do not call metadata transfer',
   'FS command 3 invokes 0x2a1270 mode 2 and saves returned status in actual return slot',
   'Null-private close, backend predicate false, invokes FS command 3 but immediately replaces return register',
   'That close continues conditional cleanup and can select zero independently of command-3 result',
   'Volume resolver returns 0x1a00010 if row+0x49==1 after earlier admission checks',
   'Initial SD and NAND row+0x49 bytes are both zero; this is not a runtime observation'],
  limits=['No universal ordinary-file close or shutdown completion proof',
   'Volume flag producer remains unidentified; offset-equal stores in unrelated structures are not evidence',
   'Synchronization primitive return handling and physical SD completion remain separate questions'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions, 12 table targets')
if __name__=='__main__':main()
