#!/usr/bin/env python3
"""Verify offline S33 V1.1 PM/raw-device binding and pending-update controller."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x1F1E1C,0x1F1ED0,'ConstructRawDeviceAndFile'),
 (0x1F1F10,0x1F1F3C,'RegisterPartitionWrapper'),
 (0x1F1F4C,0x1F1F88,'OpenPartitionWrapperIntoVolume'),
 (0x1F2038,0x1F2064,'InstallFilesystemOverPartition'),
 (0x1F3554,0x1F35B4,'SavePartitionHandleInFilesystem'),
 (0x2A0698,0x2A06F2,'RegisterPartitionCallbacks'),
 (0x2A0890,0x2A08B0,'PartitionWriteForwardAndCopyError'),
 (0x2A0504,0x2A0534,'ResolveRawDeviceVolumeIndex'),
 (0x2A0534,0x2A0594,'RawWriteConditionalBackendAndCount'),
 (0x168410,0x1684B4,'SDSelectedTransferAndRecovery'),
 (0x1684B4,0x1684D4,'SDWriteWrapperIndexZero'),
 (0x2A1270,0x2A12D4,'PendingUpdateModeController'),
 (0x2AB5E0,0x2AB634,'SecondPendingUpdateConsumer'),
]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/sd_backend';out.mkdir(parents=True,exist_ok=True)
 def raw(i,a,n):
  o=a-info[i]['load_address_candidate'];assert 0<=o<=len(ps[i])-n
  return ps[i][o:o+n]
 def word(a,i=0):return struct.unpack('<I',raw(i,a,4))[0]
 literals={0x1F1DA4:0x376018,0x2A0680:0x376018,
  0x1F2184:0x2A04D0,0x1F2188:0x2A04F0,0x1F218C:0x2A0594,
  0x1F2190:0x2A0534,0x1F2194:0x2A05F4,
  0x2A0A8C:0x2A073C,0x2A0A90:0x2A0844,0x2A0A94:0x2A0870,
  0x2A0A98:0x2A0890,0x2A0A9C:0x2A0A14,0x2A0AA0:0x2A0BF0,
  0x2A12D4:0x1A00001}
 for a,v in literals.items():assert word(a)==v,(hex(a),hex(word(a)))
 for site,offset,a in [(0x2A06C6,245,0x2A0A98),(0x2A06CE,244,0x2A0A9C),(0x2A06D2,244,0x2A0AA0)]:assert (site&~3)+4*offset==a
 assert word(0x376018+0x38,1)==0x1684B4
 assert word(0x376168+0x38,1)==0x1695D0
 for a,dev,pm in [(0x376018,b'DEVSD:',b'PMSD:'),(0x376168,b'DEVNAND:',b'PMNAND:')]:
  assert raw(1,a+8,len(dev)+1)==dev+b'\0'
  assert raw(1,a+19,len(pm)+1)==pm+b'\0'
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-sd-backend-') as td:
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
 edges=[(0x1F1EA0,0x2A04D0),(0x1F1F32,0x2A0698),(0x1F1F76,0x1F21F8),
  (0x1F205A,0x1F3554),(0x2A06D8,0x2A3C5C),(0x2A089A,0x1FA090),
  (0x2A0540,0x2A0504),(0x1684CC,0x168410),(0x16845A,0x25B9C0),
  (0x168464,0x25BB5C),(0x168476,0x25BF3C),(0x168484,0x25B63C),
  (0x168492,0x25B63C),(0x2A12AA,0x1F2484),(0x2A12B8,0x2A10F4),
  (0x2A12C0,0x2AB5E0),(0x2AB616,0x2A0D70)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={0x1F1E78:'st_s\tr0,[r14,0x18]',0x1F1EC0:'st\tr15,[r17,80]',
  0x1F1F2C:'ld_s\tr0,[r2,0x50]',0x1F1F7C:'st_s\tr0,[r14,0x54]',
  0x2A06CA:'st\tr16,[r13]',0x1F35AC:'st.as\tr15,[r13,105]',
  0x2A089E:'ld_s\tr0,[r0,0]',0x2A08AC:'st_s\tr1,[r13,0xc]',
  0x2A054E:'ldb\tr0,[r1,73]',0x2A0558:';0x2a0586',
  0x2A057E:'ld_s\tr15,[r1,0x38]',0x2A0582:'jl_s.d\t[r15]',
  0x2A0588:'st_s\tr0,[r14,0xc]',0x2A058C:'mov_s\tr13,0',
  0x2A0592:'mov_s\tr0,r13',0x1684C2:'mov_s\tr0,0',
  0x2A129C:'st_s\tr0,[r13,0x3c]',0x2A12A8:'st_s\tr15,[r13,0x3c]',
  0x2A12B4:';0x2a12c8',0x2A12BE:';0x2a12c8',0x2A12D2:'mov_s\tr0,r15',
  0x2AB622:'st\tr16,[r2,52]',0x2AB626:';0x2ab62e',
  0x2AB62A:'st.as\tr1,[r13,198]'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],
  checked_literals={hex(a):hex(v) for a,v in literals.items()},checked_instructions=len(checks),
  volume_write_callbacks={'0x376018':'0x1684b4 (DEVSD:)','0x376168':'0x1695d0 (DEVNAND:)'},
  partition_write='0x2a0890 forwards to raw handle in device private context +0; copies error +0xc',
  pending_controller={'entry':'0x2a1270','mode1':'set +0x3c=1, no flush',
   'mode0':'if +0x3c nonzero, clear then try ordered updates; otherwise no flush',
   'mode2':'try 0x1f2484, 0x2a10f4, 0x2ab5e0, stopping at first nonzero result',
   'other':'0x1a00001','second_pending_flag':'0x318, cleared only on zero result'},
  observations=['Raw row+0x49 == 1 bypasses backend callback and returns requested count with zero error',
   'Other raw writes call row+0x38; zero callback status returns requested count, nonzero returns zero count',
   'SD wrapper 0x1684b4 selects index zero in 0x168410; count selects 0x25b9c0 or 0x25bb5c',
   'SD helper includes conditional recovery and retries; physical completion meaning still unresolved'],
  limits=['Initial table and selected construction paths do not prove actual runtime mounted instance',
   'Meaning and runtime producer of row+0x49 flag not established',
   'No proof that every close/shutdown invokes controller with flushing mode',
   'No physical card persistence or low-level MMIO contract established'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instruction checks')
if __name__=='__main__':main()
