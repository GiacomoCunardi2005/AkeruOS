#!/usr/bin/env python3
"""S33 V1.1 static command MMIO, CPU data-port writes and event transfer path."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x25A278,0x25A2BC,'CommandAndArgumentHalfwordStores'),
 (0x25A5F8,0x25A658,'CommandPoll8000Iterations'),
 (0x25A084,0x25A0BC,'Status0ReadAndBitAcknowledgement'),
 (0x25A430,0x25A494,'DataPortAndMaskHelpers'),
 (0x304004,0x3040DC,'CPUHalfwordTransferAndFinalPoll'),
 (0x3040DC,0x3042A8,'ServiceTransferWithCallbacksEventsAndCleanup'),
 (0x3042E4,0x304380,'StatusCallbacksAndCompletionEventPublishers')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/sd_mmio_data';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={0x25A998:0xE00208,0x25A99C:0xE00100,0x25A9A0:0xE00101,
  0x304380:0xE01310,0x304384:0xE01200,0x304388:0x1B2920,0x30438C:0xE01110,
  0x304390:0x3042E4,0x304394:0x304324,0x304398:0xE00005,
  0x30439C:0x304368,0x3043A0:0x304374,0x3043A4:0xE01211,0x3043A8:0xE01321}
 for a,v in literals.items():assert word(a)==v
 assert (0x304088&~3)+190*4==0x304380
 assert (0x30408E&~3)+190*4==0x304384
 assert 0x7D<<6==8000
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-mmio-data-') as td:
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
 edges=[(0x25A60E,0x25A084),(0x25A616,0x25A0BC),
  (0x25A634,0x25A098),(0x25A640,0x25A098),(0x25A64C,0x25A098),
  (0x30403E,0x25A430),(0x304060,0x25A430),(0x3040AC,0x25A0BC),
  (0x3040F6,0x304004),(0x30410E,0x25A488),(0x304124,0x2BFE88),
  (0x304150,0x266768),(0x30416A,0x26671C),(0x3041A0,0x2C00E4),
  (0x3041C8,0x158D04),(0x3041D4,0x266E9C),(0x304202,0x158E28),
  (0x30427A,0x2C0E70),(0x304286,0x25A464),(0x304298,0x2667B0),
  (0x3042F2,0x158CBC),(0x304308,0x158CBC),(0x30436A,0x158CBC),
  (0x304378,0x158CBC)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={0x25A286:'0xff01824',0x25A28E:'sth.di\tr1,[r0]',
  0x25A292:'0xff01828',0x25A29E:'0xff0182c',0x25A2AA:'0xff0180c',
  0x25A086:'0xff01800',0x25A08E:'ldh.di',0x25A0B2:'sth.di',
  0x25A600:'mov_s\tr15,0x7d',0x25A602:'asl_s\tr15,r15,0x6',
  0x25A60C:';0x25a63a',0x25A61C:'btst_s\tr13,0',
  0x25A620:'btst_s\tr13,0x1',0x25A624:'btst_s\tr13,0x2',
  0x25A62C:';0x25a608',0x25A652:'mov_s\tr0,0',
  0x25A432:'0xff01834',0x25A43A:'sth.di\tr1,[r2]',0x25A488:'0xff01834',
  0x304042:'ldh.ab\tr1,[r15,2]',0x30405C:'ldh.ab\tr1,[r15,2]',
  0x3040A0:';0x304388',0x3040C4:'0x1b2920',
  0x3040EC:'bmsk.f\t0,r1,0x1',0x3040F4:';0x3040fe',
  0x3041CC:'mov_s\tr3,0x64',0x3041E4:';0x3041b2',
  0x3041E8:'cmp_s\tr14,0x9',0x3041EA:';0x3041b6',
  0x30429E:'mov_s\tr0,r13',0x30436E:'mov\tr1,512',0x30437C:'bset_s\tr1,r1,0x15'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  mmio=[dict(address=hex(a),selector_subtracted=True,access=access,meaning=meaning) for a,access,meaning in
   [(0x0FF01800,'ldh.di / sth.di','first command status/writeback'),
    (0x0FF01824,'sth.di','command selector'),(0x0FF01828,'sth.di','argument upper half'),
    (0x0FF0182C,'sth.di','argument lower half'),(0x0FF0180C,'sth.di','configuration'),
    (0x0FF01834,'sth.di / address returned','data port'),(0x0FF01840,'ldh.di / sth.di','mask modified by 0x25a444/464')]],
  command_poll={'max_iterations':8000,'unit':'iterations, not time',
   'priority':['first status bit0 -> write mask1 / 0xe00100','else bit1 -> write mask2 / 0xe00101',
   'else bit2 -> write mask4 / zero','else second status low nibble nonzero -> 0xe00208','else continue'],
   'exhausted':'0xe00100'},
  observations=['CPU path writes halfwords from buffer to data port and has a final poll bounded by 0x1b2920 iterations',
   'Service path falls back to CPU when buffer low two bits are nonzero',
   'Service path registers callbacks, waits on event 0xe00005 and checks progress counter after failed waits',
   'Counter resets on progress; nine unchanged checks do not bound total wait duration',
   'Cleanup returns saved r13 status; service/DMA implementation still incomplete'],
  limits=['No time conversion, actual MMIO trace, DMA engine attribution or persistence test',
   'Local polling bounds apply to selected loops only; other loops may remain unbounded'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
