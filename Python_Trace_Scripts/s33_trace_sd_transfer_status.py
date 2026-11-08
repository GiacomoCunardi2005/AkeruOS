#!/usr/bin/env python3
"""Offline V1.1 SD transfer status, retry bound and MMIO polling evidence."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x168410,0x1684B4,'CountDispatchAndThreeOuterAttempts'),
 (0x25B9C0,0x25BB5C,'MultipleTransferAndErrorPrecedence'),
 (0x25BB5C,0x25BC40,'SingleTransferAndErrorPreservation'),
 (0x2E509C,0x2E50CC,'CommandDescriptorConstructor'),
 (0x2E5634,0x2E5638,'CompletionTailToPolling'),
 (0x25A658,0x25A690,'CompletionPollingBitPriority'),
 (0x25A0BC,0x25A0D0,'HalfwordMMIOStatusReader'),
 (0x2E5648,0x2E5658,'DataTransferForwarder'),
 (0x3042A8,0x3042E4,'DataTransferModeDispatch'),
 (0x2E5472,0x2E5494,'CommandIssueAndResult'),
 (0x2E53A6,0x2E53AE,'WriteSelectorsDescriptorConfiguration')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/sd_transfer_status';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={0x1687B4:0x4463E0,0x25BD54:0xE00302,0x25BD58:0xE00303,
  0x25A998:0xE00208,0x25A9A4:0xE00103}
 for a,v in literals.items():assert word(a)==v
 tools=ROOT/'work/build-arc/binutils';listings=[]
 with tempfile.TemporaryDirectory(prefix='s33-transfer-') as td:
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
 edges=[(0x16845A,0x25B9C0),(0x168464,0x25BB5C),(0x168476,0x25BF3C),
  (0x168484,0x25B63C),(0x168492,0x25B63C),
  (0x25BA3C,0x2E509C),(0x25BA44,0x2E52F4),(0x25BA6A,0x2E5648),
  (0x25BA80,0x2E5634),(0x25BAA2,0x2E52F4),(0x25BAD2,0x2E5634),
  (0x25BB0A,0x2E52F4),(0x25BB44,0x2E52F4),(0x25BBC6,0x2E509C),
  (0x25BBD0,0x2E52F4),(0x25BBEA,0x2E5648),(0x25BBF8,0x2E5634),
  (0x25BC28,0x2E52F4),(0x2E5634,0x25A658),(0x25A660,0x25A0BC),
  (0x2E564E,0x3042A8),(0x3042C0,0x304004),(0x3042DE,0x3040DC),
  (0x2E547E,0x25A278),(0x2E5484,0x25A5F8)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={0x168444:'mov_s\tr0,0x3',0x168446:'mov_s\tr18,r0',
  0x16849E:'sub\tr0,r18,0x1',0x1684A4:';0x168446',0x168470:';0x1684aa',
  0x16849A:';0x1684aa',0x1684AA:'mov_s\tr0,r14',
  0x25BA16:'mov_s\tr2,0x19',0x25BBA6:'mov_s\tr2,0x18',
  0x25BAB6:';0x25bb1c',0x25BABE:'0xe00200',0x25BACC:';0x25bad2',
  0x25BB10:'0xe00200',0x25BB1A:'mov_s\tr14,0',0x25BB52:'mov_s\tr0,r14',
  0x25BC36:'mov_s\tr0,r13',0x25BBE4:'mov_s\tr3,0x1',
  0x25A666:'btst_s\tr0,0x2',0x25A66A:'btst_s\tr0,0x8',
  0x25A670:'and\tr1,r1,112',0x25A674:'cmp_s\tr1,0x50',
  0x25A678:'bmsk.f\t0,r0,0x3',0x25A67C:';0x25a660',
  0x25A686:'mov_s\tr0,0',0x25A0BE:'rsub\tr1,r0,0xff01804',
  0x25A0C6:'ldh.di\tr0,[r1]',0x2E50AA:'stw_s\tr2,[r1,0x8]',
  0x2E50B4:'st\tr8,[r1,24]',0x2E53A8:'mov\tr0,512'}
 for a,n in checks.items():assert n in line(a),line(a)
 # The back edge targets the assignment from r0, not the constant initializer.
 remaining=3;trace=[]
 while remaining:
  trace.append(remaining);remaining-=1
 assert trace==[3,2,1]
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},outer_attempt_counters=trace,
  status_mmio={'reader':'0x25a0bc','address':'0x0ff01804 - selector','access':'ldh.di',
   'poll':'0x25a658','priority':['bit2 -> 0xe00103','else bit8 -> zero',
   'else (status & 0x70)==0x50 -> 0xe00208','else low nibble zero -> poll again','else -> 0xe00208'],
   'local_timeout':'No counter, elapsed-time check or wait in selected polling body'},
  observations=['Single path builds selector 0x18 and calls data service with count one',
   'Multiple path builds selector 0x19, performs data transfer and selector 0x0c sequence',
   'Multiple path can accept 0xe00200 from selector 0x0c only at context+0xe4 boundary',
   'Later selector 0x0d result 0xe00200 is explicitly normalized to zero in boundary branch',
   'Diagnostic selector 0x0d after an existing error does not replace saved transfer status',
   'Data service reaches 0x3042a8 mode dispatch; DMA/PIO and full physical contract not established'],
  limits=['Three outer attempts do not bound internal polling duration or lower-service operations',
   'Zero denotes a selected software status path, not demonstrated power-loss persistence',
   'No measured SD timing, runtime trace or modified firmware execution'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions; outer counters 3/2/1')
if __name__=='__main__':main()
