#!/usr/bin/env python3
"""Offline S33 V1.1 alternate execution response records and completion events."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x15C684,0x15C6A2,'RegisterSecondWorker'),
 (0x23FAE4,0x23FB10,'SecondWorkerContextStore'),
 (0x23FA04,0x23FA38,'ResponseHandlerContextStore'),
 (0x343280,0x343312,'SecondWorkerResultRecordAndPublish'),
 (0x2D528C,0x2D52AC,'ReverseMailboxProducer'),
 (0x23FA50,0x23FAB4,'ResponseConsumerAndIndirectHandler'),
 (0x247364,0x247398,'ResponseTypeOneAndCompletionEvent'),
 (0x247338,0x247364,'CompletionWaitAndUnconditionalState'),
 (0x29390A,0x29391E,'RegisterFirstWorker'),
 (0x3371E8,0x337218,'FirstWorkerContextStore'),
 (0x34322E,0x343262,'FirstWorkerTypeSixResponse'),
 (0x293ADA,0x293B06,'FirstResponsePayloadAndEvent')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/alternate_response_events';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={0x15C73C:0x343280,0x15C738:0x247364}
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
 edges=[(1427088, 2357988), (2357996, 1416880), (3420934, 2970252), (2357882, 1412356), (2357894, 1412320), (2357900, 2970188), (2388876, 1412284), (2388804, 1412356), (2388816, 1412320), (2701584, 3371496), (3420756, 3371932), (2702078, 1412284)]
 edges.append((0x15C684,0x23FA04))
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={2358020: 'st.di\tr13,[r1]', 2357796: '0x424300', 2357804: 'st.di\tr14,[r0]', 3420814: 'ld.di\tr1,[r2]', 3420822: ';0x3432f4', 3420896: 'jl_s.d\t[r13]', 3420902: '0x424800', 3420908: 'st.di\tr2,[r1]', 3420912: 'st.di\tr0,[r1,4]', 3420926: '0x424800', 2357924: '0x424300', 2357936: 'jl_s\t[r1]', 2388848: 'cmp_s\tr0,0x1', 2388852: 'ld.di\tr1,[r1,4]', 2388862: 'st_s\tr1,[r0,0]', 2388870: '0x9900020', 2388880: 'mov_s\tr1,0x2', 2388824: '0x36ad54', 2388834: 'stb_s\tr1,[r0,0]', 3371524: '0x424204', 3371532: 'st.di\tr13,[r1]', 3420730: 'st.di\tr2,[r1,44]', 3420734: 'st.di\tr0,[r1,48]', 2702078: ';0x158cbc'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  observations=['Second worker registration selects 0x343280 in context 0x424404',
   'For request selector zero, worker stores response type one and callable result at 0x424800/+4',
   'Response mailbox consumer dispatches through handler stored at 0x424300',
   'Handler 0x247364 stores payload to 0x36ad58 and sets event 0x09900020 mask2 without zero-result check',
   'Wait wrapper does not compare wait result before clearing event and setting state byte 0x36ad54',
   'Nonzero second request selectors skip response-record initialization and still enter publication path',
   'First worker type-six branch also sends a separate response record via reverse mailbox'],
  limits=['Meaning of callable result and all request selectors not fully attributed',
   'Event notification is not proof of successful processing or JPEG persistence',
   'No runtime trace, concurrency guarantee or hardware modification'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
