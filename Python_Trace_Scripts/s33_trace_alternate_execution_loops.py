#!/usr/bin/env python3
"""Offline S33 V1.1 alternate execution loops, mailbox admission and callback dispatch."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[(0x141C60,0x141C7A,'OrderedStartCallsAndErrorChecks'),
 (0x337290,0x3372E8,'FirstPersistentLoopAndCallback'),
 (0x23FB84,0x23FBDC,'SecondPersistentLoopAndCallback'),
 (0x3371C0,0x3371D0,'CPUWaitLeaf'),
 (0x33737C,0x3373BC,'FirstMailboxConsumerAndReverseProducer'),
 (0x2D51EC,0x2D526C,'ForwardProducersAndReverseConsumers'),
 (0x2D526C,0x2D52AC,'SecondConsumerAndReverseProducer'),
 (0x3372E8,0x337324,'FirstTimerSetsGateFour'),
 (0x337324,0x33737C,'FirstTimerRearmDecision'),
 (0x23FC18,0x23FC70,'SecondTimerRearmDecision'),
 (0x293A9E,0x293AB4,'ConcreteFirstProducerCaller'),
 (0x24732C,0x247338,'ConcreteSecondProducerCaller')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/alternate_execution_loops';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={}
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
 edges=[(1317984, 1415708), (1317994, 1416416), (3371668, 3371456), (2358152, 3371456), (3371724, 3371900), (2358208, 2970220), (2970112, 1497704), (2970176, 1497704), (3371952, 1497704), (2970272, 1497704), (2701998, 2970092), (2388784, 2970156)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={1317992: ';0x141c78', 1318002: ';0x141c78', 3371456: 'sleep\t0', 3371678: ';0x337294', 3371684: 'st.di\tr14,[r13,8]', 3371740: 'jl_s\t[r1]', 3371744: ';0x337298', 2358168: 'st.di\tr15,[r14,8]', 2358224: 'jl_s\t[r1]', 2358228: ';0x23fb8c', 3371900: '0x427b00', 3371922: 'st_s\tr1,[r0,0]', 3371926: 'st.di\tr0,[r2]', 2970094: '0x427b00', 2970106: ';0x2d51f4', 2970108: 'st.di\tr0,[r2]', 3371934: '0x428200', 2970124: '0x428200', 2970158: '0x428300', 2970220: '0x428300', 2970188: '0x428400', 2970254: '0x428400', 2970246: 'st.di\tr0,[r2]', 3371770: 'st.di\tr1,[r0]', 3371760: 'mov_s\tr1,0x4', 3371860: ';0x337378', 2358344: ';0x23fc6c'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  mailboxes=[dict(address='0x427b00',producer='0x2d51ec',consumer='0x33737c'),
   dict(address='0x428200',producer='0x33739c',consumer='0x2d520c'),
   dict(address='0x428300',producer='0x2d522c',consumer='0x2d526c'),
   dict(address='0x428400',producer='0x2d528c',consumer='0x2d524c')],
  observations=['Initializer calls both start routines in order and stops at first nonzero return',
   'Execution entries wait for gate4, store gate3, consume mailbox then call function at context+4',
   'Consumers clear mailbox before worker callback executes; zero mailbox is admission, not callback completion',
   'Producers spin on occupied word, publish input and call 0x16da68 with channel ID',
   'CPU wait leaf executes sleep0; timer callback sets gate4 and uses aux limit/control/count0'],
  limits=['Single producer/consumer concurrency and memory ordering contract not established',
   'No time conversion, hardware wakeup or full lifecycle attribution',
   'No proof of equivalence to JPEG completion or safe buffer reuse'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
