#!/usr/bin/env python3
"""Offline S33 V1.1 worker slot ready flags, consumer wait and modulo-four index bookkeeping."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x15C76E,0x15C82A,'ProducerReadyPublicationAndRingAdvance'),
 (0x15CF0C,0x15CF5A,'ConsumerReadyWaitAndSelectedIndex'),
 (0x15CFCC,0x15D004,'ConsumerAdditionalGateAndReturn'),
 (0x15D496,0x15D4B8,'ConsumerCallerAndSubmission'),
 (0x15DAD8,0x15DB28,'ReadyClearAndRequestedIndexAdvance'),
 (0x15E314,0x15E31E,'InitialRingReset'),
 (0x15C69C,0x15C6BA,'WorkerPostCompletionGate'),
 (0x15C5B2,0x15C5B8,'SkippedPublicationPath')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/worker_slot_cycle';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={1427212: 3743928, 1427236: 3743712, 1428224: 3744052, 1428228: 3743928, 1428232: 3743908, 1428236: 3744068, 1429436: 3744040, 1429440: 3568947, 1429444: 3743928, 1429448: 3569052, 1431228: 3743928, 1432152: 3743928, 1433176: 3569032, 1433180: 3744068, 1427196: 136314896, 1435072: 3743928}
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
 edges=[(1427474, 1412284), (1429304, 1681268), (1429328, 1429270), (1430688, 1429260), (1430696, 2393660), (1434392, 710924), (1427100, 1426544), (1427104, 1427470)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={1427350: 'ldb\tr1,[r0,140]', 1427358: 'stb\tr1,[r0,132]', 1427382: 'stb\tr1,[r0,136]', 1427412: 'stb\tr1,[r0,128]', 1427444: ';0x15c80e', 1427450: 'ldb\tr0,[r0,140]', 1427454: 'stb_s\tr0,[r1,0x1]', 1427456: 'add_s\tr0,r0,0x1', 1427458: 'asr_s\tr12,r0', 1427460: 'lsr_s\tr12,r12,0x1e', 1427462: 'add_s\tr0,r0,r12', 1427464: 'bmsk_s\tr0,r0,0x1', 1427466: 'sub_s\tr0,r0,r12', 1427468: 'stb_s\tr0,[r1,0]', 1427470: 'ld.as\tr0,[pcl,-68]', 1427478: 'mov_s\tr1,0x20', 1429266: 'mov_s\tr13,r0', 1429268: 'mov_s\tr15,r1', 1429270: ';0x15cfbc', 1429278: 'ldb_s\tr14,[r0,0x14]', 1429286: 'ldb_s\tr14,[r0,0x18]', 1429290: 'ldb_s\tr14,[r0,0x10]', 1429308: 'mov_s\tr0,0x5', 1429330: ';0x15cfc8', 1429332: 'stb_s\tr13,[r0,0]', 1430680: 'ldb\tr0,[r0,142]', 1430684: 'ld.as\tr1,[r14,65]', 1432288: 'ld.as\tr1,[r14,65]', 1432298: 'ldb\tr2,[r0,142]', 1432306: 'mov_s\tr1,0', 1432308: 'stb\tr1,[r0,132]', 1432334: 'mov_s\tr1,0', 1432338: 'stb\tr1,[r0,136]', 1432344: 'stb_s\tr2,[r0,0x2]', 1432352: 'stb\tr1,[r0,128]', 1432358: 'stb_s\tr2,[r0,0x2]', 1434396: 'mov_s\tr1,0x94', 1426870: 'mov_s\tr1,0'}
 for a,n in checks.items():assert n in line(a),line(a)
 modulo_cases=[]
 for old in range(256):
  x=old+1;correction=(x>>1)>>30
  decoded_arithmetic=((x+correction)&3)-correction
  assert decoded_arithmetic==(old+1)%4 and 0<=decoded_arithmetic<4
  modulo_cases.append(decoded_arithmetic)
 assert (0x15c80e&~3)-68*4==0x15c6fc
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  index_cells={'producer':'0x392144','previous_producer':'0x392145','requested':'0x392146','selected_for_consumer':'0x36759c'},
  ready_banks={'state0':'0x39213c','state1':'0x392140','other':'0x392138'},
  verified_modulo_byte_inputs=len(modulo_cases),modulo_first_cycle=modulo_cases[:4],
  completion_event={'id':'0x08200010','mask':'0x20'},
  observations=['Producer publishes ready byte to bank selected by state, then conditionally saves old index and advances modulo4',
   'Consumer helper polls matching bank at requested index and records selected index at config+0x10c',
   'Consumer-side bookkeeping clears ready byte, and state1 or default advances requested index modulo4',
   'Ready publication path itself does not compare saved worker result 0x36ad58'],
  limits=['Modulo update proves bounded output for byte inputs, not global invariant across all writers',
   'Selected flag protocol does not prove successful computation or completion of every physical consumer',
   'Wait has additional abort and gate paths; no universal successful return claim',
   'Full submission, hardware lifetime and final buffer reuse remain unresolved'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
