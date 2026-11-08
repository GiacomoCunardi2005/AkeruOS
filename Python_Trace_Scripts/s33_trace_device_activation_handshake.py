#!/usr/bin/env python3
"""Offline S33 V1.1 device activation handshake control/status mappings and local unbounded polls."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x29601C,0x296050,'ActivationWrapperReturn'),
 (0x2EDC60,0x2EDD18,'CompleteActivationHandshake'),
 (0x2EE7B0,0x2EE7F0,'ControlBitDispatcher'),
 (0x2EE9C4,0x2EEA08,'StatusOperationDispatcher'),
 (0x309AFC,0x309B30,'BankOneControlBitWriter'),
 (0x309C44,0x309C60,'BankOneStatusOperationSwitch'),
 (0x309CB2,0x309CB6,'StatusReadPoolLoad'),
 (0x309CBC,0x309CC8,'BankOneStatusHalfwordRead'),
 (0x309C68,0x309C6C,'StatusWritePoolLoad'),
 (0x309C70,0x309C88,'BankOneStatusOperationZeroWrite'),
 (0x248826,0x24883E,'ConsumerActivationCall')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/device_activation_handshake';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={3072020: 3073968, 3072024: 3074500, 3074584: 4246276, 3074588: 4246348, 3074592: 4246420, 3074596: 4246492, 3074688: 4247532, 3074692: 4247580, 3185848: 266961212, 3185772: 266961212}
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
 edges=[(2394162, 2711580), (2711586, 3071072), (2711620, 3073968), (3071150, 3071140), (3071186, 3071176), (3071226, 3071216), (3074020, 3185404), (3074540, 3185732), (3185856, 3185860)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={2711590: 'mov_s\tr0,0x1', 2711614: 'mov_s\tr2,0', 2711624: 'mov_s\tr2,r1', 2711630: 'mov_s\tr0,0', 3071078: 'mov_s\tr16,r0', 3071082: ';0x2ee014', 3071122: ';0x2ee018', 3071140: 'mov_s\tr0,0x3', 3071142: 'mov_s\tr1,0x1', 3071144: 'jl_s.d\t[r14]', 3071146: 'mov_s\tr2,r16', 3071148: 'cmp_s\tr0,0', 3071176: 'mov_s\tr0,0x7', 3071178: 'mov_s\tr1,0x1', 3071184: 'cmp_s\tr0,0', 3071196: 'cmp_s\tr15,0x1', 3071216: 'mov_s\tr0,0xa', 3071218: 'mov_s\tr1,0x1', 3071224: 'cmp_s\tr0,0', 3071236: 'mov_s\tr0,0x2', 3071238: 'mov_s\tr1,0x1', 3071244: 'mov_s\tr0,0x2', 3071246: 'mov_s\tr1,0', 3074546: 'cmp_s\tr13,0x1', 3074552: ';0x2eea84', 3074558: 'and_s\tr0,r0,r1', 3185440: 'ldh.di\tr10,[r3]', 3185448: 'sth.di\tr10,[r3]', 3185844: ';0x309cbc', 3185852: 'ldh.di\tr0,[r0]', 3185780: 'and\tr0,r0,-2048', 3185784: 'bmsk_s\tr13,r13,0xa', 3185790: 'sth.di\tr0,[r15]', 3185752: 'ldh.as.x\tr1,[r12,r1]'}
 for a,n in checks.items():assert n in line(a),line(a)
 def data_word(a):
  hits=[b for b in bs if b['load_address_candidate']<=a and a+4<=b['load_address_candidate']+len(ps[b['index']])]
  assert len(hits)==1
  b=hits[0];return struct.unpack_from('<I',ps[b['index']],a-b['load_address_candidate'])[0]
 controls=[];statuses=[]
 for bank,addresses,masks in [(0,0x40cb04,0x40cb4c),(1,0x40cb94,0x40cbdc)]:
  for idx in (2,3,5,6,7):
   address,mask=data_word(addresses+idx*4),data_word(masks+idx*4)
   assert address==((0x0fe90138 if idx==7 else 0x0fe9012c)+bank*0x8000)
   controls.append(dict(bank=bank,index=idx,address=hex(address),mask=hex(mask)))
 for bank,table in [(0,0x40cfec),(1,0x40d01c)]:
  for idx,mask in ([(3,8),(7,128)] if bank==0 else [(3,8),(7,128),(10,1024)]):
   assert data_word(table+idx*4)==mask
   statuses.append(dict(bank=bank,index=idx,address=hex(0x0fe9013c+bank*0x8000),mask=hex(mask)))
 jt=struct.unpack_from('<4h',ps[0],0x309c60-info[0]['load_address_candidate'])
 assert tuple(jt)==(4,41,20,32) and 0x309c60+2*jt[1]==0x309cb2
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  control_mappings=controls,status_mappings=statuses,
  polling_loops=[dict(test_index=i,branch=hex(b),target=hex(t)) for i,b,t in [(3,0x2edcae,0x2edca4),(7,0x2edcd2,0x2edcc8),(10,0x2edcfa,0x2edcf0)]],
  status_jump_table=dict(base='0x309c60',relative_halfword_entries=list(jt),read_case='0x309cb2'),
  observations=['Activation performs control updates and polls nonzero status masks3/7, plus10 for normalized bank1',
   'Status operation1 reads fixed status register then masks; operation0 writes low11 bits in bank1',
   'Three local polling loops contain no timeout or scheduler call',
   'Wrapper 0x29601c returns zero through delay slot after more control writes'],
  limits=['Register functional labels and relation to last frame-buffer use are not proven',
   'No claim that observed status polls indicate frame completion rather than an activation handshake',
   'Write-one-to-clear or acknowledgement semantics are not inferred merely from stores',
   'No silicon execution, physical completion or JPEG persistence proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
