#!/usr/bin/env python3
"""Offline S33 V1.1 device IRQ status-to-event handlers, registrar slot and matching event wait."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x295EC8,0x295F30,'BankOneNotificationRegistration'),
 (0x29615C,0x2961F4,'ThreeNotificationHandlers'),
 (0x2ED4C4,0x2ED52C,'MatchingEventWaitAndTeardown'),
 (0x2956F0,0x2956FC,'OuterWaitWrapperReturnsZero'),
 (0x16D8FA,0x16D906,'RegistrarGroup0900'),
 (0x16D988,0x16D9AE,'RegistrarRecordMatchAndCallbackStore'),
 (0x2487AA,0x2487BC,'ConsumerRegistersBankOneHandler'),
 (0x2ED450,0x2ED4C4,'LowerArmingAndEventClear')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/device_status_notifications';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={2711356: 2711900, 2711360: 2314, 2711364: 2711952, 2712052: 2712000, 2712056: 2314, 2712068: 66060290, 2712076: 3589008, 2712080: 3589012, 3069912: 66060290, 3069920: 2314, 1497904: 4344880}
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
 edges=[(2711252, 1497240), (2711906, 3074500), (2711920, 3074500), (2711930, 1412284), (2711980, 1412284), (2712030, 1412284), (3069144, 1412356), (3069168, 1412356), (3069174, 1541864), (3069182, 1497152), (2709234, 3069124), (2394032, 2711240)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={2711250: ';0x295f3c', 2711256: ';0x295f40', 2711902: 'mov_s\tr0,0x1', 2711904: 'mov_s\tr1,r0', 2711910: 'mov_s\tr2,r0', 2711912: 'cmp_s\tr0,0', 2711914: ';0x29618a', 2711916: 'mov_s\tr0,0x1', 2711918: 'mov_s\tr1,0', 2711924: 'mov_s\tr2,r0', 2711926: ';0x296204', 2711934: 'bset_s\tr1,r1,0x10', 2711936: ';0x29620c', 2711944: 'jl_s\t[r0]', 2711962: 'mov_s\tr2,0', 2711984: 'mov_s\tr1,0x1', 2712034: 'bset_s\tr1,r1,0x10', 2712036: ';0x296210', 3069162: 'mov_s\tr1,0', 3069164: 'bset_s\tr1,r1,0x10', 3069166: 'mov_s\tr2,0', 3069172: 'mov_s\tr3,r2', 3069178: 'mov_s\tr13,r0', 3069224: 'mov_s\tr0,r13', 2709242: 'mov_s\tr0,0', 1497346: ';0x16db30', 1497498: 'add3\tr14,r13,r3', 1497502: 'ldh.di\tr2,[r14,12]', 1497510: 'st.di\tr1,[r14,16]', 2394036: 'mov_s\tr0,0x1', 3069090: 'bset_s\tr1,r1,0x10'}
 for a,n in checks.items():assert n in line(a),line(a)
 def data(a,n):
  hits=[b for b in bs if b['load_address_candidate']<=a and a+n<=b['load_address_candidate']+len(ps[b['index']])]
  assert len(hits)==1
  b=hits[0];return ps[b['index']][a-b['load_address_candidate']:a-b['load_address_candidate']+n]
 table=0x424c30;count=struct.unpack('<H',data(table+8,2))[0];assert count==14
 records=[]
 for i in range(count):
  address=table+12+8*i;identifier=struct.unpack('<H',data(address,2))[0]
  records.append(dict(index=i,id=hex(identifier),callback_address=hex(address+4),initial_callback=hex(struct.unpack('<I',data(address+4,4))[0])))
 matched=[r for r in records if r['id']=='0x90a'];assert len(matched)==1
 assert matched[0]['index']==6 and matched[0]['callback_address']=='0x424c70'
 assert struct.unpack('<I',data(0x40d01c+4,4))[0]==2
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  registrar_record=matched[0],registrar_record_count=count,
  notification_contract={'bank1':{'handler':'0x29615c','status_address':'0x0fe9813c','status_mask':'0x2','event':'0x03f00002','event_mask':'0x10000','callback_cell':'0x36c390'},
   'bank0':{'handler':'0x296190','status_address':'0x0fe9013c','status_mask':'0x2','event':'0x03f00002','event_mask':'0x1','callback_cell':'0x36c390'}},
  observations=['Bank1 registration requests ID0x090a handler0x29615c, matching registrar table row6 callback cell0x424c70',
   'Handler tests status index1, performs operation0, then signals shared event with bank-specific mask and optional callback',
   'Lower wait uses same event/mask, then performs critical-section and teardown without comparing event wait return',
   'Outer wait wrapper returns zero in delay slot; it does not propagate lower wait return'],
  limits=['No runtime registration or invocation proof; registrar admission guards can reject requests',
   'Physical status-bit meaning and last hardware use remain unproven',
   'Optional callback writers and link from every consumer to this wait are incomplete',
   'No hardware access, timeout verification or JPEG persistence proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
