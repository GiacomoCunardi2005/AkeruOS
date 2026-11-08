#!/usr/bin/env python3
"""Offline S33 V1.1 concrete constructor callbacks closing device-to-consumer task event bridge."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x15EE46,0x15EE50,'ConcreteCallbackInputObject'),
 (0x15EF2E,0x15EF40,'CallbackObjectConstructorCall'),
 (0x15EF8A,0x15EF98,'LibraryInitializationWithSameObject'),
 (0x243ECC,0x243F48,'ObjectConstructorAndTwoCallbackFields'),
 (0x24448C,0x24449E,'TwoTaskEventCallbacks'),
 (0x24814C,0x248164,'FirstUpperCallbackBinding'),
 (0x2482E6,0x2482FC,'SecondUpperCallbackBinding'),
 (0x24A3D0,0x24A460,'UpperCallbacksInvokeConfiguredFunctions'),
 (0x15D8D2,0x15D8E8,'TaskEventWaitAndImmediateContinuation'),
 (0x15DAD8,0x15DB28,'LaterGuardedSlotRelease')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/task_event_bridge';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={1438244: 4477340, 2375756: 2376844, 2375760: 2376852, 2376904: 136314897, 2392880: 3583364, 2392892: 2401232, 2392924: 2401320, 1432156: 136314897}
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
 edges=[(1437488, 2375372), (1437578, 2392212), (2375428, 2375208), (2376846, 1412284), (2376854, 1412284), (2392414, 2711212), (2392822, 2711212), (1431770, 1412356)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={1437254: ';0x15f224', 1437256: 'mov_s\tr0,r13', 1437486: 'mov_s\tr0,r13', 1437582: 'mov_s\tr0,r13', 2375380: 'mov_s\tr13,r0', 2375432: ';0x243f40', 2375470: ';0x24404c', 2375472: 'st\tr0,[r13,196]', 2375476: ';0x244050', 2375478: 'st\tr0,[r13,200]', 2376844: ';0x2444c8', 2376850: 'mov_s\tr1,0x80', 2376852: ';0x2444c8', 2376858: 'mov\tr1,256', 2392404: 'ld\tr1,[r14,196]', 2392410: 'st_s\tr1,[r0,0x34]', 2392806: 'ld\tr1,[r14,196]', 2392812: 'st_s\tr1,[r0,0x34]', 2392814: 'ld\tr1,[r14,200]', 2392818: 'st_s\tr1,[r0,0x38]', 2401306: 'ld_s\tr1,[r2,0x34]', 2401312: 'jl_s\t[r1]', 2401358: 'ld_s\tr1,[r1,0x38]', 2401366: 'jl_s.d\t[r1]', 1431762: ';0x15da5c', 1431764: 'mov_s\tr1,0x7f', 1431766: 'asl_s\tr1,r1,0x7', 1431768: 'mov_s\tr2,0x1', 1431774: 'mov_s\tr3,0', 1431776: 'ld\tr0,[r14,212]'}
 for a,n in checks.items():assert n in line(a),line(a)
 callbacks=[dict(input_offset='0xc4',input_cell=hex(0x44519c+196),function='0x24448c',library_cell=hex(0x36ad84+0x34),event='0x08200011',mask='0x80'),
  dict(input_offset='0xc8',input_cell=hex(0x44519c+200),function='0x244494',library_cell=hex(0x36ad84+0x38),event='0x08200011',mask='0x100')]
 wait_mask=0x7f<<7;assert wait_mask==0x3f80
 for callback in callbacks:assert int(callback['mask'],16)&wait_mask==int(callback['mask'],16)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  configured_callbacks=callbacks,task_wait_mask=hex(wait_mask),
  observations=['Constructor0x243ecc installs concrete task-event callbacks into input+0xc4/+0xc8',
   'Verified caller constructs object0x44519c then passes it to library0x248094',
   'Concrete callbacks signal same task event0x08200011 with masks0x80/0x100 in tail-branch delay slots',
   'Both masks are members of task wait mask0x3f80; RTOS option semantics and wait result still require audit',
   'Task immediately loads another field after wait rather than comparing returned status'],
  limits=['Bridge is conditional on constructor success, configuration admission and active handler path',
   'No claim that either bit alone satisfies the complete RTOS wait condition',
   'Other mask bits, event freshness and every path to slot clear remain incomplete',
   'No runtime notification, final physical buffer-use or JPEG persistence proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
