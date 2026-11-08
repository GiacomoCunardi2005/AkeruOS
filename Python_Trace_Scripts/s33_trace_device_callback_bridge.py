#!/usr/bin/env python3
"""Offline S33 V1.1 device notification callback bridge, upper wait callers and distinct task event."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x248826,0x24883E,'SubmissionStateTwoBeforeActivation'),
 (0x295EAC,0x295EB4,'TwoDeviceCallbackSlotSetter'),
 (0x24814C,0x248164,'SinglePathCallbackConfiguration'),
 (0x2482E6,0x248306,'DualPathCallbackConfiguration'),
 (0x29615C,0x29618E,'DeviceHandlerThenOptionalCallback'),
 (0x24A3D0,0x24A460,'UpperNotificationCallbacks'),
 (0x24A1FC,0x24A238,'StateTwoWaitThenResetCaller'),
 (0x24A398,0x24A3D0,'StateTwoWaitThenCopyCaller'),
 (0x249D14,0x249D30,'ConditionalWaitInsideProcessingLoop'),
 (0x15D8D2,0x15D8E0,'ConsumerTaskDifferentEventWait'),
 (0x15DAD8,0x15DB28,'LaterSlotFlagClear')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/device_callback_bridge';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={2711352: 3588928, 2712076: 3589008, 2712080: 3589012, 2392880: 3583364, 2392892: 2401232, 2392924: 2401320, 2401376: 3583364, 2401400: 5292340, 2401404: 3583392, 2401408: 5291444, 1432156: 136314897}
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
 edges=[(2392414, 2711212), (2392822, 2711212), (2400816, 2709232), (2401200, 2709232), (2401216, 710944), (2399514, 2709232), (1431770, 1412356)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={0x24882E: 'mov_s\tr0,0x2', 0x248830: 'st_s\tr0,[r15,0x8]', 2711214: 'st_s\tr0,[r2,0x50]', 2711216: 'j_s.d\t[blink]', 2711218: 'st_s\tr1,[r2,0x54]', 2392404: 'ld\tr1,[r14,196]', 2392410: 'st_s\tr1,[r0,0x34]', 2392412: ';0x24833c', 2392418: 'mov_s\tr1,0', 2392806: 'ld\tr1,[r14,196]', 2392812: 'st_s\tr1,[r0,0x34]', 2392814: 'ld\tr1,[r14,200]', 2392818: 'st_s\tr1,[r0,0x38]', 2392826: ';0x24835c', 2711936: ';0x29620c', 2711944: 'jl_s\t[r0]', 2401272: 'mov_s\tr1,0x1', 2401274: 'st_s\tr1,[r2,0x8]', 2401306: 'ld_s\tr1,[r2,0x34]', 2401312: 'jl_s\t[r1]', 2401358: 'ld_s\tr1,[r1,0x38]', 2401366: 'jl_s.d\t[r1]', 2401368: 'ldw_s\tr0,[r0,0]', 2401190: 'cmp_s\tr0,0x2', 2401214: 'add_s\tr1,r13,0x4', 2401220: 'mov_s\tr2,0x20', 2401222: 'mov_s\tr0,0x1', 2401224: 'st_s\tr0,[r14,0x4]', 2401226: 'mov_s\tr0,0', 1431764: 'mov_s\tr1,0x7f', 1431766: 'asl_s\tr1,r1,0x7', 1431768: 'mov_s\tr2,0x1', 1431774: 'mov_s\tr3,0', 1432308: 'stb\tr1,[r0,132]'}
 for a,n in checks.items():assert n in line(a),line(a)
 assert 0x36c340+0x50==0x36c390 and 0x36c340+0x54==0x36c394
 assert 0x36ad84+0x34==0x36adb8 and 0x36ad84+0x38==0x36adbc
 assert 0x7f<<7==0x3f80
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  callback_bridge={'device_cell':'0x36c390','configured_function':'0x24a3d0','next_callback_cell':'0x36adb8','next_source':'initializer input+0xc4',
   'second_device_cell':'0x36c394','second_function':'0x24a428','second_next_cell':'0x36adbc','second_source':'initializer input+0xc8'},
  consumer_task_wait={'event':'0x08200011','mask':'0x3f80','site':'0x15d8da'},
  observations=['Device optional callback slots have a concrete two-pointer setter with second store in return delay slot',
   'Upper callback0x24a3d0 updates library state and conditionally invokes configured callback input+0xc4',
   'Upper callback0x24a428 uses second configured callback input+0xc8 under separate state guards',
   'State2 upper wait caller copies32bytes and publishes state1 without comparing wait-wrapper return',
   'Consumer task waits a different event0x08200011/mask0x3f80 before later slot-clear paths'],
  limits=['Configured callback identities and bridge to task event remain unresolved',
   'State1 publication after wait wrapper does not establish successful hardware completion',
   'Order, admission and optional callback presence require runtime or more static evidence',
   'No claim that all slot-clear paths depend on this wait; no hardware or JPEG persistence proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
