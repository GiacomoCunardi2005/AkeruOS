#!/usr/bin/env python3
"""Offline S33 V1.1 grid construction and three-buffer dataflow through selected worker paths."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x3432CE,0x3432E4,'WorkerCommonArguments'),
 (0x16538C,0x1653B4,'FallbackWrapperForwarding'),
 (0x165414,0x16543E,'PreferredWrapperForwarding'),
 (0x1FE4A2,0x1FE4C2,'FallbackSourcePublication'),
 (0x200652,0x200672,'PreferredSourcePublication'),
 (0x1FE6CA,0x1FE704,'FallbackLowerArguments'),
 (0x2007B4,0x2007E2,'PreferredLowerArguments'),
 (0x1FD646,0x1FD65C,'LowerGridAndFinalDestination'),
 (0x1FD6A6,0x1FD6CE,'GridBranchSelectorCompare'),
 (0x1FD736,0x1FD894,'SimpleGridBuilderAndClampedColumn'),
 (0x1FD9CE,0x1FDA5C,'FirstInterpolatorCallAndFinalCopy'),
 (0x1FE0DC,0x1FE102,'SecondFallbackInterpolatorCall'),
 (0x200436,0x20047E,'PreferredInterpolatorCall'),
 (0x1FD514,0x1FD51A,'GridCoordinateReads'),
 (0x1FD5FA,0x1FD614,'GridReplacementAndAdvance')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/grid_buffer_flow';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
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
 edges=[(1463216, 2090096), (1463352, 2098720), (2090748, 2086420), (2099164, 2091680), (2087410, 2086116), (2089216, 2086116), (2098296, 2086116), (2086710, 2087516)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={3420890: 'ld_s\tr0,[r3,0]', 3420884: 'ld_s\tr1,[r3,0x4]', 3420892: 'ld_s\tr2,[r3,0x10]', 2090146: 'mov_s\tr25,r0', 2090148: 'st_s\tr1,[sp,0x1c]', 2090166: 'mov\tr19,0x3695dc', 2090174: 'st\tr2,[r19,40]', 2098770: 'mov_s\tr22,r0', 2098772: 'mov_s\tr23,r1', 2098790: 'mov\tr19,0x3695dc', 2098798: 'st\tr2,[r19,40]', 2090716: 'mov_s\tr0,r25', 2090734: 'ld_s\tr1,[sp,0x1c]', 2099148: 'mov_s\tr0,r22', 2099152: 'mov_s\tr1,r23', 2086470: 'st_s\tr1,[sp,0x4]', 2086476: 'mov_s\tr13,r0', 2086582: 'cmp_s\tr1,0x2', 2086714: 'st_s\tr0,[sp,0x24]', 2086720: 'cmp_s\tr1,0', 2086808: ';0x1fd814', 2086838: 'add1\tr9,r13,r3', 2086846: 'asr\tr11,r2', 2086850: 'cmp\tr4,r11', 2086860: 'extw\tr15,r11', 2086876: 'sth\tr11,[r9,2]', 2086886: 'sth\tr15,[r10,2]', 2086894: 'sth\tr16,[r11]', 2086912: 'add\tr9,r9,0x4', 2086962: 'add_s\tr0,r0,0x10', 2087004: 'sth\tr16,[r11,2]', 2087014: 'sth\tr9,[r15,2]', 2087020: 'sth\tr0,[r16]', 2087380: 'ld\tr4,[0x369604]', 2087396: 'mov_s\tr3,r13', 2087454: 'ld\tr4,[sp,4]', 2087462: 'add1\tr6,r13,r5', 2087470: 'ldh\tr0,[r6,2]', 2087484: 'asr_s\tr0,r0', 2087486: 'sth\tr0,[r4,2]', 2087490: 'ldh.ab\tr1,[r6,4]', 2087494: 'asr_s\tr1,r1', 2087496: 'sth.ab\tr1,[r4,4]', 2089182: 'ld\tr4,[0x369604]', 2098240: 'ld\tr4,[0x369604]', 2098250: 'mov_s\tr3,r18', 2086164: 'ldw_s\tr1,[r3,0x2]', 2086168: 'ldw_s\tr3,[r3,0]', 2086404: 'sth\tr3,[r10,2]', 2086408: 'add\tr3,r10,0x4'}
 for a,n in checks.items():assert n in line(a),line(a)
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  buffer_roles={'worker_payload+0':'grid scratch, later sampled pairs on selected paths',
   'worker_payload+4':'final destination used by selected halfword copy loops',
   'worker_payload+0x10':'source samples pointer stored at 0x369604 and loaded into interpolator r4'},
  shared_source_address=hex(0x3695dc+40),
  observations=['Both backend entry paths publish worker r2 to shared source pointer before lower calls',
   'Simple fallback branch generates regular coordinate pairs with final-column replication',
   'Shared helper overwrites same grid pairs, then selected lower loop writes shifted samples to separate destination argument',
   'Additional processing branches have different grid generation and remain incomplete'],
  limits=['No universal role across every branch or firmware call; selected dataflow only',
   'No allocation size, ownership, aliasing, concurrency or final-release proof',
   'Source component format and real mode admission remain unresolved',
   'No hardware execution or JPEG persistence proof'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
