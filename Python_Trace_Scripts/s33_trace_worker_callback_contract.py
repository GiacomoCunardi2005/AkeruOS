#!/usr/bin/env python3
"""Offline S33 V1.1 concrete worker callbacks, constant guard, arguments and returned status."""
import json,re,struct,tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads,run,sha
ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x165338,0x165440,'BothConcreteCallbacks'),
 (0xC7870,0xC7874,'ConstantGuardReturn'),
 (0x334110,0x33413A,'CallbackRegisterSave'),
 (0x33415C,0x334162,'CallbackRestoreEntry'),
 (0x3341BA,0x3341E4,'CallbackRegisterRestore'),
 (0x343298,0x3432F4,'WorkerArgumentsAndResponse'),
 (0x1FE470,0x1FE73C,'FallbackBackendFullBody'),
 (0x200620,0x200818,'PreferredBackendFullBody'),
 (0x247364,0x247398,'ResponseValueAndEvent')]
def main():
 bs,ps,bd=verified_payloads(ROOT);info={b['index']:b for b in bs}
 out=ROOT/'Ghidra_Results/ghidra_reports/worker_callback_contract';out.mkdir(parents=True,exist_ok=True)
 def word(a):return struct.unpack_from('<I',ps[0],a-info[0]['load_address_candidate'])[0]
 literals={}
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
 edges=[(1463098, 3358992), (1463136, 817264), (1463144, 1463180), (1463216, 2090096), (1463228, 3359068), (1463234, 3358992), (1463272, 817264), (1463280, 1463316), (1463352, 2098720), (1463356, 1463220), (2090748, 2086420), (2099164, 2091680), (2388864, 2357816), (2388876, 1412284)]
 for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
 checks={817264: 'mov_s\tr0,0x1', 817266: 'j_s\t[blink]', 1463142: 'cmp_s\tr0,0', 1463278: 'cmp_s\tr0,0', 1463180: 'ld\tr0,[fp,48]', 1463192: 'ldb\tr0,[fp,52]', 1463190: 'st_s\tr0,[sp,0]', 1463208: 'st_s\tr0,[sp,0x4]', 1463316: 'ld\tr0,[fp,48]', 1463328: 'ldb\tr0,[fp,52]', 1463326: 'st_s\tr0,[sp,0]', 1463344: 'st_s\tr0,[sp,0x4]', 3420834: 'ld_s\tr13,[r3,0x38]', 3420858: 'ld_s\tr13,[r3,0x34]', 3420878: 'st_s\tr0,[sp,0]', 3420880: 'ldb\tr0,[r3,48]', 3420884: 'ld_s\tr1,[r3,0x4]', 3420886: 'mov_s\tr4,r14', 3420888: 'st_s\tr0,[sp,0x4]', 3420890: 'ld_s\tr0,[r3,0]', 3420892: 'ld_s\tr2,[r3,0x10]', 3420894: 'ldw_s\tr3,[r3,0x14]', 3420896: 'jl_s.d\t[r13]', 3420898: 'mov_s\tr5,r15', 3420912: 'st.di\tr0,[r1,4]', 2090354: 'mov\tr23,0x2af9', 2090376: 'mov\tr23,0', 2090432: 'mov\tr23,0x2afa', 2090756: 'mov_s\tr0,r23', 2098952: 'mov\tr20,0', 2098958: 'mov\tr20,1002', 2099170: 'mov_s\tr0,r20', 2090808: 'j_s\t[blink]', 2099222: 'j_s\t[blink]', 2388852: 'ld.di\tr1,[r1,4]', 2388856: 'mov_s\tr0,0x36ad58', 2388862: 'st_s\tr1,[r0,0]', 2388870: 'mov_s\tr0,0x9900020', 2388880: 'mov_s\tr1,0x2'}
 for a,n in checks.items():assert n in line(a),line(a)
 # Explore ordinary intra-function branches. Calls are assumed to return and
 # preserve callee-saved status registers; this does not execute the firmware.
 def status_flow(start,end,register,assignments):
  ins={}
  for raw in listing.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+)+)\s*(\S+)\s*(.*)$',raw)
   if m and start<=int(m[1],16)<end:
    ins[int(m[1],16)]=(m[3],m[4])
  addresses=sorted(ins);nxt=dict(zip(addresses,addresses[1:]))
  pending=[(start,'unassigned')];seen=set();returned=set()
  branch=re.compile(r'^b(?:eq|ne|lt|ge|gt|le|lo|ls|hi|hs|c|nc|n|p|v|nv)?(?:_s)?(?:\.d)?$')
  while pending:
   pc,value=pending.pop()
   if (pc,value) in seen:continue
   seen.add((pc,value));op,args=ins[pc]
   if pc in assignments:value=assignments[pc]
   if op=='j_s' and args=='[blink]':returned.add(value);continue
   if branch.fullmatch(op):
    target=int(re.search(r';0x([0-9a-f]+)',args)[1],16)
    assert target in ins,(hex(pc),hex(target))
    if op.endswith('.d'):
     slot=nxt[pc]
     assert slot not in assignments,'status assignment in delay slot needs explicit model'
     fall=nxt[slot]
    else:fall=nxt[pc]
    pending.append((target,value))
    if op not in ('b','b_s','b.d','b_s.d'):pending.append((fall,value))
   else:
    assert pc in nxt,hex(pc)
    pending.append((nxt[pc],value))
  assert returned==set(assignments.values()),(register,returned)
  return dict(register=register,return_values=sorted(returned),visited_states=len(seen),
   assumptions='ordinary call returns preserve status register; no exceptions or runtime code mutation')
 flows={
  'fallback':status_flow(0x1FE470,0x1FE73A,'r23',{0x1FE572:'0x2af9',0x1FE588:'0',0x1FE5C0:'0x2afa'}),
  'preferred':status_flow(0x200620,0x200818,'r20',{0x200708:'0',0x20070E:'1002'})}
 result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
  script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in bs},
  windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
  checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],checked_instructions=len(checks),
  checked_literals={hex(a):hex(v) for a,v in literals.items()},
  ordinary_branch_status_flow=flows,
  callback_backends={'0x165338':'0x1fe470','0x1653c0':'0x200620'},
  worker_arguments={'r0':'payload+0x00 word','r1':'payload+0x04 word','r2':'payload+0x10 word',
   'r3':'payload+0x14 halfword','r4':'payload+0x16 halfword',
   'r5':'preferred payload+0x20, fallback +0x18',
   'r6':'preferred payload+0x24, fallback +0x1c',
   'r7':'preferred payload+0x28, fallback +0x20',
   'stack0':'preferred payload+0x2c, fallback +0x24','stack4':'payload+0x30 byte'},
  observed_status_assignments={'fallback':['0','0x2af9','0x2afa'],'preferred':['0','1002']},
  observations=['Guard 0xc7870 returns constant 1; both callbacks take nonzero branch to backend in unmodified static image',
   'Conditional zero-return bypass involving 0xd2e40 is not reached from these entries under that constant',
   'Callback wrappers forward register and two stack arguments; second stack argument is byte loaded',
   'Backend tails replace immediate inner-call return with locally selected status register',
   'Worker copies callback return to response+4; handler saves it to 0x36ad58 and signals event without success comparison'],
  limits=['Status labels and the mathematical or image meaning of backend operations remain unresolved',
   'No claim of successful JPEG processing or physical buffer release',
   'All callees, exception paths and possible runtime code mutation are not fully audited',
   'Constant guard is a static image property, not observed camera execution'])
 (out/'gnu_verified.txt').write_text(listing)
 (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instructions')
if __name__=='__main__':main()
