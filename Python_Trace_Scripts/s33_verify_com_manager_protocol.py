#!/usr/bin/env python3
"""Bounded USB producer/descriptor-parent tests; no scheduler or hardware.

Original event publication and descriptor pointer stores execute against a declared
empty-list kernel fixture. Backend, runtime state and outside services are stubs.
Producer and parent matrices are separate calls, not a simulated camera boot.
"""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib, json, re, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, u32, locate, disasm

BASE=0x366b7c; SELECTOR=BASE+33; GUARD=BASE+54
REC=0x373880; BITS=REC+36; HANDLE=0x2100001; CONFIG=0x3680a4
CURRENT=0x2000000; STATES=0x2001000
KERNEL=0x2040000; TASK=0x2041000; READY=0x2042000
WINDOWS=[(0x138e20,0x138e48),(0x138e9c,0x138eb4),(0x138ec0,0x138efc),
 (0x138efc,0x138f2c),(0x13901c,0x139098),(0x13910c,0x139120),
 (0x139120,0x13919e),(0x13919e,0x139226),(0x139226,0x13926e),
 (0x1394b0,0x1394e0),(0x139658,0x139674),(0x158c8c,0x158d04),
 (0x23c758,0x23c8ac),(0x23c8ac,0x23c902),(0x190c1c,0x190c7c),
 (0x81dba4,0x81dbc0)]


def main():
 out=ROOT/'Risultati/USB_MSDC_Default/Protocollo_ComMgr'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='bounded-com-manager-producer-and-descriptor-parent'))
 print('Evidence:',out,flush=True)
 try:
  r.prepare()
  prev=ROOT/json.loads((ROOT/'Risultati/USB_MSDC_Default/Struttura_USB/latest.json').read_text())['evidence']
  old=json.loads(prev.read_text());assert old['status']=='PASS_USBDEVMODE_IDENTITY_AND_LOCAL_STORES'
  for p,h in old['input_hashes'].items():assert sha(Path(p))==h,p;r.input_hashes[p]=h
  r.input_hashes[str(prev)]=sha(prev)
  candidate=ROOT/old['artifact_unchanged'];assert sha(candidate)==old['artifact_sha256']
  dump=(ROOT/'DUMPS/MainCode.dmp').read_bytes();spans=[]
  def check(a,n):
   b,o=locate(a,n);d=raw(a,n);assert dump[b['offset']+o:b['offset']+o+n]==d
   spans.append(dict(address=hex(a),bytes=n,sha256=hashlib.sha256(d).hexdigest()))
  listings=[]
  for a,b in WINDOWS:check(a,b-a);listings.append(disasm(a,b))
  (out/'gnu_verified.txt').write_text('\n'.join(listings))
  for a,v in [(0x138e48,HANDLE),(0x138eb4,GUARD),(0x138f2c,0x4109),
              (0x13909c,BASE+28),(0x1390a0,BASE),(0x138f68,BASE+8)]:check(a,4);assert u32(a)==v
  check(REC,56);assert struct.unpack('<14I',raw(REC,56))==(0x45564e4c,HANDLE,2)+tuple([0]*11)
  images={i:bytearray(PS[i]) for i in (0,1,4)};patches=[];maps=[]
  def binary(name,source):
   elf=compile_probe(r,name,source);p=out/(name+'.bin')
   proc=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert proc.returncode==0
   return p
  def mmap(p,a):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{p.stat().st_size}']
  head=f' mov r10,{CURRENT:#x}\n ld r10,[r10]\n'
  def record(code):
   return head+f' ld r9,[r10,64]\n add r11,r10,r9\n mov r9,{code}\n stb r9,[r11,128]\n ld r9,[r10,64]\n add r9,r9,1\n st r9,[r10,64]\n'
  def patch(name,target,source):
   address=0x2030000+len(patches)*0x200;p=binary(name,source);d=p.read_bytes();assert len(d)<0x200
   p.write_bytes(d+bytes(8+(-len(d))%8));maps.extend(mmap(p,address))
   t=binary('entry_'+name,f' mov_s r12,{address:#x}\n j_s [r12]\n').read_bytes();assert len(t)==8
   b,at=locate(target,8);assert not any(target<int(x['address'],16)+8 and int(x['address'],16)<target+8 for x in patches)
   before=bytes(images[b['index']][at:at+8]);images[b['index']][at:at+8]=t
   patches.append(dict(name=name,address=hex(target),destination=hex(address),original=before.hex(),replacement=t.hex()))
  for name,a,mode in [('ptp_backend',0x1394e0,2),('msdc_backend',0x13959c,1)]:
   patch(name,a,record(10+mode)+f' mov r9,{mode}\n st r9,[r10,68]\n ld r9,[r10,72]\n add r9,r9,1\n st r9,[r10,72]\n ld r0,[r10,4]\n j_s [blink]\n')
  patch('runtime_state',0x18ac58,record(20)+' ld r9,[r10]\n st r9,[r0]\n mov r0,0\n j_s [blink]\n')
  patch('application_event',0x169eb4,record(21)+' st r0,[r10,76]\n st r1,[r10,80]\n st r2,[r10,84]\n mov r0,0\n j_s [blink]\n')
  for name,a,offset,code in [('conditional_mount',0x139990,8,30),('branch_first',0x1399d8,12,31),('branch_second',0x1399fc,16,32)]:
   patch(name,a,record(code)+f' ld r0,[r10,{offset}]\n j_s [blink]\n')
  patch('alternate_four',0x139cf4,record(33)+' st r0,[r10,88]\n mov r0,0\n j_s [blink]\n')
  # Keep 1394B0 and its mode decision real, record its service identifiers.
  patch('mode_service',0x12a738,record(34)+' ld r9,[r10,92]\n add r11,r10,r9\n stb r0,[r11,112]\n add r9,r9,1\n st r9,[r10,92]\n mov r0,0\n j_s [blink]\n')
  zeros=[0x1435fc,0x81dbd0,0x139780,0x81dbf4,0x12b888,0x12b7e4,0x139a04,
         0x81dcb8,0x81dc8c,0x81dc6c]
  for i,a in enumerate(zeros):patch('outside_zero_'+str(i),a,' mov r0,0\n j_s [blink]\n')
  patch('serial',0x1e0eb0,' mov r0,0x2060000\n j_s [blink]\n')
  patch('time',0x129888,' mov r1,0\n st r1,[r0]\n st r1,[r0,4]\n st r1,[r0,8]\n st r1,[r0,12]\n st r1,[r0,16]\n j_s [blink]\n')
  callback_address=0x2050000;p=binary('callback',record(35)+' mov r0,0\n j_s [blink]\n');d=p.read_bytes();p.write_bytes(d+bytes(8+(-len(d))%8));maps.extend(mmap(p,callback_address))
  cases=[]
  for mode in (1,2,255):
   for state in (0,1,2,3,255,0xffffffff):
    for guard in (0,1,255):
     for status in (0,0x200304):cases.append(dict(kind='producer',mode=mode,state=state,guard=guard,status=status))
   for mount in (0,1):
    for first in (0,1):
     for second in (0,1):
      for callback in (0,1):cases.append(dict(kind='parent',mode=mode,guard=1,mount=mount,first=first,second=second,callback=callback))
  assert len(cases)==156
  states=bytearray(len(cases)*256);asm=f' mov r0,{KERNEL:#x}\n mov r1,0x369348\n st r0,[r1]\n'
  for i,c in enumerate(cases):
   a=STATES+i*256;struct.pack_into('<5I',states,i*256,c.get('state',0),c.get('status',0),c.get('mount',0),c.get('first',0),c.get('second',0))
   asm+=f' mov r21,{a:#x}\n mov r1,{CURRENT:#x}\n st r21,[r1]\n st sp,[r21,20]\n mov r1,{BASE:#x}\n mov r0,0\n'
   for j in range(16):asm+=f' st r0,[r1,{j*4}]\n'
   asm+=(f' mov r0,{c["mode"]}\n stb r0,[r1,33]\n mov r0,{c["guard"]}\n stb r0,[r1,54]\n'
         f' mov r0,{callback_address if c.get("callback") else 0:#x}\n st r0,[r1,24]\n st r0,[r1,8]\n'
         f' mov r0,0x80000002\n mov r1,{REC+8:#x}\n st r0,[r1]\n mov r0,0xa5000002\n mov r1,{BITS:#x}\n st r0,[r1]\n'
         f' mov r0,0\n mov r1,{CONFIG:#x}\n st r0,[r1]\n mov r12,{0x138e9c if c["kind"]=="producer" else 0x13901c:#x}\n jl [r12]\n st r0,[r21,24]\n st sp,[r21,28]\n'
         f' mov r1,{BASE:#x}\n ldb r0,[r1,33]\n st r0,[r21,32]\n ldb r0,[r1,54]\n st r0,[r21,36]\n'
         f' mov r1,{BITS:#x}\n ld r0,[r1]\n st r0,[r21,40]\n mov r1,{CONFIG:#x}\n ld r0,[r1]\n st r0,[r21,44]\n')
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  k=bytearray(0x800);struct.pack_into('<I',k,28,TASK);struct.pack_into('<I',k,44,READY)
  t=bytearray(0x100);struct.pack_into('<I',t,104,1)
  for name,a,data in [('kernel',KERNEL,k),('task',TASK,t),('ready',READY,struct.pack('<II',TASK,TASK)),
                     ('current',CURRENT,bytes(8)),('serial_data',0x2060000,b'12\0'+bytes(61)),('states_mmap',STATES,states)]:
   p=out/(name+'.bin');p.write_bytes(data);maps.extend(mmap(p,a))
  (out/'states_input.bin').write_bytes(states)
  for a,b in WINDOWS:
   block,at=locate(a,b-a);assert images[block['index']][at:at+b-a]==raw(a,b-a)
  for i,data in images.items():
   p=out/f'block{i}_LAB_ONLY.bin';p.write_bytes(data);maps.extend(mmap(p,BS[i]['load_address_candidate']))
  elf=compile_probe(r,'protocol_cases',asm);cpu,log=r.run('protocol_cases','/result/'+elf.name,maps,trace=True)
  assert cpu['exit_code']==0 and cpu['fault'] is None,log
  got=(out/'states_mmap.bin').read_bytes()
  for i,c in enumerate(cases):
   w=struct.unpack_from('<64I',got,i*256);events=list(got[i*256+128:i*256+128+w[16]])
   assert w[5]==w[7] and w[8]==c['mode'],(i,c,w)
   if c['kind']=='producer':
    active=c['guard']==0;direct=active and c['state'] not in (1,3);app=active and not direct;mark=2 if c['mode']==2 else 1
    assert w[6]==(c['status'] if active else c['guard']) and w[9]==(1 if active else c['guard']),(i,c,w)
    assert w[10]==(0xa5000003 if direct else 0xa5000002) and w[11]==0
    assert (w[17],w[18])==((mark,1) if active else (0,0))
    assert events==([10+mark,20]+([21] if app else []) if active else []),(i,c,events)
    if app:assert w[19:22]==(0,0x4109,0)
   else:
    alternate=bool(c['first'] and c['second']);expected=[30,31]+([32] if c['first'] else [])+([33] if alternate else [35,35] if c['callback'] else [])
    # Mode-service calls precede the branch predicates in the parent.
    identifiers=[0x1c,0x1d] if c['mode']==2 else [0x1e] if c['mode']==1 else []
    expected=[34]*len(identifiers)+expected
    assert events==expected,(i,c,events,expected)
    assert w[9]==int(alternate) and w[10]==0xa5000002 and w[11]==(0x3900f0 if c['mode']==2 else 0x3901b0),(i,c,w)
    assert w[23]==len(identifiers) and list(got[i*256+112:i*256+112+w[23]])==identifiers
    if alternate:assert w[22]==4
   c.update(return_value=hex(w[6]),guard_after=w[9],pending_bits=hex(w[10]),descriptor=hex(w[11]),backend_calls=w[18],events=events,stack_restored=True)
  (out/'cpu_cases.json').write_text(json.dumps(cases,indent=2)+'\n')
  trace=(out/'protocol_cases.trace').read_text();pcs=sorted({int(m[1],16) for m in re.finditer(r'^0x([0-9a-f]+)\s',trace,re.M)})
  checked=[]
  for pc in pcs:
   if any(int(x['address'],16)<=pc<int(x['address'],16)+8 for x in patches):continue
   try:locate(pc,8)
   except ValueError:continue
   check(pc,8);checked.append(pc)
  assert (out/'block0_LAB_ONLY.bin').read_bytes()==images[0] and (out/'block4_LAB_ONLY.bin').read_bytes()==images[4]
  mapped=(out/'block1_LAB_ONLY.bin').read_bytes();at=REC-BS[1]['load_address_candidate']
  assert struct.unpack_from('<14I',mapped,at)==(0x45564e4c,HANDLE,0x80000002,0,0,0,0,0,0,0xa5000002,0,0,0,0)
  for name,data in [('kernel',k),('task',t),('ready',struct.pack('<II',TASK,TASK))]:assert (out/(name+'.bin')).read_bytes()==data
  assert sha(candidate)==old['artifact_sha256']
  (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_BOUNDED_COM_MANAGER_PROTOCOL',previous_evidence=str(prev.relative_to(ROOT)),artifact_unchanged=str(candidate.relative_to(ROOT)),artifact_sha256=sha(candidate),
   cpu_cases=len(cases),producer_cases=108,parent_cases=48,windows=len(WINDOWS),original_unique_pcs=len(checked),checked_spans=spans,
   facts=['138EFC selects backend before state normalization and notification; backend error does not suppress notification',
          'Raw state1/3 dispatches application event4109; others set ComMgr event02100001/bit1',
          '13901C stores selected descriptor; direct guard clear139092 is skipped when1399D8 and1399FC are nonzero; alternate139CF4 is stubbed'],
   assumptions=['Empty event wait lists, active ComMgr record and nested-lock kernel are lab inputs; no task wake or scheduler',
                'Producer and parent matrices are separately called; no global ordering, boot or real connection simulated',
                'Outside parent services, backend bodies and runtime state getter are recording/return stubs; serial12 and zero time',
                'Only ComMgr event is marked active; controller events from descriptor pointer stores return uninitialized errors in this fixture'],
   limits=['Real runtime state,4109 consumer and scheduling/order relative to init default remain open',
           'Guard skip is conditional on supplied outside predicate returns; their real meaning and side effects remain open',
           'No USB enumeration, SD ownership, alias/copy exhaustion or physical recovery; candidate unchanged, NO-GO installation'])
  cpu.update(cases=len(cases),producer_cases=108,parent_cases=48)
  r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
 print('PASS:108 producer cases;48 descriptor-parent cases; no hardware; candidate unchanged',flush=True)


if __name__=='__main__':main()
