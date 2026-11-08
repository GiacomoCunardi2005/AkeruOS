#!/usr/bin/env python3
"""Original USB4109 enqueue/pop/default handler with explicit outside stubs.

No WindowMgr scheduler or object transition is executed. The lab passes the
popped event to the default handler directly; actual object routing stays open.
"""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib,json,re,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,u32,locate,disasm,cstring
CURRENT=0x2000000;STATES=0x2001000;BASE=0x366b7c;GUARD=BASE+54
RING=0x367bbc;SLOTS=0x47a848;TABLE=0x3e8bb4
WINDOWS=[(0x138e9c,0x138eb4),(0x138ec0,0x138efc),(0x138efc,0x138f2c),
 (0x139658,0x139674),(0x169eb4,0x169f00),(0x17bc7c,0x17bce4),
 (0x17bd4c,0x17bd98),(0x20e814,0x20e844),(0x169f60,0x169fb4),
 (0x20fc04,0x20fc24),(0x144314,0x1443ac),(0x1399bc,0x1399d4),
 (0x1399d8,0x1399e0),(0x1399e0,0x1399f8),(0x1399fc,0x139a04),(0x139cf4,0x139d14),
 (0x13a1a4,0x13a1c0),(0xc5f00,0xc5f34)]


def main():
 out=ROOT/'Risultati/USB_MSDC_Default/Evento_4109'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='usb4109-queue-default-handler-and-byte-contracts'))
 print('Evidence:',out,flush=True)
 try:
  r.prepare();prev=ROOT/json.loads((ROOT/'Risultati/USB_MSDC_Default/Protocollo_ComMgr/latest.json').read_text())['evidence'];old=json.loads(prev.read_text());assert old['status']=='PASS_BOUNDED_COM_MANAGER_PROTOCOL'
  for p,h in old['input_hashes'].items():assert sha(Path(p))==h,p;r.input_hashes[p]=h
  r.input_hashes[str(prev)]=sha(prev);candidate=ROOT/old['artifact_unchanged'];assert sha(candidate)==old['artifact_sha256']
  dump=(ROOT/'DUMPS/MainCode.dmp').read_bytes();spans=[]
  def check(a,n):
   b,o=locate(a,n);d=raw(a,n);assert dump[b['offset']+o:b['offset']+o+n]==d
   spans.append(dict(address=hex(a),bytes=n,sha256=hashlib.sha256(d).hexdigest()))
  listing=[]
  for a,b in WINDOWS:check(a,b-a);listing.append(disasm(a,b))
  (out/'gnu_verified.txt').write_text('\n'.join(listing))
  pools={0x20e844:TABLE,0x1399d4:BASE+37,0x1399f8:BASE+38,0x139d14:BASE+20,
         0x17bff8:RING,0x17c000:SLOTS,0x1443ac:0x366e6c,0x1443b0:0x366e84}
  for a,v in pools.items():check(a,4);assert u32(a)==v
  check(BASE+36,3);check(BASE+20,4);assert raw(BASE+36,3)==bytes(3) and u32(BASE+20)==0
  entries=[]
  for i in range(512):
   a=TABLE+8*i;event,handler=struct.unpack('<II',raw(a,8));entries.append(dict(address=hex(a),event=hex(event),handler=hex(handler)))
   if event==0:break
  else:raise AssertionError('Missing default table terminator')
  assert [e for e in entries if e['event']=='0x4109']==[dict(address='0x3e8d0c',event='0x4109',handler='0x20fc04')]
  check(TABLE,len(entries)*8);(out/'default_event_table.json').write_text(json.dumps(entries,indent=2)+'\n')
  names=[]
  for ident in (7,0x5e,0x87,0xa5,0xc2):
   a=u32(0x3f5900+4*ident);words=struct.unpack('<6I',raw(a,24));name=cstring(words[5]);assert name
   check(0x3f5900+4*ident,4);check(a,24);check(words[5],len(name)+1);names.append(dict(id=hex(ident),descriptor=hex(a),name=name))
  (out/'requested_objects.json').write_text(json.dumps(names,indent=2)+'\n')
  images={i:bytearray(PS[i]) for i in (0,1)};patches=[];maps=[]
  def binary(name,source):
   elf=compile_probe(r,name,source);p=out/(name+'.bin');proc=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert proc.returncode==0;return p
  def mmap(p,a):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{p.stat().st_size}']
  head=f' mov r10,{CURRENT:#x}\n ld r10,[r10]\n'
  def patch(name,target,source):
   address=0x2030000+len(patches)*0x200;p=binary(name,source);data=p.read_bytes();assert len(data)<0x200;p.write_bytes(data+bytes(8+(-len(data))%8));maps.extend(mmap(p,address))
   t=binary('entry_'+name,f' mov_s r12,{address:#x}\n j_s [r12]\n').read_bytes();assert len(t)==8
   b,at=locate(target,8);assert not any(target<int(x['address'],16)+8 and int(x['address'],16)<target+8 for x in patches)
   patches.append(dict(name=name,address=hex(target),original=bytes(images[b['index']][at:at+8]).hex(),replacement=t.hex()));images[b['index']][at:at+8]=t
  for name,a,mode in [('ptp',0x1394e0,2),('msdc',0x13959c,1)]:patch(name,a,head+f' mov r9,{mode}\n st r9,[r10,64]\n mov r0,0\n j_s [blink]\n')
  patch('runtime_state',0x18ac58,head+' ld r9,[r10]\n st r9,[r0]\n mov r0,0\n j_s [blink]\n')
  for name,a in [('lock',0x1593ac),('unlock',0x1594a4),('context_enter',0x1786e8),('context_exit',0x179354)]:patch(name,a,' mov r0,0\n j_s [blink]\n')
  patch('queue_notification',0x158cbc,head+' ld r9,[r10,68]\n add r9,r9,1\n st r9,[r10,68]\n st r0,[r10,72]\n st r1,[r10,76]\n mov r0,0\n j_s [blink]\n')
  for name,a,offset in [('predicate',0xd21a4,4),('current_object',0x1453fc,8),('mode',0xcad30,12),('boot_mode',0xbbc20,16)]:patch(name,a,head+f' ld r0,[r10,{offset}]\n j_s [blink]\n')
  patch('prepare_warning',0xc7dd8,head+' ld r9,[r10,80]\n add r9,r9,1\n st r9,[r10,80]\n mov r0,0\n j_s [blink]\n')
  patch('request_transition',0x1453e4,head+' st r0,[r10,84]\n st r1,[r10,88]\n ld r9,[r10,92]\n add r9,r9,1\n st r9,[r10,92]\n mov r0,0\n j_s [blink]\n')
  cbaddr=0x2050000;p=binary('callback_record',head+' st r0,[r10,96]\n mov r0,0x123\n j_s [blink]\n');data=p.read_bytes();p.write_bytes(data+bytes(8+(-len(data))%8));maps.extend(mmap(p,cbaddr))
  cases=[]
  profiles=[dict(predicate=0,current=0,mode=0,boot=0,flag=0,request=0x87),dict(predicate=1,current=0,mode=0,boot=0,flag=0,request=0xc2),dict(predicate=0,current=0xa5,mode=0,boot=2,flag=1,request=7),dict(predicate=0,current=0,mode=0,boot=2,flag=1,request=0x5e)]
  for selector in (1,2):
   for state in (1,3):
    for index in (0,1,63,127):
     for profile in profiles:cases.append(dict(kind='queued_default',selector=selector,state=state,index=index,**profile))
     cases.append(dict(kind='full_queue',selector=selector,state=state,index=index))
  for setter,getter,cell in [(0x1399bc,0x1399d8,BASE+37),(0x1399e0,0x1399fc,BASE+38)]:
   for v in [*range(256),256,257,0xffffffff]:cases.append(dict(kind='byte_contract',selector=1,setter=setter,getter=getter,cell=cell,value=v))
  for callback in (0,cbaddr):
   for arg in (0,4,256,0xffffffff):cases.append(dict(kind='alternate_callback',selector=1,callback=callback,value=arg))
  assert len(cases)==606
  states=bytearray(256*len(cases));asm=''
  def call(a):return f' mov r12,{a:#x}\n jl [r12]\n'
  for i,c in enumerate(cases):
   a=STATES+i*256;struct.pack_into('<5I',states,i*256,c.get('state',0),c.get('predicate',0),c.get('current',0),c.get('mode',0),c.get('boot',0))
   asm+=f' mov r21,{a:#x}\n mov r1,{CURRENT:#x}\n st r21,[r1]\n st sp,[r21,20]\n mov r0,{c["selector"]}\n mov r1,{BASE+33:#x}\n stb r0,[r1]\n mov r0,0\n mov r1,{GUARD:#x}\n stb r0,[r1]\n'
   kind=c['kind']
   if kind in ('queued_default','full_queue'):
    index=c['index'];read=(index+1)&127 if kind=='full_queue' else index
    asm+=(f' mov r1,{SLOTS+12*index:#x}\n mov r0,0xdeadbeef\n st r0,[r1]\n st r0,[r1,4]\n st r0,[r1,8]\n'
          f' mov r0,{read}\n mov r1,{RING:#x}\n sth r0,[r1]\n mov r0,{index}\n sth r0,[r1,2]\n'
          f' mov r0,0\n mov r1,0x36780c\n st r0,[r1]\n mov r0,{c.get("flag",0)}\n mov r1,0x366e84\n stb r0,[r1]\n'+call(0x138e9c)+' st r0,[r21,24]\n')
    if kind=='queued_default':
     asm+=' add r0,r21,112\n'+call(0x17bd4c)+' st r0,[r21,28]\n ld r0,[r21,112]\n ldh r1,[r21,116]\n ld r2,[r21,120]\n'+call(0x20e814)
    asm+=(f' mov r1,{RING:#x}\n ldh r0,[r1]\n st r0,[r21,32]\n ldh r0,[r1,2]\n st r0,[r21,36]\n mov r1,0x366e84\n ldb r0,[r1]\n st r0,[r21,40]\n'
          f' mov r1,{SLOTS+12*index:#x}\n ld r0,[r1]\n st r0,[r21,124]\n ld r0,[r1,4]\n st r0,[r21,128]\n ld r0,[r1,8]\n st r0,[r21,132]\n')
   elif kind=='byte_contract':
    asm+=f' mov r0,{c["value"]:#x}\n'+call(c['setter'])+call(c['getter'])+' st r0,[r21,24]\n'
   else:
    asm+=f' mov r0,{c["callback"]:#x}\n'+call(0x13a1a4)+f' mov r0,{c["value"]:#x}\n'+call(0x139cf4)+' st r0,[r21,24]\n'
   asm+=f' mov r1,{BASE+33:#x}\n ldb r0,[r1]\n st r0,[r21,44]\n mov r1,{GUARD:#x}\n ldb r0,[r1]\n st r0,[r21,48]\n st sp,[r21,52]\n'
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for a,b in WINDOWS:
   block,at=locate(a,b-a);assert images[block['index']][at:at+b-a]==raw(a,b-a)
  (out/'states_input.bin').write_bytes(states)
  for name,a,data in [('current',CURRENT,bytes(8)),('states_mmap',STATES,states),('ring_slots',SLOTS,bytes(0x600))]+[(f'block{i}_LAB_ONLY',BS[i]['load_address_candidate'],d) for i,d in images.items()]:
   p=out/(name+'.bin');p.write_bytes(data);maps.extend(mmap(p,a))
  elf=compile_probe(r,'event_cases',asm);cpu,log=r.run('event_cases','/result/'+elf.name,maps,trace=True);assert cpu['exit_code']==0 and cpu['fault'] is None,log
  got=(out/'states_mmap.bin').read_bytes()
  for i,c in enumerate(cases):
   w=struct.unpack_from('<64I',got,i*256);assert w[5]==w[13] and w[11]==c['selector'],(i,c,w)
   if c['kind']=='queued_default':
    end=(c['index']+1)&127;assert w[6:10]==(0,1,end,end) and w[28:31]==(0,0x4109,0) and w[31:34]==(0,0xdead4109,0),(i,c,w)
    assert w[16:20]==(c['selector'],1,0x300008,1) and w[21:24]==(c['request'],0,1),(i,c,w)
    assert w[10]==0 and w[12]==1
   elif c['kind']=='full_queue':
    assert w[6]==0 and w[8:10]==((c['index']+1)&127,c['index']) and w[17]==0 and w[23]==0 and w[12]==1 and w[31:34]==(0xdeadbeef,)*3,(i,c,w)
   elif c['kind']=='byte_contract':assert w[6]==c['value']&255 and w[12]==0,(i,c,w)
   else:
    assert w[6]==(0x123 if c['callback'] else 0) and w[24]==(c['value'] if c['callback'] else 0) and w[12]==0,(i,c,w)
   c.update(observed_return=hex(w[6]),selector_after=w[11],guard_after=w[12],transition_request=hex(w[21]),queue_notifications=w[17],stack_restored=True)
  (out/'cpu_cases.json').write_text(json.dumps(cases,indent=2)+'\n')
  trace=(out/'event_cases.trace').read_text();checked=[]
  for pc in sorted({int(m[1],16) for m in re.finditer(r'^0x([0-9a-f]+)\s',trace,re.M)}):
   if any(int(x['address'],16)<=pc<int(x['address'],16)+8 for x in patches):continue
   try:locate(pc,8)
   except ValueError:continue
   check(pc,8);checked.append(pc)
  assert (out/'block0_LAB_ONLY.bin').read_bytes()==images[0] and sha(candidate)==old['artifact_sha256']
  (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_USB4109_BOUNDED_QUEUE_AND_DEFAULT_HANDLER',previous_evidence=str(prev.relative_to(ROOT)),artifact_unchanged=str(candidate.relative_to(ROOT)),artifact_sha256=sha(candidate),
   cpu_cases=len(cases),queued_dispatch_cases=64,full_queue_cases=16,byte_contract_cases=518,callback_cases=8,windows=len(WINDOWS),original_unique_pcs=len(checked),checked_spans=spans,table_entries=len(entries),requested_objects=names,
   assumptions=['Original producer/queue/pop/default table/handler; outside lock, runtime state, UI queries and transition services stubbed',
                'Host harness calls default callback after pop; WindowMgr/current-object dispatch and actual UI changes not executed',
                'Only valid empty/full ring indices supplied; no concurrency; queue notification service is a recorder'],
   limits=['Default4109 handler requests a UI transition; not direct ComMgr notification or proof USB mode completed',
           'Real callback at366B90 and global writers/residency remain unknown; byte getter contracts do not assign physical semantics',
           'No actual USB, SD or recovery, candidate unchanged, NO-GO installation'])
  cpu.update(cases=len(cases));r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
 print('PASS:64 queued/default dispatch;16 full queues;518 byte contracts;8 callbacks; no hardware',flush=True)


if __name__=='__main__':main()
