#!/usr/bin/env python3
"""Bounded original UI57 entry/state-event USB selection; no hardware.

Original UI table, callback, selector getter and callback setter execute.
Outside UI/timer/volume services and backend bodies are recording stubs.
"""
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib,json,re,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,u32,locate,disasm
BASE=0x366b7c;SELECTOR=BASE+33;GUARD=BASE+54;CB=BASE+28
CURRENT=0x2000000;STATES=0x2001000;OBJECT=0x3eb3e8
WINDOWS=[(0x22451c,0x22454c),(0x224554,0x22457c),(0x22457c,0x2246b0),
 (0x2246c4,0x224704),(0x224704,0x224748),(0x224748,0x22477c),
 (0x138f70,0x138f78),(0x13a1e4,0x13a1fc),(0x138e9c,0x138eb4),
 (0x138ec0,0x138efc),(0x138efc,0x138f2c),(0x139658,0x139674),
 (0xc58c8,0xc58f4),(0xc58f8,0xc5910),(0xc5e8c,0xc5ea4),
 (0xc6234,0xc627c),(0xc627c,0xc62a4),(0xc5ec0,0xc5f00)]


def main():
 out=ROOT/'Risultati/USB_MSDC_Default/UI57'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='ui57-usb-entry-and-state-events'))
 print('Evidence:',out,flush=True)
 try:
  r.prepare();prev=ROOT/json.loads((ROOT/'Risultati/USB_MSDC_Default/Evento_4109/latest.json').read_text())['evidence'];old=json.loads(prev.read_text());assert old['status']=='PASS_USB4109_BOUNDED_QUEUE_AND_DEFAULT_HANDLER'
  for p,h in old['input_hashes'].items():assert sha(Path(p))==h,p;r.input_hashes[p]=h
  r.input_hashes[str(prev)]=sha(prev);candidate=ROOT/old['artifact_unchanged'];assert sha(candidate)==old['artifact_sha256']
  dump=(ROOT/'DUMPS/MainCode.dmp').read_bytes();spans=[]
  def check(a,n):
   b,o=locate(a,n);data=raw(a,n);assert dump[b['offset']+o:b['offset']+o+n]==data
   spans.append(dict(address=hex(a),bytes=n,sha256=hashlib.sha256(data).hexdigest()))
  text=[]
  for a,b in WINDOWS:check(a,b-a);text.append(disasm(a,b))
  (out/'gnu_verified.txt').write_text('\n'.join(text))
  pools={0x22454c:0x3eb408,0x224550:0x3eb428,0x2246b0:0x369e08,0x2246b8:0xd1870,
         0xc58f4:0x365618,0xc5ebc:0xc6234}
  for a,v in pools.items():check(a,4);assert u32(a)==v
  check(0x3f5900+0x57*4,4);assert u32(0x3f5900+0x57*4)==OBJECT
  check(OBJECT,32);assert u32(OBJECT+12)==0x22451c
  check(0x3eb408,32);check(0x3eb428,64)
  table=[struct.unpack('<II',raw(0x3eb428+i*8,8)) for i in range(8)]
  assert table[3]==(0x440e,0x224704) and table[-1]==(0,0x20e814)
  images={i:bytearray(PS[i]) for i in (0,1)};maps=[];patches=[]
  def binary(name,source):
   elf=compile_probe(r,name,source);p=out/(name+'.bin');proc=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert proc.returncode==0;return p
  def mmap(p,a):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{p.stat().st_size}']
  head=f' mov r10,{CURRENT:#x}\n ld r10,[r10]\n'
  def patch(name,target,source):
   address=0x2030000+len(patches)*0x200;p=binary(name,source);data=p.read_bytes();assert len(data)<0x200;p.write_bytes(data+bytes(8+(-len(data))%8));maps.extend(mmap(p,address))
   t=binary('entry_'+name,f' mov_s r12,{address:#x}\n j_s [r12]\n').read_bytes();assert len(t)==8
   b,at=locate(target,8);assert not any(target<int(x['address'],16)+8 and int(x['address'],16)<target+8 for x in patches)
   patches.append(dict(name=name,address=hex(target),original=bytes(images[b['index']][at:at+8]).hex(),replacement=t.hex()));images[b['index']][at:at+8]=t
  zeros=[0x135a84,0x137774,0xcb5e4,0xcad38,0x14b5c0,0x145b08,0x1439d4,0x1450a8,
         0x22479c,0x14905c,0xcfbac,0x148e14,0xcf5e0,0xcb84c,0x16aedc,0x13b0bc,
         0xcbdf8,0x177030,0x149028,0x143afc,0xd448c,0xcbea0,0x253cdc,0x136550]
  for i,a in enumerate(zeros):patch('outside_zero_'+str(i),a,' mov r0,0\n j_s [blink]\n')
  patch('object_flag_present',0x14503c,' mov r0,1\n j_s [blink]\n')
  for name,a,offset in [('primary_mode',0xc86cc,0),('profile',0xcb5a8,4),('usb_query',0x1398e8,8),('key',0x16f920,12)]:patch(name,a,head+f' ld r0,[r10,{offset}]\n j_s [blink]\n')
  patch('runtime_state',0x18ac58,' mov r1,0\n st r1,[r0]\n mov r0,0\n j_s [blink]\n')
  for name,a,mode in [('ptp',0x1394e0,2),('msdc',0x13959c,1)]:
   patch(name,a,head+f' mov r9,{mode}\n st r9,[r10,80]\n ld r9,[r10,84]\n add r9,r9,1\n st r9,[r10,84]\n mov r0,0\n j_s [blink]\n')
  patch('commgr_notification',0x158cbc,head+' st r0,[r10,88]\n st r1,[r10,92]\n ld r9,[r10,96]\n add r9,r9,1\n st r9,[r10,96]\n mov r0,0\n j_s [blink]\n')
  cases=[]
  for selector in (1,2):
   for key in (0,1,255,256):cases.append(dict(kind='validation',selector=selector,key=key))
   for mode in (0,10):
    for profile in (0,1):
     for query in (0,1):
      for seed in (0,0x12345678):
       for guard in (0,1):
        for arg in (0,1,3,4,0xffffffff):cases.append(dict(kind='entry_then_state',selector=selector,mode=mode,profile=profile,query=query,seed=seed,guard=guard,arg=arg))
  assert len(cases)==328
  states=bytearray(128*len(cases));asm=''
  def invoke(event,arg):return f' mov r0,{OBJECT:#x}\n mov r1,{event:#x}\n mov r2,{arg:#x}\n mov r12,0x22451c\n jl [r12]\n'
  for i,c in enumerate(cases):
   a=STATES+128*i;struct.pack_into('<4I',states,128*i,c.get('mode',0),c.get('profile',0),c.get('query',0),c.get('key',1))
   asm+=(f' mov r21,{a:#x}\n mov r1,{CURRENT:#x}\n st r21,[r1]\n st sp,[r21,16]\n mov r0,{c["selector"]}\n mov r1,{SELECTOR:#x}\n stb r0,[r1]\n'
         f' mov r0,{c.get("seed",0):#x}\n mov r1,{CB:#x}\n st r0,[r1]\n mov r0,0\n mov r1,0x369e08\n st r0,[r1]\n')
   if c['kind']=='validation':asm+=invoke(0x4403,0)+' st r0,[r21,20]\n'
   else:
    asm+=invoke(0x4405,0)+f' mov r1,{CB:#x}\n ld r0,[r1]\n st r0,[r21,24]\n mov r0,{c["guard"]}\n mov r1,{GUARD:#x}\n stb r0,[r1]\n'+invoke(0x440e,c['arg'])+invoke(0x440e,c['arg'])
   asm+=f' mov r1,{SELECTOR:#x}\n ldb r0,[r1]\n st r0,[r21,28]\n mov r1,{CB:#x}\n ld r0,[r1]\n st r0,[r21,32]\n mov r1,{GUARD:#x}\n ldb r0,[r1]\n st r0,[r21,36]\n st sp,[r21,40]\n'
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for a,b in WINDOWS:
   block,at=locate(a,b-a);assert images[block['index']][at:at+b-a]==raw(a,b-a)
  (out/'states_input.bin').write_bytes(states)
  for name,a,data in [('current',CURRENT,bytes(8)),('states_mmap',STATES,states)]+[(f'block{i}_LAB_ONLY',BS[i]['load_address_candidate'],d) for i,d in images.items()]:
   p=out/(name+'.bin');p.write_bytes(data);maps.extend(mmap(p,a))
  elf=compile_probe(r,'ui57_cases',asm);cpu,log=r.run('ui57_cases','/result/'+elf.name,maps,trace=True);assert cpu['exit_code']==0 and cpu['fault'] is None,log
  got=(out/'states_mmap.bin').read_bytes()
  for i,c in enumerate(cases):
   w=struct.unpack_from('<32I',got,128*i);assert w[4]==w[10] and w[7]==c['selector'],(i,c,w)
   if c['kind']=='validation':assert w[5]==(0 if c['key'] else 0xffffffff),(i,c,w)
   else:
    eligible=c['profile']==1 and c['query']==0
    expected=c['seed'] if c['mode']==10 or (eligible and c['selector']!=2) else 0xd1870 if eligible else 0
    active=c['arg']==1 and c['guard']==0
    assert w[6]==expected and w[8]==expected and w[9]==(1 if active else c['guard']),(i,c,w)
    assert w[20:22]==((c['selector'],1) if active else (0,0)),(i,c,w)
    assert w[24]==int(active)
    if active:assert w[22:24]==(0x2100001,1)
   c.update(selector_after=w[7],callback_after=hex(w[8]),backend_calls=w[21],guard_after=w[9],notification_calls=w[24],validation_return=hex(w[5]) if c['kind']=='validation' else None,stack_restored=True)
  (out/'cpu_cases.json').write_text(json.dumps(cases,indent=2)+'\n')
  trace=(out/'ui57_cases.trace').read_text();checked=[]
  for pc in sorted({int(m[1],16) for m in re.finditer(r'^0x([0-9a-f]+)\s',trace,re.M)}):
   if any(int(x['address'],16)<=pc<int(x['address'],16)+8 for x in patches):continue
   try:locate(pc,8)
   except ValueError:continue
   check(pc,8);checked.append(pc)
  assert (out/'block0_LAB_ONLY.bin').read_bytes()==images[0] and sha(candidate)==old['artifact_sha256']
  (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_UI57_BOUNDED_ENTRY_AND_BACKEND_GATE',previous_evidence=str(prev.relative_to(ROOT)),artifact_unchanged=str(candidate.relative_to(ROOT)),artifact_sha256=sha(candidate),
   cpu_cases=len(cases),validation_cases=8,entry_state_cases=320,windows=len(WINDOWS),original_unique_pcs=len(checked),checked_spans=spans,
   facts=['UI57 table440E invokes224704; argument1 requests guarded backend,3/4 do not request it in tested service profile',
          'Entry4405 selector2 conditionally installs callbackD1870 at366B98; selector1 skips setter and preserves prior callback in same profile',
          'Primary queryC86CC result10 skips callback setter, preserving prior value for both selectors',
          'Static coordinator order: C5910/C2, callback365618=C6234 withC5EC0, thenC59AC/C3,C5AF4/C4,C5A50/Resource'],
   assumptions=['Original UI callback/table/getter/callback setter and guarded backend selector; outside services and backend bodies stubbed',
                'Object descriptor57 supplied directly; no manager transition, validation enforcement, scheduler, timer or USB hardware',
                'Query profiles are lab inputs, not measured runtime modes; guard seed set by caller explicitly before state event'],
   limits=['CallbackD1870 body and actual timers are not executed; mode10 or eligible selector1 preserves a previous callback',
           'Static loader order does not exclude asynchronous events before default assignment; early USB ingress remains open',
           'No exhaustive alias/copy proof, actual SD ownership, enumeration or recovery; candidate unchanged, NO-GO installation'])
  cpu.update(cases=len(cases));r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
 print('PASS:8 validation cases;320 UI57 entry/state cases; candidate unchanged; no hardware',flush=True)


if __name__=='__main__':main()
