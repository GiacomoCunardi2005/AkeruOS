#!/usr/bin/env python3
"""Execute HotKeyMenu wrapper and simple navigation handlers using an open recorder."""
from datetime import datetime, timezone
from types import SimpleNamespace
import json,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,locate,u16,u32,disasm

def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('hotkey_navigation_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-hotkey-menu-navigation'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';d=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x3f5b74,4),(0x7846f4,24),(0x784714,80),(0x6646c0,0x38),(0x664830,0x60),(0x169f60,0x54)]:
   b,o=locate(a,n);assert raw(a,n)==d[b['offset']+o:b['offset']+o+n]
  assert u32(0x3f5900+0x9d*4)==0x7846f4 and u16(0x7846f8)==0x9d and u32(0x784700)==0x6646c0
  assert u32(0x6646f0)==0x6820c0 and u32(0x6646f4)==0x784714
  events={u32(0x784714+8*i):u32(0x784718+8*i) for i in range(10)}
  assert {e:events[e] for e in (0x80,0x180,0x580)}=={0x80:0x664830,0x180:0x664850,0x580:0x664870}
  (out/'gnu_windows.txt').write_text(disasm(0x6646c0,0x6646ee)+disasm(0x664830,0x664890))
  images={i:bytearray(PS[i]) for i in (0,2,3)};maps=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm);p=out/(name+'.bin');x=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert x.returncode==0,x.stdout
   b=p.read_bytes();p.write_bytes(b+bytes(8+(-len(b))%8));return p
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  stub=binary('open',''' mov r10,0x2000000
 ld r10,[r10]
 st r0,[r10]
 st r1,[r10,4]
 ld r11,[r10,8]
 add r11,r11,1
 st r11,[r10,8]
 mov r0,0
 j_s [blink]
''');maps+=mapping(stub,0x2030000,stub.stat().st_size)
  entry=binary('entry_open',' mov_s r12,0x2030000\n j_s [r12]\n').read_bytes()[:8]
  b,o=locate(0x1453e4,8);before=bytes(images[b['index']][o:o+8]);assert before==raw(0x1453e4,8)
  images[b['index']][o:o+8]=entry
  tests=[(e,blocked) for e in (0x80,0x180,0x580) for blocked in (0,1)]
  state=bytearray(len(tests)*64);asm=' mov r20,0x2000000\n'
  for i,(event,blocked) in enumerate(tests):
   addr=0x2001000+i*64;filtered=event if blocked else 0x4004
   asm+=f''' mov r21,{addr:#x}
 st r21,[r20]
 mov r0,{filtered:#x}
 mov r1,0x6820c0
 sth r0,[r1]
 mov r0,0
 sth r0,[r1,2]
 st sp,[r21,12]
 mov r0,0
 mov r1,{event:#x}
 mov r2,0
 mov r12,0x6646c0
 jl [r12]
 st sp,[r21,16]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(image);maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
  p=out/'cases.bin';p.write_bytes(state);maps+=mapping(p,0x2001000,len(state));statefile=p
  p=out/'current.bin';p.write_bytes(bytes(8));maps+=mapping(p,0x2000000,8)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert case['exit_code']==0 and case['fault'] is None,log
  got=statefile.read_bytes();rows=[]
  for i,(event,blocked) in enumerate(tests):
   dest,arg,count,before_sp,after_sp=struct.unpack_from('<5I',got,i*64);expected=(2,4) if event==0x580 else (0x87,0)
   assert before_sp==after_sp and count==1-blocked,(i,dest,arg,count)
   if not blocked:assert (dest,arg)==expected,(i,dest,arg)
   rows.append({'event':hex(event),'filtered':bool(blocked),'open_calls':count,'destination':hex(dest) if count else None,'argument':arg if count else None,'stack_preserved':True})
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n')
  (out/'fixture_patch.json').write_text(json.dumps({'address':'0x1453e4','original':before.hex(),'fixture':entry.hex(),'meaning':'open recorder'},indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(__import__('pathlib').Path(__file__).read_bytes())
  r.results.update(status='PASS_HOTKEY_NAVIGATION_BOUNDED',scenarios=rows,
   assumptions=['Original wrapper 6646c0, event dispatcher 169f60, event handlers and table.', 'Synthetic RAM filter; open 1453e4 replaced by recorder.'],
   limits=['No real WindowMgr, transition, display, queue, physical input or service effects.', 'Only events 80, 180, 580 and fixture filters tested.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: 6 bounded HotKeyMenu navigation cases;',out,flush=True)
if __name__=='__main__':main()
