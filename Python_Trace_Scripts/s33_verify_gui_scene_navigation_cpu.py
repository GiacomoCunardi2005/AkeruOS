#!/usr/bin/env python3
"""Execute Scene Mode LV2 left/right callbacks with the original index getter and setter."""
from datetime import datetime, timezone
from types import SimpleNamespace
import json,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,locate,u32,disasm

def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('scene_nav_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-scene-mode-left-right'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for addr,n in [(0x7ca554,0x1de),(0xcfc44,0x2c),(0x981f4c,12*8)]:
   b,o=locate(addr,n);assert raw(addr,n)==data[b['offset']+o:b['offset']+o+n]
  assert u32(0xcfc4c)==0x3657c2 and u32(0x7ca4d8)==0x899832
  events={u32(0x981f4c+i*8):u32(0x981f50+i*8) for i in range(12)}
  assert events[0x480]==0x7ca554 and events[0x500]==0x7ca634
  (out/'gnu_windows.txt').write_text(disasm(0x7ca554,0x7ca634)+disasm(0x7ca634,0x7ca6e8)+disasm(0xcfc44,0xcfc4c))
  images={i:bytearray(PS[i]) for i in (0,1,4,5)};maps=[];patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm);p=out/(name+'.bin');res=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert res.returncode==0,res.stdout
   b=p.read_bytes();p.write_bytes(b+bytes(8+(-len(b))%8));return p
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  common=' mov r10,0x2000000\n ld r10,[r10]\n'
  services=[('resource',0x145654,' mov r0,0x2100000\n j_s [blink]\n'),
   ('position',0x1450b8,common+' st r1,[r10,4]\n st r2,[r10,8]\n ld r11,[r10,12]\n add r11,r11,1\n st r11,[r10,12]\n mov r0,0\n j_s [blink]\n'),
   ('select',0x131544,common+' st r0,[r10,16]\n ld r11,[r10,20]\n add r11,r11,1\n st r11,[r10,20]\n mov r0,0\n j_s [blink]\n'),
   ('refresh',0x145150,common+' ld r11,[r10,24]\n add r11,r11,1\n st r11,[r10,24]\n mov r0,0\n j_s [blink]\n'),
   ('change_notify',0xcc518,common+' st r0,[r10,28]\n ld r11,[r10,32]\n add r11,r11,1\n st r11,[r10,32]\n mov r0,0\n j_s [blink]\n')]
  for i,(name,addr,asm) in enumerate(services):
   target=0x2030000+i*0x400;p=binary(name,asm);maps+=mapping(p,target,p.stat().st_size)
   entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(addr,8);before=bytes(images[b['index']][o:o+8]);assert before==raw(addr,8)
   images[b['index']][o:o+8]=entry;patches.append({'service':name,'address':hex(addr),'original':before.hex(),'fixture':entry.hex()})
  tests=[(event,initial,0x1f) for event in (0x480,0x500) for initial in range(5)]+[(0x480,2,0),(0x500,2,0)]
  state=bytearray(len(tests)*128);asm=' mov r20,0x2000000\n'
  for i,(event,initial,mode) in enumerate(tests):
   stateaddr=0x2001000+i*128;entry=events[event]
   asm+=f''' mov r21,{stateaddr:#x}
 st r21,[r20]
 mov r1,0x899832
 mov r0,{mode}
 stb r0,[r1]
 mov r1,0x3657c2
 mov r0,{initial}
 sth r0,[r1]
 st sp,[r21,36]
 mov r0,0x2100000
 mov r1,{event}
 mov r2,0
 mov r12,{entry:#x}
 jl [r12]
 mov r1,0x3657c2
 ldh r0,[r1]
 st r0,[r21,40]
 st sp,[r21,44]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(image);maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
  p=out/'cases.bin';p.write_bytes(state);maps+=mapping(p,0x2001000,len(state));statefile=p
  p=out/'current.bin';p.write_bytes(bytes(8));maps+=mapping(p,0x2000000,8)
  p=out/'context.bin';p.write_bytes(bytes(256));maps+=mapping(p,0x2100000,256)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert case['exit_code']==0 and case['fault'] is None,log
  got=statefile.read_bytes();results=[]
  for i,(event,initial,mode) in enumerate(tests):
   w=struct.unpack_from('<12I',got,i*128);new=(initial+(1 if event==0x480 else -1))%5 if mode==0x1f else initial
   active=int(mode==0x1f);assert w[10]==new and w[9]==w[11],(i,w,new)
   assert (w[3],w[5],w[6],w[8])==(active,active,active,active),(i,w)
   if active: assert (w[1],w[2],w[4],w[7])==(12,138+90*(4-new),new,16),(i,w,new)
   results.append({'event':hex(event),'mode':hex(mode),'initial':initial,'final':new,'position':w[2] if active else None,
                   'select_calls':w[5],'refresh_calls':w[6],'stack_preserved':True})
  (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(__import__('pathlib').Path(__file__).read_bytes())
  r.results.update(status='PASS_SCENE_NAVIGATION_BOUNDED',scenarios=results,
   assumptions=['Original left/right handlers, index getter and setter; five external services are fixtures.',
   'Synthetic mode 0x1f and initial indices 0..4; UI positions and selection services are recorders.'],
   limits=['Handlers called directly after static event-table verification; no dispatcher, event queue or physical key.',
   'Mode 0x7b and other paths untested; no rendering, hardware or proof of meaning of selection.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: 12 Scene Mode LV2 left/right cases;',out,flush=True)
if __name__=='__main__':main()
