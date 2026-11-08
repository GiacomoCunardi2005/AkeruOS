#!/usr/bin/env python3
"""Verify original debug-menu ISO/time value propagation using synthetic inputs."""
from datetime import datetime,timezone
from types import SimpleNamespace
import json,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,locate,u16,u32,disasm

def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('debug_exposure_values_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-debug-exposure-values'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';d=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x7d2394,0x30),(0x7d25b0,0x40),(0xd03b8,0x4c),(0x17c320,0xd0),(0xde78c,0x40),(0xf6f0c,8),(0x989cf8,72),(0x989ff8,24)]:
   b,o=locate(a,n);assert raw(a,n)==d[b['offset']+o:b['offset']+o+n]
  assert u32(0x7d23c4)==0x899ad0 and u32(0xd03d4)==0x365787 and u32(0xd03fc)==0x365788
  assert u32(0x17c3e8)==0x367bc8 and u32(0xf6f10)==0x37fbd0
  assert any(u32(0x989cf8+8*i)==0x580 and u32(0x989cfc+8*i)==0x7d2394 for i in range(9))
  assert u32(0x98a000)==0x4801 and u32(0x98a004)==0x7d25b0
  windows=[disasm(0x7d2394,0x7d23c4),disasm(0x7d25b0,0x7d25f0),disasm(0xd03b8,0xd03d4),
           disasm(0xd03e0,0xd03fc),disasm(0x17c320,0x17c3e8),disasm(0xde78c,0xde7d0)]
  (out/'gnu_windows.txt').write_text('\n'.join(windows))
  images={i:bytearray(PS[i]) for i in (0,1,4,5)}
  def binary(name,asm):
   elf=compile_probe(r,name,asm);p=out/(name+'.bin');x=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert x.returncode==0,x.stdout
   v=p.read_bytes();p.write_bytes(v+bytes(8+(-len(v))%8));return p
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  open_stub=binary('open',''' mov r10,0x2000000
 ld r10,[r10]
 st r0,[r10,16]
 st r1,[r10,20]
 ld r11,[r10,24]
 add r11,r11,1
 st r11,[r10,24]
 mov r0,0
 j_s [blink]
''');maps=mapping(open_stub,0x2030000,open_stub.stat().st_size)
  entry=binary('entry_open',' mov_s r12,0x2030000\n j_s [r12]\n').read_bytes()[:8]
  b,o=locate(0x1453e4,8);before=bytes(images[b['index']][o:o+8]);assert before==raw(0x1453e4,8);images[b['index']][o:o+8]=entry
  expected_iso=[0,50,64,80,100,120,125,140,160,200,250,280,320,400,500,640,800,1000,1250,1600,2000,2500,3200,6400,0]
  tests=[('iso',i) for i in range(25)]+[('time',i) for i in (0,1,42,120,4000)]
  state=bytearray(len(tests)*96);asm=' mov r20,0x2000000\n'
  for i,(kind,val) in enumerate(tests):
   stateaddr=0x2001000+i*96;asm+=f' mov r21,{stateaddr:#x}\n st r21,[r20]\n st sp,[r21,28]\n'
   if kind=='iso':
    asm+=f''' mov r0,{val}
 mov r12,0xd03b8
 jl [r12]
 mov r1,0x365787
 ldb r0,[r1]
 st r0,[r21]
 mov r1,0x367bc8
 ldb r0,[r1]
 st r0,[r21,4]
 mov r1,0x37fbf2
 ldh r0,[r1]
 st r0,[r21,8]
'''
   else:
    asm+=f''' mov r1,0x899ad0
 mov r0,{val}
 st r0,[r1]
 mov r0,0
 mov r1,0x580
 mov r2,0
 mov r12,0x7d2394
 jl [r12]
 mov r1,0x365788
 ld r0,[r1]
 st r0,[r21]
 mov r1,0x37fbf4
 ld r0,[r1]
 st r0,[r21,4]
'''
   asm+=' st sp,[r21,32]\n'
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(image);maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
  p=out/'cases.bin';p.write_bytes(state);maps+=mapping(p,0x2001000,len(state));sf=p
  p=out/'current.bin';p.write_bytes(bytes(8));maps+=mapping(p,0x2000000,8)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  got=sf.read_bytes();rows=[]
  for i,(kind,val) in enumerate(tests):
   w=struct.unpack_from('<9I',got,i*96);assert w[7]==w[8],(kind,val,w)
   if kind=='iso':assert (w[0],w[1],w[2])==(val,val,expected_iso[val]),(kind,val,w)
   else:assert (w[0],w[1],w[4],w[5],w[6])==(val*1000,val*1000,0x36,0,1),(kind,val,w)
   rows.append({'case':kind,'input':val,'state_a':w[0],'state_b':w[1],
    'converted':w[2] if kind=='iso' else None,'open_id':hex(w[4]) if kind=='time' else None,'stack_preserved':True})
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patch.json').write_text(json.dumps({'service':'0x1453e4','original':before.hex(),'fixture':entry.hex()},indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(__import__('pathlib').Path(__file__).read_bytes())
  r.results.update(status='PASS_DEBUG_EXPOSURE_VALUE_PATHS',scenarios=rows,
   assumptions=['Original ISO setter and conversion; original exposure confirmation callback and setters.',
                'Synthetic input enum/time values and RAM; open 1453e4 replaced by recorder.'],
   limits=['No actual camera capture, AE arbitration, sensor effect, persistence or physical range established.',
           'ISO callback selection path inspected statically; tests call the downstream setter directly.',
           'Exposure input values are injected, not necessarily reachable through UI.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: 25 ISO enum values and 5 synthetic exposure confirmation values;',out,flush=True)
if __name__=='__main__':main()
