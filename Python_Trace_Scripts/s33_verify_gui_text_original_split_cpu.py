#!/usr/bin/env python3
"""Exercise original text splitting and restoration with synthetic callbacks."""
from datetime import datetime, timezone
from types import SimpleNamespace
from pathlib import Path
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, disasm

def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('text_original_split_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='text-temporary-write'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); dump=ROOT/'DUMPS/MainCode.dmp'; data=dump.read_bytes()
  for p in (dump,Path(__file__)): r.input_hashes[str(p)]=sha(p)
  for addr,size in ((0x186c40,0xa4),(0x186b14,0x12c),(0x14c768,8),(0x23acc4,8),(0x23ad30,8),(0x14c6f4,8)):
   block,off=locate(addr,size);assert raw(addr,size)==data[block['offset']+off:block['offset']+off+size]
  (out/'gnu_windows.txt').write_text(disasm(0x186c40,0x186ce4))
  images={i:bytearray(PS[i]) for i in (0,1,2)};maps=[];patches=[]
  def mapping(p,a):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{p.stat().st_size}']
  def binary(name,code):
   elf=compile_probe(r,name,code);p=out/(name+'.bin')
   run=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert run.returncode==0,run.stdout
   chunk=p.read_bytes();p.write_bytes(chunk+bytes(8+(-len(chunk))%8));return p
  for i,(name,addr,ret) in enumerate([('metric_mode',0x14c768,0),('metric_end',0x14c6f4,0),('byte_class',0x23ad30,0),('glyph_width',0x23acc4,10)]):
   target=0x2030000+i*0x400
   fixture=binary(name,f' mov r0,{ret}\n j_s [blink]\n');maps+=mapping(fixture,target)
   entry=binary(name+'_entry',f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   block,off=locate(addr,8);before=bytes(images[block['index']][off:off+8]);assert before==raw(addr,8)
   images[block['index']][off:off+8]=entry;patches.append({'address':hex(addr),'original':before.hex(),'fixture':entry.hex()})
  callback=binary('callback_fixture',''' mov r10,0x2005000
 ld r11,[r10,8]
 asl r12,r11,4
 add r12,r12,r10
 st r0,[r12,16]
 st r1,[r12,20]
 ld r0,[r0]
 st r0,[r12,24]
 add r11,r11,1
 st r11,[r10,8]
 ld r0,[r10,4]
 j_s [blink]
''');maps+=mapping(callback,0x2031000)
  tests=[(80,1),(30,0),(30,1)]
  asm=''
  for i,(width,cb_return) in enumerate(tests):
   addr=0x2001000+i*128
   asm+=f''' mov r20,{addr:#x}
 mov r1,0x2005000
 mov r0,{width}
 st r0,[r1]
 mov r0,{cb_return}
 st r0,[r1,4]
 mov r0,0
 st r0,[r1,8]
 mov r1,0x367f3e
 mov r0,1
 sth r0,[r1]
 st sp,[r20,0]
 mov r0,0x2200000
 mov r1,{width}
 mov r2,64
 mov r3,0x2031000
 mov r4,0
 mov r12,0x186c40
 jl [r12]
 st sp,[r20,4]
 mov r1,0x2005000
 ld r0,[r1,8]
 st r0,[r20,8]
 ld r0,[r1,16]
 st r0,[r20,12]
 ld r0,[r1,20]
 st r0,[r20,16]
 ld r0,[r1,24]
 st r0,[r20,20]
 ld r0,[r1,32]
 st r0,[r20,24]
 ld r0,[r1,36]
 st r0,[r20,28]
 ld r0,[r1,40]
 st r0,[r20,32]
 mov r1,0x2200000
 ld r0,[r1]
 st r0,[r20,36]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,img in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(img);maps+=mapping(p,BS[i]['load_address_candidate'])
  for name,addr,content in [('text',0x2200000,b'ISO X\0\xa5\xa5'),('calls',0x2005000,bytes(64)),('cases',0x2001000,bytes(384))]:
   p=out/(name+'.bin');p.write_bytes(content);maps+=mapping(p,addr)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert case['exit_code']==0 and case['fault'] is None,log
  rows=[]
  for i,(width,cb_return) in enumerate(tests):
   w=struct.unpack_from('<10I',(out/'cases.bin').read_bytes(),i*128)
   do_split=width==30
   assert w[0]==w[1] and w[9]==0x204f5349,(i,w)
   assert w[2]==(2 if do_split and cb_return else 1),(i,w)
   assert w[3]==0x2200000 and w[4]==(0 if do_split else 1) and w[5]==(0x004f5349 if do_split else 0x204f5349),(i,w)
   if w[2]==2:assert (w[6],w[7],w[8])==(0x2200004,1,0xa5a50058),(i,w)
   rows.append({'width':width,'split_observed':do_split,'callback_return':cb_return,'calls':w[2],
                'first_callback_text_bytes':struct.pack('<I',w[5]).hex(),
                'after_return_text_bytes':struct.pack('<I',w[9]).hex(),'stack_preserved':True})
  assert (out/'text.bin').read_bytes()==b'ISO X\0\xa5\xa5'
  trace=(out/'cases.trace').read_text()
  assert sum(line.startswith('0x186b14 ') for line in trace.splitlines())==4
  assert sum(line.startswith('0x186c9c ') for line in trace.splitlines())==2
  assert sum(line.startswith('0x186cbc ') for line in trace.splitlines())==2
  assert all(sha(p)==r.input_hashes[str(p)] for p in (dump,Path(__file__)))
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n')
  (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_ORIGINAL_SPLIT_AND_RESTORATION_SYNTHETIC_METRICS',scenarios=rows,
   assumptions=['Original 186c40 and 186b14 run with writable synthetic string; glyph width, byte classification, metric services and callback are fixtures; context is seeded.'],
   limits=['Glyph widths and character classification are synthetic; no original text renderer, real font, display, physical memory, concurrency or callback failure.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',len(tests),'synthetic text restoration cases;',out,flush=True)
if __name__=='__main__':main()
