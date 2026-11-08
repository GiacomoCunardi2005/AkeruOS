#!/usr/bin/env python3
"""Execute original RAW configuration selection and special helper with synthetic services."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, EXPECTED, ORIGINAL, raw, locate, disasm


def main():
 out=ROOT/'Risultati/HiddenMenu_RAW'/datetime.now(timezone.utc).strftime('prepare_selection_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='raw-prepare-selection'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); assert sha(ORIGINAL)==EXPECTED
  dump=ROOT/'DUMPS/MainCode.dmp';data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  sim=LAB/'install/bin/arc-elf32-run';assert sha(sim)==json.loads(BUILD.read_text())['experimental_sha256']
  r.experimental_engine=LAB;r.input_hashes[str(sim)]=sha(sim);r.input_hashes[str(BUILD)]=sha(BUILD)
  spans=[(0x1baa28,0x1baa80),(0x17d62c,0x17d680),(0x28d48c,0x28d494),(0x14a2d8,0x14a2e0)]
  for a,b in spans:
   block,off=locate(a,b-a);assert raw(a,b-a)==data[block['offset']+off:block['offset']+off+b-a]
  (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in spans))
  images={i:bytearray(PS[i]) for i in range(6)};maps=[];patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm);p=out/(name+'.bin');v=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert v.returncode==0,v.stdout
   data=p.read_bytes();p.write_bytes(data+bytes(8+(-len(data))%8));return p
  def mapping(p,addr):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{addr:#x},{p.stat().st_size}']
  fixtures=[('fallback',0x17d458,''' mov r10,0x2200000
 mov r11,1
 st r11,[r10]
 st r0,[r10,8]
 st r1,[r10,12]
 st r2,[r10,16]
 mov r0,0
 j_s [blink]
'''),('special_input',0xdf47c,''' mov r10,0x2200000
 mov r11,1
 st r11,[r10,4]
 mov r11,0x12345678
 st r11,[r0,4]
 mov r11,0xabcd
 sth r11,[r0,38]
 mov r0,0
 j_s [blink]
'''),('stop',0x1baa80,' j [r26]\n')]
  for i,(name,addr,asm) in enumerate(fixtures):
   target=0x2030000+i*0x400;p=binary('fixture_'+name,asm);maps+=mapping(p,target)
   entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   block,off=locate(addr,8);image=images[block['index']];before=bytes(image[off:off+8]);assert before==raw(addr,8)
   image[off:off+8]=entry;patches.append(dict(name=name,address=hex(addr),original=before.hex(),fixture=entry.hex()))
  tests=[('off_mode3',0,3,0),('on_mode3',1,3,1),('on_mode0',1,0,0),('flag2_mode3',2,3,0)]
  asm=''
  for i,(name,flag,mode,special) in enumerate(tests):
   addr=0x2001000+128*i
   asm+=f''' mov r20,{addr:#x}
 mov r1,0x2200000
 mov r0,0
 st r0,[r1]
 st r0,[r1,4]
 mov r1,0x36c26e
 mov r0,{flag}
 stb r0,[r1]
 mov r1,0x366f90
 mov r0,{mode}
 st r0,[r1]
 st sp,[r20]
 sub sp,sp,1024
 add fp,sp,800
 mov r0,0x11223344
 st r0,[fp,-36]
 mov r0,0x55667788
 st r0,[fp,-32]
 mov r26,after_{i}
 mov r12,0x1baa28
 j [r12]
 after_{i}:
 mov r1,0x2200000
 ld r0,[r1]
 st r0,[r20,4]
 ld r0,[r1,4]
 st r0,[r20,8]
 sub r1,fp,680
 ld r0,[r1]
 st r0,[r20,12]
 add r1,r1,588
 ldb r0,[r1]
 st r0,[r20,16]
 ldh r0,[r1,2]
 st r0,[r20,20]
 ld sp,[r20]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(image);maps+=mapping(p,BS[i]['load_address_candidate'])
  resultfile=out/'results.bin';resultfile.write_bytes(bytes(len(tests)*128));maps+=mapping(resultfile,0x2001000)
  service=out/'service.bin';service.write_bytes(bytes(32));maps+=mapping(service,0x2200000)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  vals=resultfile.read_bytes();rows=[]
  for i,(name,flag,mode,special) in enumerate(tests):
   w=struct.unpack_from('<6I',vals,128*i)
   assert (w[1],w[2])==(1-special,special),(name,w)
   if special:assert (w[3],w[4],w[5])==(0x3000,0x78,0xabcd),(name,w)
   rows.append(dict(name=name,flag=flag,mode=mode,special_helper_calls=w[2],fallback_fixture_calls=w[1],special_word=hex(w[3]) if special else None))
  trace=(out/'cases.trace').read_text()
  for a in ('0x1baa28','0x17d62c','0x17d64c','0x17d66c','0x1baa80'):
   assert any(x.startswith(a+' ') for x in trace.splitlines()),a
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_RAW_PREPARATION_SELECTION_CPU',scenarios=rows,assumptions=['Original 1BAA28 fragment and 17D62C; fallback and DF47C are synthetic fixtures; fragment stopped before continuation.', 'Flag, mode, frame, inputs synthetic; DSP experimental.'],limits=['No complete callback, sensor, physical frame, file I/O, JPEG or hardware.', 'Special helper fields do not prove buffer allocation, bit depth, physical capture or compatibility with 2N writer.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',out,flush=True)

if __name__=='__main__':main()
