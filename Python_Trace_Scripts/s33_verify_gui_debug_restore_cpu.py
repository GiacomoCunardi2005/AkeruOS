#!/usr/bin/env python3
"""Test the original conditional ISO/time restore on synthetic records."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, disasm


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('debug_restore_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-debug-conditional-restore'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); dump=ROOT/'DUMPS/MainCode.dmp'; data=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  for addr,size in [(0xca654,0xac),(0xd03d8,8),(0xd0400,8),(0x17c320,0xd0),(0x17c49c,0x90),(0xde7b4,0x1c)]:
   b,o=locate(addr,size); assert raw(addr,size)==data[b['offset']+o:b['offset']+o+size]
  (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in [(0xca654,0xca6f6),(0xd03d8,0xd03e0),(0xd0400,0xd0408)]))
  images={i:bytearray(PS[i]) for i in (0,1,4,5)}; maps=[]; patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm); path=out/(name+'.bin'); result=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path]); assert result.returncode==0,result.stdout
   content=path.read_bytes(); path.write_bytes(content+bytes(8+(-len(content))%8)); return path
  def mapping(path,addr):return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']
  stub=binary('other_setter_fixture',' mov r0,0\n j_s [blink]\n');maps+=mapping(stub,0x2030000)
  entry=binary('entry_other_setter',' mov_s r12,0x2030000\n j_s [r12]\n').read_bytes()[:8]
  # Other settings are not under test; every substituted entry is recorded.
  for addr in (0xde23c,0xde3a4,0xde664,0xdee04,0x17c5e4,0xde5f0,0xd0428,0x17c448,0x17e468,0x17e124,0xdeb78,0xdebcc,0xdebf0,0x17e36c):
   b,o=locate(addr,8);before=bytes(images[b['index']][o:o+8]);assert before==raw(addr,8)
   images[b['index']][o:o+8]=entry;patches.append(dict(address=hex(addr),original=before.hex(),fixture=entry.hex()))
  tests=[(0,0),(0,42000),(6,0),(6,42000)]
  state=bytearray(len(tests)*96);records=bytearray(len(tests)*64);asm=' mov r20,0x2000000\n'
  for i,(iso,time) in enumerate(tests):
   s=0x2001000+i*96;c=0x2100000+i*64
   struct.pack_into('<H',records,i*64+8,19);records[i*64+12]=1;struct.pack_into('<I',records,i*64+24,90000)
   asm+=f''' mov r21,{s:#x}
 mov r1,0x365787
 mov r0,{iso}
 stb r0,[r1]
 mov r1,0x365788
 mov r0,{time}
 st r0,[r1]
 st sp,[r21,24]
 mov r0,{c:#x}
 mov r12,0xca654
 jl [r12]
 mov r1,{c+8:#x}
 ldh r0,[r1]
 st r0,[r21]
 mov r1,{c+24:#x}
 ld r0,[r1]
 st r0,[r21,4]
 mov r1,0x37fbf2
 ldh r0,[r1]
 st r0,[r21,8]
 mov r1,0x37fbf4
 ld r0,[r1]
 st r0,[r21,12]
 st sp,[r21,28]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,img in images.items():
   path=out/f'block{i}_LAB_FIXTURE.bin';path.write_bytes(img);maps+=mapping(path,BS[i]['load_address_candidate'])
  statefile=out/'cases.bin';statefile.write_bytes(state);maps+=mapping(statefile,0x2001000)
  path=out/'records.bin';path.write_bytes(records);maps+=mapping(path,0x2100000)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  rows=[]
  for i,(iso,time) in enumerate(tests):
   w=struct.unpack_from('<8I',statefile.read_bytes(),i*96);expected=(iso or 19,time or 90000,125 if iso else 1600,time or 90000)
   assert tuple(w[:4])==expected and w[6]==w[7],(i,w,expected)
   rows.append(dict(debug_iso=iso,debug_time=time,record_iso=w[0],record_time=w[1],iso_field=w[2],time_field=w[3],stack_preserved=True))
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_DEBUG_CONDITIONAL_RESTORE_SYNTHETIC',scenarios=rows,
   assumptions=['Original CA654, debug getters, ISO conversion and time setters; synthetic records and values.', 'Fourteen unrelated services replaced by no-op fixtures.'],
   limits=['Calls forced directly; no scheduling, runtime concurrency, actual records, sensor, GUI or persistence.', 'Zero handling is limited to these synthetic tests; no physical interpretation.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: four conditional restore cases;',out,flush=True)
if __name__=='__main__':main()
