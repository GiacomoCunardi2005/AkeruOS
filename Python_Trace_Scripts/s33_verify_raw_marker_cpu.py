#!/usr/bin/env python3
"""Execute V1.1 RAW marker on bounded synthetic buffers using provisional DSP."""
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import json,struct,sys,hashlib
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import BUILD,LAB,compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,locate,disasm

def digest(data):return hashlib.sha256(data).hexdigest()
def main():
 out=ROOT/'Risultati/HiddenMenu_RAW'/datetime.now(timezone.utc).strftime('marker_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='raw-marker-original-bounded'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['experimental_sha256']
  r.experimental_engine=LAB;r.input_hashes[str(LAB/'install/bin/arc-elf32-run')]=build['experimental_sha256'];r.input_hashes[str(BUILD)]=sha(BUILD)
  dump_path=ROOT/'DUMPS/MainCode.dmp';dump=dump_path.read_bytes();r.input_hashes[str(dump_path)]=sha(dump_path)
  spans=[(0x28d5bc,0xb0),(0x35231c,32),(0x128c20,0x110),(0x334120,0x18),(0x33417c,0x80)]
  for a,n in spans:
   b,o=locate(a,n);assert raw(a,n)==dump[b['offset']+o:b['offset']+o+n]
  (out/'gnu_windows.txt').write_text(disasm(0x28d5bc,0x28d668))
  bits=list(raw(0x35231c,32));assert len(bits)==32 and all(x in (0,1) for x in bits)
  def mapped(name,data,address):
   p=out/name;p.write_bytes(data);return ['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}']
  block=out/'block0.bin';opts=mapped(block.name,PS[0],BS[0]['load_address_candidate'])
  state=out/'state.bin';opts+=mapped(state.name,bytes(32),0x4000000)
  width,height=4208,3152;base_offset=16;offsets=[base_offset+width*height+i*2*width for i in range(32)]
  length=offsets[-1]+64
  buffer=out/'buffer.bin';opts+=mapped(buffer.name,bytes(length),0x2000000)
  scenarios=[('inverse',2),('matching',2),('zero',2),('unsupported_selector',3)]
  results=[]
  for pattern,selector in scenarios:
   initial=bytearray([0xa4])*length
   for i,off in enumerate(offsets):initial[off]=0 if pattern=='zero' else (0xa4 | (bits[i]^int(pattern=='inverse')))
   expected=bytearray(initial)
   if selector==2:
    for i,off in enumerate(offsets):expected[off]=(expected[off]&0xfe)|bits[i]
   buffer.write_bytes(initial);state.write_bytes(bytes(32))
   asm=f''' mov r20,0x4000000
 st sp,[r20,4]
 mov r0,0x2000000
 mov r1,{base_offset}
 mov r2,{width}
 mov r3,{height}
 mov r4,{selector}
 mov r12,0x28d5bc
 jl [r12]
 mov r20,0x4000000
 st r0,[r20]
 st sp,[r20,8]
 mov r0,0
 mov r8,1
 trap_s 1
'''
   elf=compile_probe(r,'case_'+pattern,asm)
   case,log=r.run('case_'+pattern,'/result/'+elf.name,opts,trace=True)
   assert case['exit_code']==0 and case['fault'] is None,log
   assert 'S33_DSP_GUARD' not in log
   if selector==2:
    assert log.count('S33_DSP_LAB pc=0028d62c word=2e0d147e left=00000c50 right=00001070 r56=00000000 r57=00ca6300 provisional=1')==1,log
   else:assert 'S33_DSP_LAB pc=0028d62c' not in log
   got=buffer.read_bytes();assert got==expected,pattern
   ret,before,after=struct.unpack_from('<III',state.read_bytes());assert before==after and ret==(0 if selector==2 else 1)
   changed=[i for i,(a,b) in enumerate(zip(initial,got)) if a!=b]
   assert all(x in offsets for x in changed)
   results.append(dict(pattern=pattern,selector=selector,return_value=ret,changed_count=len(changed),changed_offsets=changed,
     input_sha256=digest(initial),output_sha256=digest(got),stack_preserved=True,entire_mapped_buffer_compared=True))
  assert [x['changed_count'] for x in results]==[32,0,sum(bits),0]
  assert block.read_bytes()==PS[0]
  (out/'cases.json').write_text(json.dumps({'width':width,'height':height,'base_offset':base_offset,'buffer_size':length,'target_bits':bits,'target_offsets':offsets,'cases':results},indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_RAW_MARKER_PROVISIONAL_DSP',scenarios=results,
   assumptions=['Calls marker and copy/prologue/epilogue original code directly, synthetic buffer and stack.', 'Experimental GNU DSP v7 models MULUDW provisionally; no camera calibration.'],
   limits=['No caller, flag, physical camera, sensor frame, storage, CFA or pixel layout.', 'Whole output checked but read bounds not independently monitored.', 'No runtime reachability, concurrency or physical buffer size established.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: four bounded RAW marker scenarios with provisional DSP;',out,flush=True)
if __name__=='__main__':main()
