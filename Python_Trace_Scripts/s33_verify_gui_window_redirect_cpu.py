#!/usr/bin/env python3
"""Exercise the original V1.1 WindowManager redirect interpreter offline."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm

def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('window_redirect_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-window-redirect'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); dump=ROOT/'DUMPS/MainCode.dmp'; d=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x14503c,14),(0x14507c,28),(0x14510c,68),(0x145350,4),(0x33412c,8),(0x334194,8)]:
   b,o=locate(a,n); assert raw(a,n)==d[b['offset']+o:b['offset']+o+n],hex(a)
  assert u32(0x145350)==0x366e94
  (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in [(0x14503c,0x14504a),(0x14507c,0x145098),(0x14510c,0x145150)]))
  # Return word, previous descriptor, descriptor flags, table enabled, expected status/destination/argument.
  cases=[('fallback_null',0xffffffff,0,0,1,0,0,0x76543210),
   ('fallback_previous',0xffffffff,0x2101000,0,1,0,0x2101000,0),
   ('fallback_blocked_bit9',0xffffffff,0x2101000,0x200,1,0,0,0x76543210),
   ('lookup_id1_positive_arg',0x12340001,0,0,1,0,0x2102000,0x1234),
   ('lookup_id1_negative_arg',0xfffe0001,0,0,1,0,0x2102000,0xfffffffe),
   ('lookup_negative_id',0x0001ffff,0,0,1,1,0,1),
   ('lookup_out_of_range',0x00010003,0,0,1,1,0,1),
   ('lookup_null_entry',0x00020002,0,0,1,1,0,2),
   ('lookup_absent_table',0x00030001,0,0,0,1,0,3)]
  maps=[]
  def mapping(p,a,n): return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  for i in (0,1,4,5):
   p=out/f'block{i}_original.bin';p.write_bytes(PS[i]);maps+=mapping(p,BS[i]['load_address_candidate'],len(PS[i]))
  state=out/'cases.bin';state.write_bytes(bytes(len(cases)*32));maps+=mapping(state,0x2001000,len(cases)*32)
  table=out/'table.bin'; table.write_bytes(struct.pack('<III',0,0x2102000,0));maps+=mapping(table,0x2100000,12)
  desc=out/'descriptors.bin';desc.write_bytes(bytes(0x1100));maps+=mapping(desc,0x2101000,0x1100)
  asm=''
  for i,(name,ret,prev,flags,enabled,*_) in enumerate(cases):
   s=0x2001000+i*32
   asm+=f''' mov r21,{s:#x}
 mov r0,{flags:#x}
 mov r1,0x2101000
 st r0,[r1]
 mov r0,{0x2100000 if enabled else 0:#x}
 mov r1,0x366e9c
 st r0,[r1]
 mov r0,3
 mov r1,0x366ea0
 sth r0,[r1]
 mov r0,0x11111111
 st r0,[r21,4]
 mov r0,0x76543210
 st r0,[r21,8]
 st sp,[r21,12]
 mov r0,{ret:#x}
 mov r1,{prev:#x}
 add r2,r21,4
 add r3,r21,8
 mov r12,0x14510c
 jl [r12]
 st r0,[r21]
 st sp,[r21,16]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert case['exit_code']==0 and case['fault'] is None,log
  data=state.read_bytes();rows=[]
  for i,(name,ret,prev,flags,enabled,status,dest,arg) in enumerate(cases):
   w=struct.unpack_from('<5I',data,i*32)
   assert w[:3]==(status,dest,arg),(name,w,(status,dest,arg))
   assert w[3]==w[4],(name,w)
   rows.append(dict(case=name,response=hex(ret),previous=hex(prev),flags=hex(flags),table_enabled=bool(enabled),result=status,destination=hex(dest),argument=hex(arg),stack_preserved=True))
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_WINDOW_REDIRECT_CPU',scenarios=rows,
   assumptions=['Original 14510c, 14503c, 14507c and save/restore instructions; manager table, descriptor flags, caller inputs and RAM synthetic.'],
   limits=['Direct calls to redirect interpreter; no real callback, event, transition, display, hardware or runtime order.',
    'Table entries are synthetic and cannot establish registration or identity of real objects.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',len(cases),'redirect cases;',out,flush=True)
if __name__=='__main__':main()
