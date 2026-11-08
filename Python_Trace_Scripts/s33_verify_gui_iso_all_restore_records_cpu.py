#!/usr/bin/env python3
"""Chain original ISO/time confirmation and conditional restore with synthetic controls."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm


def main():
 out = ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('iso_all_restore_records_cpu_%Y%m%dT%H%M%SZ')
 r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-iso-time-confirm-restore'))
 print('Prove:', out, flush=True)
 try:
  r.prepare(); dump=ROOT/'DUMPS/MainCode.dmp'; data=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  spans=[(0xca654,0xac),(0xd03d8,8),(0xd0400,8),(0x17c320,0xd0),(0x17c49c,0x90),(0xde7b4,0x1c), (0x7d25b0,0x40),(0x6410f4,0x34),(0xd03b8,0x1c),(0xde78c,0x40),(0x989da4,480),(0x7d2394,0x30),(0xd03e0,0x28)]
  for addr,size in spans:
   b,o=locate(addr,size); assert raw(addr,size)==data[b['offset']+o:b['offset']+o+size],hex(addr)
  for pos,value in [(0,0xffffffff),(1,0),(7,6)]: assert u32(0x989da4+20*pos+12)==value
  assert [u32(0x989da4+20*pos+12) for pos in range(24)] == [0xffffffff, *range(23)]
  (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in [(0xca654,0xca6f6),(0x7d25b0,0x7d25f0),(0x7d2394,0x7d23c4)]))
  images={i:bytearray(PS[i]) for i in (0,1,2,4,5)}; maps=[]; patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm); p=out/(name+'.bin'); result=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]); assert result.returncode==0,result.stdout
   content=p.read_bytes(); p.write_bytes(content+bytes(8+(-len(content))%8)); return p
  def mapping(p,addr): return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{addr:#x},{p.stat().st_size}']
  noop=binary('other_setter_fixture',' mov r0,0\n j_s [blink]\n'); maps+=mapping(noop,0x2030000)
  get=binary('control_fixture',' mov r0,0x2200000\n j_s [blink]\n'); maps+=mapping(get,0x2030400)
  opening=binary('open_fixture',' mov r10,0x2000000\n ld r10,[r10]\n ld r11,[r10,48]\n add r11,r11,1\n st r11,[r10,48]\n st r0,[r10,52]\n st r1,[r10,56]\n mov r0,0\n j_s [blink]\n'); maps+=mapping(opening,0x2030800)
  groups=[(0x2030000,(0xde23c,0xde3a4,0xde664,0xdee04,0x17c5e4,0xde5f0,0xd0428,0x17c448,0x17e468,0x17e124,0xdeb78,0xdebcc,0xdebf0,0x17e36c)),(0x2030400,(0x145790,)),(0x2030800,(0x1453e4,))]
  for dst,addresses in groups:
   entry=binary('entry_'+hex(dst),f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
   for addr in addresses:
    b,o=locate(addr,8); before=bytes(images[b['index']][o:o+8]); assert before==raw(addr,8)
    images[b['index']][o:o+8]=entry; patches.append(dict(address=hex(addr),original=before.hex(),fixture=entry.hex()))
  tests=[(pos,record_iso) for pos in range(24) for record_iso in (0,6,19)]
  state=bytearray(len(tests)*96); records=bytearray(len(tests)*64); asm=' mov r20,0x2000000\n'
  for i,(pos,record_iso) in enumerate(tests):
   t=42
   s=0x2001000+i*96; c=0x2100000+i*64
   struct.pack_into('<H',records,i*64+8,record_iso); records[i*64+12]=1; struct.pack_into('<I',records,i*64+24,90000)
   asm+=f''' mov r21,{s:#x}
 st r21,[r20]
 st sp,[r21,60]
 mov r1,0x2200026
 mov r0,{pos}
 stb r0,[r1]
 mov r1,0x365787
 mov r0,19
 stb r0,[r1]
 mov r1,0x367bc8
 stb r0,[r1]
 mov r1,0x37fbf2
 mov r0,1600
 sth r0,[r1]
 mov r0,0
 mov r1,0x4801
 mov r2,0
 mov r12,0x7d25b0
 jl [r12]
 mov r1,0x365787
 ldb r0,[r1]
 st r0,[r21]
 mov r1,0x37fbf2
 ldh r0,[r1]
 st r0,[r21,4]
 mov r1,0x899ad0
 mov r0,{t}
 st r0,[r1]
 mov r0,0
 mov r1,0x580
 mov r2,0
 mov r12,0x7d2394
 jl [r12]
 mov r1,0x365788
 ld r0,[r1]
 st r0,[r21,8]
 mov r1,0x37fbf4
 ld r0,[r1]
 st r0,[r21,12]
 mov r0,{c:#x}
 mov r12,0xca654
 jl [r12]
 mov r1,{c+8:#x}
 ldh r0,[r1]
 st r0,[r21,16]
 mov r1,{c+24:#x}
 ld r0,[r1]
 st r0,[r21,20]
 mov r1,0x37fbf2
 ldh r0,[r1]
 st r0,[r21,24]
 mov r1,0x37fbf4
 ld r0,[r1]
 st r0,[r21,28]
 mov r1,0x365787
 ldb r0,[r1]
 st r0,[r21,32]
 mov r1,0x365788
 ld r0,[r1]
 st r0,[r21,36]
 st sp,[r21,64]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,img in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin'; p.write_bytes(img); maps+=mapping(p,BS[i]['load_address_candidate'])
  statefile=out/'cases.bin'; statefile.write_bytes(state); maps+=mapping(statefile,0x2001000)
  p=out/'records.bin'; p.write_bytes(records); maps+=mapping(p,0x2100000)
  p=out/'current.bin'; p.write_bytes(bytes(8)); maps+=mapping(p,0x2000000)
  control=bytearray(256);control[37]=24;struct.pack_into('<I',control,64,0x989da4)
  p=out/'control.bin';p.write_bytes(control);maps+=mapping(p,0x2200000)
  elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True); assert case['exit_code']==0 and case['fault'] is None,log
  got=statefile.read_bytes();rows=[]
  values=[0,50,64,80,100,120,125,140,160,200,250,280,320,400,500,640,800,1000,1250,1600,2000,2500,3200]
  for i,(pos,record_iso) in enumerate(tests):
   w=struct.unpack_from('<17I',got,i*96)
   diagnostic=19 if pos==0 else pos-1
   confirmed=values[diagnostic]
   restored_index=diagnostic if diagnostic else record_iso
   assert tuple(w[:10])==(diagnostic,confirmed,42000,42000,restored_index,42000,values[restored_index],42000,diagnostic,42000),(pos,record_iso,w)
   assert (w[12],w[13],w[14])==(2,0x36,0) and w[15]==w[16],(pos,record_iso,w)
   rows.append(dict(selection_position=pos,selection='Exit' if pos==0 else ('Auto' if pos==1 else str(values[pos-1])),initial_record_index=record_iso,diagnostic_index=diagnostic,confirmed_iso=confirmed,record_index_after=restored_index,restored_iso=w[6],time=42000,stack_preserved=True))
  trace=(out/'cases.trace').read_text()
  for addr in ('0x7d25b0','0x6410f4','0x7d2394','0x0ca654','0x17c320','0x0de7b4'): assert any(line.startswith(addr+' ') for line in trace.splitlines()),addr
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n'); (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n'); (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_ISO_ALL_RESTORE_RECORDS_SYNTHETIC',scenarios=rows,assumptions=['Original ISO/time confirmation callbacks and CA654 called directly in an imposed order; original ISO list and synthetic control/record.', 'Fourteen unrelated setters, control lookup and GUI opening are fixtures.'],limits=['No manager lifecycle, physical buttons, exposure units, AE scheduling, sensor, photography, persistence or physical RAM mapping.','Zero semantics are limited to the tested CA654 branch.'])
  r.finish()
 except Exception as e: r.results.update(status='FAIL',error=repr(e)); raise
 finally: r.save()
 print('PASS:',len(tests),'ISO/record confirm-restore cases;',out,flush=True)
if __name__=='__main__': main()
