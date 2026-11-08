#!/usr/bin/env python3
"""Run nominal FE6 controls, mode1 arrays, and signed out-of-domain probes."""
import json,re,struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha,IMAGE
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_remaining_direct_mmio import ObservedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_verify_register_memory_observer import LIBS,SYMBOLS
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
NOMINAL=[0,1,2,4]
SETTERS={0x2c694c:(1,[0x2c6964,0x2c696c,0x2c6974,0x2c697c],[0x2c699c,0x2c69a4,0x2c69ac,0x2c69b4]),0x2c69bc:(2,[0x2c69d4,0x2c69dc,0x2c69e4,0x2c69ec],[0x2c6a0c,0x2c6a14,0x2c6a1c,0x2c6a24]),0x2c6a5c:(3,[0x2c6a74,0x2c6a7c,0x2c6a84,0x2c6a8c],[0x2c6aac,0x2c6ab4,0x2c6abc,0x2c6ac4])}
ARRAYS=[(0x2c6c98,24,0xfe60100,0x2c6cc4,0x2c6cdc,0x05500100),(0x2c6ce8,12,0xfe64000,0x2c6d14,0x2c6d2c,0x05500101)]
WINDOWS=[(0x2c694c,0x2c6b74),(0x2c6c98,0x2c6d38),(0x1f0a6c,0x1f0a90)]
def ctrl(s):return 0xfe646c0 if s==4 else(0xfe64600+((s<<5)&0xffffffff))&0xffffffff

def main():
 r=ObservedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='fe6-controls-mode1-signed-boundary'))
 print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB
  sources=[Path(__file__),Path(__file__).with_name('s33_verify_remaining_direct_mmio.py'),Path(__file__).with_name('s33_register_profile_observer.c'),Path(__file__).with_name('s33_register_memory_observer.c')]
  for p in sources+[BUILD,LAB/'install/bin/arc-elf32-run']+[LAB/'build-gnu89'/x for x in LIBS]:r.input_hashes[str(p)]=sha(p)
  for p in sources:(r.out/p.name).write_bytes(p.read_bytes())
  incs=['build-gnu89/sim/arc','build-gnu89/bfd','source/gnu-arc700-sim-src/include','source/gnu-arc700-sim-src/sim/arc','source/gnu-arc700-sim-src/sim/common','source/gnu-arc700-sim-src/opcodes']
  cmd=['podman','run','--rm','--network','none','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','-v',str(LAB)+':/work:ro','-v',str(sources[0].parent)+':/frontend:ro','-v',str(r.out)+':/newout:rw',IMAGE,'gcc','-std=gnu11','-fgnu89-inline','-O2','-g','-fsanitize=bounds','-fno-sanitize-recover=all']
  for p in incs:cmd+=['-I','/work/'+p]
  cmd+=['/frontend/s33_register_profile_observer.c','-Wl,--start-group']+['/work/build-gnu89/'+p for p in LIBS]+['-Wl,--end-group']+['-Wl,--wrap='+s for s in SYMBOLS]+['-lnsl','-lm','-o','/newout/observer']
  q=r.command('build_observer',cmd,timeout=90);assert q.returncode==0,q.stdout[-2000:]
  blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate'];main=r.out/'payload0_mmap.bin';main.write_bytes(body);r.input_hashes[str(directory/info['file'])]=sha(directory/info['file'])
  (r.out/'original_windows.txt').write_text('\n\n'.join(aligned_window(body,base,a,b)for a,b in WINDOWS))
  cells=sorted({ctrl(s)+off for s in NOMINAL for off in[0,4,8]}|{b+4*s for _,n,b,*_ in ARRAYS for s in range(n)});assert len(cells)==48;pairs=[]
  scenarios=[('domain_zero',0,1),('domain_ones',65535,1),('rejected_nonnegative',0xa55a,1),('mode_gate2',0xa55a,2),('signed_aliases',0,1),('fault_ffffffff',0,1),('fault_80000004',0,1)]
  for scenario,seed,mode in scenarios:
   expected={a:seed for a in cells};sequence=[];calls=[];fault=scenario.startswith('fault_');asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
   def call(entry,args,events,ret=None,outbyte=None):
    nonlocal asm
    asm+=''.join(f'mov r{i},{v&0xffffffff:#x}\n'for i,v in enumerate(args))+f'mov r12,{entry:#x}\njl [r12]\n'
    if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
    if outbyte is not None:asm+=f'mov r11,0x700000\nldb r10,[r11]\ncmp r10,{outbyte}\nbne fail\n'
    asm+='cmp sp,r20\nbne fail\ncmp r13,0x13371337\nbne fail\ncmp r14,0x14471447\nbne fail\ncmp r15,0x15571557\nbne fail\ncmp r16,0x16671667\nbne fail\n';calls.append(dict(entry=hex(entry),arguments=list(map(hex,args)),expected_events=events,expected_return=ret,expected_output_byte=outbyte));sequence.extend(events)
   if scenario.startswith('domain_')or scenario=='rejected_nonnegative':
    selectors=NOMINAL if scenario.startswith('domain_')else[3,5,0x7fffffff]
    for s in selectors:
     valid=s in NOMINAL;a=ctrl(s)
     for entry,(bit,normal,special)in SETTERS.items():
      pcs=special if s==4 else normal
      for flag in[1,0]:
       v=None if not valid else(expected[a]|(1<<bit)if flag else expected[a]&~(1<<bit));ev=[]if not valid else[(pcs[0 if flag else 2],'read',a,expected[a]),(pcs[1 if flag else 3],'write',a,v)]
       call(entry,[s,flag],ev)
       if valid:expected[a]=v
     for one,four in[(7,3),(0,0)]:
      v=None if not valid else(expected[a]&~0x11)|((one&1)|((four&1)<<4));ev=[]if not valid else[(0x2c6b54 if s==4 else 0x2c6b2c,'read',a,expected[a]),(0x2c6b6a,'write',a,v)]
      call(0x2c6b0c,[s,one,four],ev)
      if valid:expected[a]=v
     call(0x2c6a2c,[s],[]if not valid else[(0x2c6a50,'read',a+8,expected[a+8])],expected[a+8]&0x10 if valid else 0)
     call(0x2c6acc,[s,0x700000],[]if not valid else[(0x2c6af4,'read',a+4,expected[a+4])],expected[a+4]&0x7fff if valid else 0,(expected[a+4]>>15)&1 if valid else 0)
    for entry,n,b,read,write,error in ARRAYS:
     for s in(range(n)if scenario.startswith('domain_')else[n,0xffffffff]):
      for val in([3,0,1,2]if scenario.startswith('domain_')else[1]):
       a=b+4*s;valid=s<n;v=None if not valid else(expected[a]&~0x3000)|((val&3)<<12);call(entry,[s,val],[]if not valid else[(read,'read',a,expected[a]),(write,'write',a,v)],0 if valid else error)
       if valid:expected[a]=v
   elif scenario=='mode_gate2':
    for entry,n,b,read,write,error in ARRAYS:call(entry,[0,3],[],0)
   elif scenario=='signed_aliases':
    for s in[0x80000000,0x80000001]:
     a=ctrl(s)
     for flag in[1,0]:
      v=expected[a]|2 if flag else expected[a]&~2;call(0x2c694c,[s,flag],[(0x2c6964 if flag else 0x2c6974,'read',a,expected[a]),(0x2c696c if flag else 0x2c697c,'write',a,v)]);expected[a]=v
   else:
    s=0xffffffff if scenario=='fault_ffffffff'else 0x80000004;call(0x2c694c,[s,1],[])
   asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
    for a in cells:
     data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,a%8,seed);f=r.out/f'{name}_{a:x}.bin';f.write_bytes(data);fixtures[hex(a)]=dict(file=f.name,before=data.hex(),kind='modeled_mmio');options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},2']
    cache=bytearray(12);cache[4]=1;struct.pack_into('<I',cache,8,mode<<16)
    for a,data,size in[(0x423f00,cache,12),(0x700000,bytearray(b'\xa5'*8),1)]:
     f=r.out/f'{name}_ram_{a:x}.bin';f.write_bytes(data);fixtures[hex(a)]=dict(file=f.name,before=data.hex(),kind='synthetic_ram');options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},{size:#x}']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x},0x423f00:12,0x700000:1';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
    assert case['exit_code']==(11 if fault else 0),log[-4000:];assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
    if fault:assert case['fault']==dict(size=2,operation='read',address=hex(ctrl(s)),pc='0x2c6964'),case
    else:assert case['fault']is None
    ev=[json.loads(x)for x in re.findall(r'S33_MEM (\{[^\n]+)',log)];done=[e for e in ev if e['stage']=='result'];begins=[e for e in ev if e['stage']=='begin'];attempts=[e for e in begins if e['id']not in{e['id']for e in done}]
    assert all(e['width_bytes']==2 for e in ev);assert [(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(sequence if enabled else[])
    assert len(attempts)==int(fault and enabled)
    if attempts:assert attempts[0]['address']==ctrl(s)and attempts[0]['pc']==0x2c6964
    for key,f in fixtures.items():
     after=(r.out/f['file']).read_bytes();f['after']=after.hex();before=bytes.fromhex(f['before']);a=int(key,0)
     if f['kind']=='modeled_mmio':
      assert struct.unpack_from('<H',after,a%8)[0]==expected[a];assert all(after[j]==before[j]for j in range(8)if j not in[a%8,a%8+1])
     elif a==0x423f00:assert after==before
     else:
      outcalls=[c for c in calls if c['expected_output_byte']is not None];want=outcalls[-1]['expected_output_byte']if outcalls else 0xa5;assert after[0]==want and after[1:]==before[1:]
    assert main.read_bytes()==body;case.update(scenario=scenario,observer_enabled=enabled,mode_fixture=mode,fixtures=fixtures,original_calls=calls,completed_memory_events=done,attempts_without_result=attempts,expected_sequence=sequence,full_selected_paths_completed=not fault,scope_kind='out_of_domain_fault'if fault else'out_of_domain_alias'if scenario=='signed_aliases'else'nominal_or_rejected');traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(done),'events',len(attempts),'attempts',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,trace_identical=True,events=len(sequence),expected_fault=fault,original_calls=len(calls)))
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();off=fw.find(body);assert off>=0 and fw.find(body,off+1)<0
  r.results.update(status='PASS_FE6_CONTROLS_MODE1_AND_SIGNED_BOUNDARY',pairs=pairs,windows=WINDOWS,nominal_control_selectors=NOMINAL,nominal_addresses=list(map(hex,cells)),excluded_out_of_domain_attempt_addresses=['0xfe645e0','0xfe64680'],payload=dict(base=base,size=len(body),firmware_offset=off,sha256=sha(main),path=str(main)),hardware_access=False,gnu_modified=False,limits=['Nominal controls0/1/2/4 and two unsigned-bounded mode1 arrays are separate from signed negative probes.','Negative addresses from incomplete software bounds are not promoted to ordinary or physical registers. Unmapped fault is a model boundary, not a camera fault.','Mode cache ready1/mode1 or2, MMIO seeds and output RAM are explicit fixtures, not physical reset/configuration or free RAM.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
