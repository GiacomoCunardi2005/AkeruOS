#!/usr/bin/env python3
"""Keep unbounded-index MMIO expressions separate from nominal control registers."""
import json,re,struct,shutil,argparse
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_remaining_direct_mmio import ObservedRunner
from s33_verify_gnu_dsp_lab import compile_probe
REUSED=ROOT/'outputs/gnu_arc700/20261025T104108Z_2704fcf9'
CONTROL={0x2c6ba4:(1,[0x2c6bbc,0x2c6bc4,0x2c6bcc,0x2c6bd4]),0x2c6bdc:(2,[0x2c6bf4,0x2c6bfc,0x2c6c04,0x2c6c0c]),0x2c6c38:(0,[0x2c6c60,0x2c6c68,0x2c6c50,0x2c6c58])}
NOMINAL={0xfe648c0+256*s+off for s in[0,1,2]for off in[0,4]}

def family_address(entry,s,i):return(((0xfe64680 if s==0 else 0xfe646d0)if entry==0x2c6b74 else(0xfe648d0+((s<<8)&0xffffffff)))+((i<<2)&0xffffffff))&0xffffffff

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--census',type=Path,required=True);args=ap.parse_args();census=args.census.resolve();r=ObservedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='fe6-indexed-families-no-index-inflation'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB
  provenance=json.loads((REUSED/'verified_evidence.json').read_text());assert provenance['status']=='PASS_FE6_CONTROLS_MODE1_AND_SIGNED_BOUNDARY'and sha(REUSED/'observer')==provenance['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  from s33_trace_state_dispatch import verified_payloads
  from s33_verify_sensor_mmio_dialog import aligned_window
  for p in[Path(__file__),Path(__file__).with_name('s33_verify_remaining_direct_mmio.py'),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json',census]:r.input_hashes[str(p)]=sha(p)
  calls=json.loads(census.read_text());assert not calls['call_candidates']and not calls['pointer_candidates'];assert all(sha(Path(p))==h for p,h in calls['payload_sha256'].items());r.input_hashes.update(calls['payload_sha256']);shutil.copy2(census,r.out/'caller_census.json');shutil.copy2(Path(__file__),r.out/Path(__file__).name)
  blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate'];main=r.out/'payload0_mmap.bin';main.write_bytes(body)
  windows=[(0x2c6b74,0x2c6c98)];(r.out/'original_windows.txt').write_text(aligned_window(body,base,*windows[0]))
  examples={family_address(0x2c6b74,s,i)for s in[0,1,0xffffffff]for i in[0,1,0xffffffff,0x40000000]}|{family_address(0x2c6c70,s,i)for s in[0,1,2,0xffffffff]for i in[0,1,0xffffffff,0x40000000]};assert len(examples)==18 and not examples&NOMINAL
  scenarios=[('domain_zero',0),('domain_ones',65535),('structural_families',0xa55a),('rejected',0xa55a),('control_alias',0),('control_fault',0)];pairs=[]
  for scenario,seed in scenarios:
   expected={a:seed for a in NOMINAL|examples};sequence=[];original_calls=[];fault=scenario=='control_fault';asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
   def call(entry,args,ev,ret=None):
    nonlocal asm
    asm+=''.join(f'mov r{i},{v&0xffffffff:#x}\n'for i,v in enumerate(args))+f'mov r12,{entry:#x}\njl [r12]\n'
    if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
    asm+='cmp sp,r20\nbne fail\ncmp r13,0x13371337\nbne fail\ncmp r14,0x14471447\nbne fail\ncmp r15,0x15571557\nbne fail\ncmp r16,0x16671667\nbne fail\n';sequence.extend(ev);original_calls.append(dict(entry=hex(entry),arguments=list(map(hex,args)),expected_events=ev,expected_return=ret))
   if scenario in['domain_zero','domain_ones','rejected']:
    for s in([0,1,2]if scenario!='rejected'else[3,0x7fffffff]):
     valid=s in[0,1,2];a=0xfe648c0+256*s
     for entry,(bit,pcs)in CONTROL.items():
      for flag in[1,0,2]:
       setting=flag!=0 if bit==0 else flag==1;v=None if not valid else(expected[a]|(1<<bit)if setting else expected[a]&~(1<<bit));ev=[]if not valid else[(pcs[0 if setting else 2],'read',a,expected[a]),(pcs[1 if setting else 3],'write',a,v)];call(entry,[s,flag],ev)
       if valid:expected[a]=v
     call(0x2c6c14,[s],[]if not valid else[(0x2c6c2a,'read',a+4,expected[a+4])],0 if not valid else expected[a+4]&0x10)
   elif scenario=='structural_families':
    for entry,channels in[(0x2c6b74,[0,1,0xffffffff]),(0x2c6c70,[0,1,2,3,0xffffffff])]:
     for s in channels:
      for i in[0,1,0xffffffff,0x40000000]:
       for flag in[0,1,2]:
        active=entry==0x2c6b74 or s!=3;a=family_address(entry,s,i);v=(0 if flag==1 else 0x8000)|0xeef;call(entry,[s,i,flag,0xdeadbeef],[(0x2c6b9c if entry==0x2c6b74 else 0x2c6c90,'write',a,v)]if active else[])
        if active:expected[a]=v
   elif scenario=='control_alias':
    for s in[0x80000000,0x80000001]:
     a=(0xfe648c0+((s<<8)&0xffffffff))&0xffffffff
     for flag in[1,0,2]:
      v=expected[a]|2 if flag==1 else expected[a]&~2;call(0x2c6ba4,[s,flag],[(0x2c6bbc if flag==1 else 0x2c6bcc,'read',a,expected[a]),(0x2c6bc4 if flag==1 else 0x2c6bd4,'write',a,v)]);expected[a]=v
   else:call(0x2c6ba4,[0xffffffff,1],[])
   asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
    for a in sorted(NOMINAL|examples):
     data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,a%8,seed);f=r.out/f'{name}_{a:x}.bin';f.write_bytes(data);fixtures[hex(a)]=dict(file=f.name,before=data.hex(),scope='nominal_control'if a in NOMINAL else'structural_example_not_register_admission');options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},2']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==(11 if fault else 0),log[-4000:];assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
    if fault:assert case['fault']==dict(size=2,operation='read',address='0xfe647c0',pc='0x2c6bbc')
    else:assert case['fault']is None
    ev=[json.loads(x)for x in re.findall(r'S33_MEM (\{[^\n]+)',log)];done=[e for e in ev if e['stage']=='result'];attempts=[e for e in ev if e['stage']=='begin'and e['id']not in{x['id']for x in done}];assert all(e['width_bytes']==2 for e in ev)
    assert [(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(sequence if enabled else[]);assert len(attempts)==int(fault and enabled)
    for key,f in fixtures.items():
     a=int(key,0);after=(r.out/f['file']).read_bytes();f['after']=after.hex();before=bytes.fromhex(f['before']);assert struct.unpack_from('<H',after,a%8)[0]==expected[a];assert all(after[j]==before[j]for j in range(8)if j not in[a%8,a%8+1])
    assert main.read_bytes()==body;scope='structural_family_examples'if scenario=='structural_families'else'signed_alias'if scenario=='control_alias'else'incomplete_attempt'if fault else'nominal_control'
    case.update(scenario=scenario,scope_kind=scope,observer_enabled=enabled,fixtures=fixtures,original_calls=original_calls,completed_memory_events=done,attempts_without_result=attempts,full_selected_paths_completed=not fault);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(done),'events',len(attempts),'attempts',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,trace_identical=True,events=len(sequence),original_calls=len(original_calls),expected_fault=fault))
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0
  r.results.update(status='PASS_FE6_INDEXED_FAMILIES_SEPARATE_ADMISSION',pairs=pairs,windows=windows,nominal_control_addresses=list(map(hex,sorted(NOMINAL))),structural_example_addresses_not_admitted=list(map(hex,sorted(examples))),reused_observer=dict(source=str(REUSED/'observer'),sha256=sha(REUSED/'observer')),payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main),path=str(main)),hardware_access=False,gnu_modified=False,limits=['No BL or exact LE/ME pointer candidates to six target entries in16payloads; this does not exclude computed calls, tail branches or global reachability.','Unbounded r1 family examples are modeled transfers, not concrete register admissions; caller index domains remain unknown.','Control nominal nonnegative inputs0..2 are separate from signed aliases and unmapped attemptFE647C0.','No physical reset, ID, permissions, peripheral function, timing or RAM geometry inferred.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
