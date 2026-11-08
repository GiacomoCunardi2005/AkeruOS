#!/usr/bin/env python3
"""Execute the three remaining FF7 raw tables and tail stores with unchanged GNU."""
import json,struct,shutil,re,hashlib
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
REUSED=ROOT/'outputs/gnu_arc700/20261025T104108Z_2704fcf9'
SPECS=[dict(name='raw9_tail',window='raw9_tail',entry=0x2e10f0,end=0x2e1150,base=0xff760d0,count=9,kind='raw16',pc=0x2e1124,param_addresses=[0xff760f4,0xff760f8],param_pcs=[0x2e1138,0x2e1148],aux_pcs=[0x2e1104,0x2e110a]),dict(name='raw33_b',window='raw33_b',entry=0x2e1298,end=0x2e12d8,base=0xff76128,count=33,kind='raw16',pc=0x2e12c8,param_addresses=[],param_pcs=[],aux_pcs=[0x2e12a8,0x2e12ae]),dict(name='raw17_c',window='raw17_c',entry=0x2e12d8,end=0x2e1318,base=0xff761ac,count=17,kind='raw16',pc=0x2e1308,param_addresses=[],param_pcs=[],aux_pcs=[0x2e12e8,0x2e12ee])]

def make_input(spec,pattern):
 n=spec['count'];values=[(0 if pattern==0 else 65535 if pattern==1 else ((i*1237+0x3412)^(65535 if pattern==3 else 0))&65535)for i in range(n)]
 return struct.pack('<'+'H'*n,*values),values

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ff7-remaining-raw-writers'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB;pinned=json.loads((REUSED/'verified_evidence.json').read_text());assert sha(REUSED/'observer')==pinned['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),Path(__file__).with_name('s33_verify_ff7_transfer_windows.py'),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate'];main=r.out/'payload0_mmap.bin';main.write_bytes(body);r.input_hashes[str(directory/info['file'])]=sha(directory/info['file'])
  (r.out/'original_windows.txt').write_text('\n\n'.join(aligned_window(body,base,s['entry'],s['end'])for s in SPECS));pairs=[];outputs={}
  for spec in SPECS:
   patterns=[0,1,2,3]
   for pattern in patterns:
    scenario=spec['name']+'_'+str(pattern);raw,values=make_input(spec,pattern);p1,p2=(0x12345678,0x9abcdeff)if pattern!=2 else(0,0xabcdfc00);param_values=[p1&65535,p2&65535]if spec['param_addresses']else[]
    ret=p2 if spec['param_addresses']else spec['base']+4*(spec['count']-1)
    sequence=[(spec['pc'],'write',spec['base']+4*i,v)for i,v in enumerate(values)]+[(pc,'write',a,v)for pc,a,v in zip(spec['param_pcs'],spec['param_addresses'],param_values)];outputs[(spec['name'],pattern)]=sequence
    inp=r.out/(scenario+'_input.bin');inp.write_bytes(raw);asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\nmov r0,0x700000\n'+f'mov r1,{p1:#x}\nmov r2,{p2:#x}\nmov r12,{spec["entry"]:#x}\njl [r12]\ncmp r0,{ret:#x}\nbne fail\ncmp sp,r20\nbne fail\ncmp r13,0x13371337\nbne fail\ncmp r14,0x14471447\nbne fail\ncmp r15,0x15571557\nbne fail\ncmp r16,0x16671667\nbne fail\nmov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
    for enabled in[False,True]:
     name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;table=r.out/(name+'_window.bin');data_offset=spec['base']%8;before=b'\xa5'*(data_offset+spec['count']*4+8);table.write_bytes(before);expected=bytearray(before)
     for i,v in enumerate(values):struct.pack_into('<H',expected,data_offset+4*i,v)
     options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}','--memory-mapfile','/result/'+inp.name,'--memory-region',f'0x700000,{len(raw):#x}','--memory-mapfile','/result/'+table.name,'--memory-region',f'{spec["base"]:#x},{4*spec["count"]:#x}'];fixtures={}
     for a in spec['param_addresses']:
      data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,a%8,0x5aa5);f=r.out/f'{name}_{a:x}.bin';f.write_bytes(data);fixtures[hex(a)]=dict(file=f.name,before=data.hex());options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},2']
     r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x},0x700000:{len(raw):#x}';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,log[-4000:];assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
     ev=[json.loads(line.removeprefix('S33_MEM '))for line in(r.out/(name+'.stderr.log')).read_text().splitlines()if line.startswith('S33_MEM ')];done=[e for e in ev if e['stage']=='result'];assert len(ev)==2*len(done)and all(e['width_bytes']==2 for e in ev)
     assert[(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(sequence if enabled else[]);assert table.read_bytes()==expected
     for a,value in zip(spec['param_addresses'],param_values):
      f=fixtures[hex(a)];after=(r.out/f['file']).read_bytes();f['after']=after.hex();old=bytes.fromhex(f['before']);assert struct.unpack_from('<H',after,a%8)[0]==value;assert all(after[j]==old[j]for j in range(8)if j not in[a%8,a%8+1])
     assert inp.read_bytes()==raw and main.read_bytes()==body;case.update(scenario=scenario,spec_name=spec['name'],observer_enabled=enabled,input_pattern=pattern,input_file=inp.name,parameter_arguments=[hex(p1),hex(p2)],expected_packed_values=values,expected_parameter_values=param_values,expected_r0_after_return=hex(ret),window_file=table.name,window_data_offset=data_offset,window_expected_sha256=hashlib.sha256(expected).hexdigest(),fixtures=fixtures,completed_memory_events=done,full_original_writer_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(done),'events',flush=True)
    assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,trace_identical=True,events=len(sequence),spec_name=spec['name']))
  assert len(pairs)==12 and sum(p['events']for p in pairs)==244
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FF7_REMAINING_RAW_WRITERS',pairs=pairs,specs=SPECS,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main),path=str(main)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Three bounded raw transfer windows are separate from independent control-register admissions.','The raw9 writer unconditionally writes two tail parameters after the9 input halfwords.','Input buffers,caller stack,parameter seeds and backing are fixtures,not physical reset/configuration or free RAM.','No physical peripheral identity/access permissions/timing/IRQ or actual Nikon caller domains verified.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
