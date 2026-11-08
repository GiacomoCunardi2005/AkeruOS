#!/usr/bin/env python3
"""Execute five original bounded FF7 writers; retain apertures separately from registers."""
import json,re,struct,shutil,subprocess
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import DefinedRunner,LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
REUSED=ROOT/'outputs/gnu_arc700/20261025T104108Z_2704fcf9'
SPECS=[dict(name='halfword_a',entry=0x2e0574,end=0x2e0600,base=0xff72000,count=1024,input_bits=16,store_pc=0x2e05b0,control=0xff74000,bit=1,set_read=0x2e0554,set_write=0x2e055c,clear_read=0x2e0564,clear_write=0x2e056c,tails=[0xff74038,0xff7403c,0xff74040],tail_pcs=[0x2e05d0,0x2e05e4,0x2e05f8],aux_pcs=[0x2e0592,0x2e0598]),dict(name='halfword_b',entry=0x2e0cd8,end=0x2e0d64,base=0xff73000,count=1024,input_bits=16,store_pc=0x2e0d14,control=0xff76098,bit=1,set_read=0x2e0cb8,set_write=0x2e0cc0,clear_read=0x2e0cc8,clear_write=0x2e0cd0,tails=[0xff7609c,0xff760a0,0xff760a4],tail_pcs=[0x2e0d34,0x2e0d48,0x2e0d5c],aux_pcs=[0x2e0cf6,0x2e0cfc]),dict(name='byte_a',entry=0x2e1318,end=0x2e13a4,base=0xff78000,count=256,input_bits=8,store_pc=0x2e1354,control=0xff760cc,bit=0,set_read=0x2e1068,set_write=0x2e1070,clear_read=0x2e1078,clear_write=0x2e1080,tails=[0xff760a8,0xff760ac,0xff760b0],tail_pcs=[0x2e1374,0x2e1388,0x2e139c],aux_pcs=[0x2e1336,0x2e133c]),dict(name='byte_b',entry=0x2e13a4,end=0x2e1430,base=0xff79000,count=256,input_bits=8,store_pc=0x2e13e0,control=0xff760cc,bit=1,set_read=0x2e109c,set_write=0x2e10a4,clear_read=0x2e10ac,clear_write=0x2e10b4,tails=[0xff760b4,0xff760b8,0xff760bc],tail_pcs=[0x2e1400,0x2e1414,0x2e1428],aux_pcs=[0x2e13c2,0x2e13c8]),dict(name='byte_c',entry=0x2e1430,end=0x2e14bc,base=0xff7a000,count=256,input_bits=8,store_pc=0x2e146c,control=0xff760cc,bit=2,set_read=0x2e10d0,set_write=0x2e10d8,clear_read=0x2e10e0,clear_write=0x2e10e8,tails=[0xff760c0,0xff760c4,0xff760c8],tail_pcs=[0x2e148c,0x2e14a0,0x2e14b4],aux_pcs=[0x2e144e,0x2e1454])]

class SeparatedRunner(DefinedRunner):
 def command(self,name,cmd,timeout=30):
  cmd=list(cmd)
  if '/engine/install/bin/arc-elf32-run'in cmd:
   cmd[cmd.index('/engine/install/bin/arc-elf32-run')]='/result/observer';cmd[2:2]=['--env','S33_MEM_OBSERVER='+str(int(self.observe))]
  if cmd[:2]==['podman','run']:cmd[2:2]=['--env','S33_DEFINED_RANGES='+self.known_ranges]
  cmd=list(map(str,cmd));(self.out/(name+'.command.json')).write_text(json.dumps(cmd,indent=2)+'\n')
  try:q=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
  except subprocess.TimeoutExpired as exc:
   for stream in['stdout','stderr']:
    value=getattr(exc,stream)or b'';(self.out/(name+'.'+stream+'.log')).write_bytes(value.encode()if isinstance(value,str)else value)
   raise RuntimeError(name+': host timeout, not an expected firmware stop')from exc
  (self.out/(name+'.stdout.log')).write_text(q.stdout);(self.out/(name+'.stderr.log')).write_text(q.stderr)
  q.stdout=q.stdout+'\n'+q.stderr;(self.out/(name+'.log')).write_text(q.stdout);return q

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ff7-bounded-transfer-windows'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB
  provenance=json.loads((REUSED/'verified_evidence.json').read_text());assert sha(REUSED/'observer')==provenance['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),Path(__file__).with_name('s33_verify_remaining_direct_mmio.py'),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate'];main=r.out/'payload0_mmap.bin';main.write_bytes(body);r.input_hashes[str(directory/info['file'])]=sha(directory/info['file'])
  windows=[(s['entry'],s['end'])for s in SPECS]+[(0x2e0540,0x2e0574),(0x2e0ca4,0x2e0cd8),(0x2e1054,0x2e10f0)];(r.out/'original_windows.txt').write_text('\n\n'.join(aligned_window(body,base,a,b)for a,b in windows));pairs=[]
  for spec in SPECS:
   n=spec['count'];bits=spec['input_bits'];mask=(1<<bits)-1
   for pattern in[0,1]:
    values=[((i*(109 if bits==16 else 37)+0x1234)^((0xffff if bits==16 else 0xff)if pattern else 0))&mask for i in range(n)];tails=([0x8001,0x55aa,0xffff]if bits==16 else[0x81,0x5a,0xff]);tails=[v^(mask if pattern else 0)for v in tails];all_values=values+tails;raw=struct.pack('<'+('H'if bits==16 else'B')*len(all_values),*all_values);input_file=r.out/f'{spec["name"]}_{pattern}_input.bin';input_file.write_bytes(raw)
    for skip in[False,True]:
     scenario=f'{spec["name"]}_{pattern}_'+('parameters_only'if skip else'bulk');seed=0x5aa5 if pattern==0 else 0xa55a;set_value=seed|(1<<spec['bit']);clear_value=seed&~(1<<spec['bit']);sequence=[]
     if not skip:
      sequence+=[(spec['set_read'],'read',spec['control'],seed),(spec['set_write'],'write',spec['control'],set_value)]
      sequence.extend((spec['store_pc'],'write',spec['base']+4*i,v)for i,v in enumerate(values));sequence+=[(spec['clear_read'],'read',spec['control'],set_value),(spec['clear_write'],'write',spec['control'],clear_value)]
     sequence.extend((pc,'write',a,v)for pc,a,v in zip(spec['tail_pcs'],spec['tails'],tails))
     asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\nmov r0,0x700000\n'+f'mov r1,{int(skip)}\nmov r12,{spec["entry"]:#x}\njl [r12]\ncmp r0,{tails[-1]:#x}\nbne fail\ncmp sp,r20\nbne fail\ncmp r13,0x13371337\nbne fail\ncmp r14,0x14471447\nbne fail\ncmp r15,0x15571557\nbne fail\ncmp r16,0x16671667\nbne fail\nmov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
     for enabled in[False,True]:
      name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}','--memory-mapfile','/result/'+input_file.name,'--memory-region',f'0x700000,{len(raw):#x}'];fixtures={}
      table=r.out/(name+'_window.bin');before=b'\xa5'*(4*n+8);table.write_bytes(before);options+=['--memory-mapfile','/result/'+table.name,'--memory-region',f'{spec["base"]:#x},{4*n:#x}'];expected_table=bytearray(before)
      if not skip:
       for i,v in enumerate(values):struct.pack_into('<H',expected_table,4*i,v)
      for a in[spec['control']]+spec['tails']:
       data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,a%8,seed);f=r.out/f'{name}_{a:x}.bin';f.write_bytes(data);fixtures[hex(a)]=dict(file=f.name,before=data.hex());options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},2']
      r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x},0x700000:{len(raw):#x}';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
      assert case['exit_code']==0 and case['fault']is None,log[-4000:];assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:']);ev=[json.loads(x)for x in re.findall(r'S33_MEM (\{[^\n]+)',log)];done=[e for e in ev if e['stage']=='result'];assert len(ev)==2*len(done)and all(e['width_bytes']==2 for e in done)
      assert [(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(sequence if enabled else[]),(name,len(done),len(sequence));assert table.read_bytes()==expected_table
      for a in[spec['control']]+spec['tails']:
       f=fixtures[hex(a)];after=(r.out/f['file']).read_bytes();f['after']=after.hex();expected=seed if skip else clear_value
       if a in spec['tails']:expected=tails[spec['tails'].index(a)]
       assert struct.unpack_from('<H',after,a%8)[0]==expected;prior=bytes.fromhex(f['before']);assert all(after[j]==prior[j]for j in range(8)if j not in[a%8,a%8+1])
      assert main.read_bytes()==body and input_file.read_bytes()==raw;case.update(scenario=scenario,spec_name=spec['name'],observer_enabled=enabled,parameters_only=skip,input_pattern=pattern,input_file=input_file.name,input_values=values,input_tail_values=tails,fixtures=fixtures,window_file=table.name,window_initial_byte=0xa5,window_file_size=len(before),window_expected_sha256=__import__('hashlib').sha256(expected_table).hexdigest(),completed_memory_events=done,full_original_writer_completed=True,expected_sequence=sequence);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(done),'events',flush=True)
     assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,trace_identical=True,events=len(sequence),parameters_only=skip,spec_name=spec['name']))
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0
  r.results.update(status='PASS_FF7_BOUNDED_TRANSFER_WINDOWS',pairs=pairs,specs=SPECS,windows=windows,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main),path=str(main)),hardware_access=False,gnu_modified=False,capture_streams_separate=True,diagnostic_log_order='stdout then stderr; raw streams retained separately',limits=['Five bounded indexed write windows are separate from scalar controls/parameters;2816 observed cell offsets are not2816 independent physical control registers.','Input buffers, control seeds and storage windows/gaps are explicit fixtures; physical kind, reset, access permissions and side effects unknown.','Flagr1 nonzero skips the bulk and control RMW but still writes three parameters; only0/1 are exercised here.','MMIO transactions observed are halfword writes with stride4; untouched model gaps do not prove reserved silicon fields.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
