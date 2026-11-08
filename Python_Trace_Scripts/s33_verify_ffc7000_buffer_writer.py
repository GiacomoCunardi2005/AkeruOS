#!/usr/bin/env python3
"""Execute the original FFC7000 sparse structure writer with bounded input fixtures."""
import json,struct,shutil
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
REUSED=ROOT/'outputs/gnu_arc700/20261025T104108Z_2704fcf9'
SLOTS=[(0x308a84,0x308a98,38,16),(0x308aa4,0x308ab8,40,16),(0x308ac4,0x308ad6,50,9)]
for i in range(15):
 read=0x308ae4+0x1c*i;offset=52+2*i;SLOTS.append((read,read+(14 if offset<64 else 16),offset,9))
SLOTS +=[(0x308c88,0x308ca0,118,16),(0x308cac,0x308cc4,120,16),(0x308cd0,0x308ce8,122,16),(0x308cf4,0x308d0c,124,16),(0x308d18,0x308d28,82,9),(0x308d34,0x308d44,84,9)]
SLOTS +=[(0x308d50+0x1c*i,0x308d60+0x1c*i,86+2*i,9)for i in range(14)]

def make_input(pattern,slots):
 values=[(i*1237+0x3412)&65535 for i in range(63)];values[19:21]=[0xbeef,0x8001];values[59:63]=[0,65535,0x1234,0x8000]
 for i,v in enumerate([0,1,0x1ff,0x200,0x8000,0xffff]):values[25+i]=v
 used={s['input_offset']//2 for s in slots};low9={s['input_offset']//2 for s in slots if s['field_width_bits']==9}
 if pattern==0:values=[0]*63
 elif pattern==1:values=[65535]*63
 elif pattern==3:
  for i in low9:values[i]^=0xfe00
 elif pattern==4:
  for i in set(range(63))-used:values[i]^=65535
 elif pattern==5:values=[v^65535 for v in values]
 return struct.pack('<63H',*values)

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ffc7000-sparse-buffer-writer'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256'];r.experimental_engine=LAB;assert sha(REUSED/'observer')==json.loads((REUSED/'verified_evidence.json').read_text())['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json',Path(__file__).with_name('s33_verify_ff7_transfer_windows.py')]:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);body=ps[0];base=bs[0]['load_address_candidate'];mf=r.out/'payload0_mmap.bin';mf.write_bytes(body);r.input_hashes[str(bd/bs[0]['file'])]=sha(bd/bs[0]['file']);slots=[dict(read_pc=rd,write_pc=wr,input_offset=off,field_width_bits=width,address=struct.unpack_from('<I',body,rd-4-base)[0])for rd,wr,off,width in SLOTS];expected_addresses=set(range(0xffc7124,0xffc717c,4))|set(range(0xffc7180,0xffc71c0,4));assert len(slots)==38 and {s['address']for s in slots}==expected_addresses and sum(s['field_width_bits']==9 for s in slots)==32
  (r.out/'linear_navigation_only.txt').write_text(aligned_window(body,base,0x308a74,0x308ed4));pairs=[];outputs={};sentinels={13:0x13371337,14:0x14471447,15:0x15571557,16:0x16671667,17:0x17771777,18:0x18871887,19:0x19971997}
  for pattern in range(8):
   scenario='buffer_'+str(pattern);raw=make_input(pattern,slots);inp=r.out/(scenario+'_input.bin');inp.write_bytes(raw);seed=0 if pattern==0 else 65535 if pattern==1 else 0x5aa5 if pattern==5 else 0xa55a;arg1=0xffffffff if pattern==6 else 0 if pattern==7 else 0x12345678;state={a:seed for a in expected_addresses};sequence=[]
   for s in slots:
    addr=s['address'];value=struct.unpack_from('<H',raw,s['input_offset'])[0];mask=(1<<s['field_width_bits'])-1;result=(state[addr]&(~mask&65535))|(value&mask);sequence.extend([(s['read_pc'],'read',addr,state[addr]),(s['write_pc'],'write',addr,result)]);state[addr]=result
   assert len(sequence)==76;outputs[pattern]=[(addr,value)for pc,op,addr,value in sequence if op=='write'];asm='mov r20,sp\n'+''.join(f'mov r{i},{x:#x}\n'for i,x in sentinels.items())+f'mov r0,0x700000\nmov r1,{arg1:#x}\nmov r12,0x308a74\njl [r12]\ncmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{x:#x}\nbne fail\n'for i,x in sentinels.items())+'mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+mf.name,'--memory-region',f'{base:#x},{len(body):#x}','--memory-mapfile','/result/'+inp.name,'--memory-region','0x700000,0x7e'];fixtures={}
    for addr in sorted(expected_addresses):
     data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,addr%8,seed);p=r.out/f'{name}_{addr:x}.bin';p.write_bytes(data);fixtures[hex(addr)]=dict(file=p.name,before=data.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{addr:#x},2']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x},0x700000:0x7e';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,log[-5000:];assert all(x not in log for x in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:']);captured=[json.loads(line.removeprefix('S33_MEM '))for line in(r.out/(name+'.stderr.log')).read_text().splitlines()if line.startswith('S33_MEM ')];events=[e for e in captured if e['stage']=='result'];assert len(captured)==2*len(events)and all(e['width_bytes']==2 for e in captured);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==(sequence if enabled else[])
    for key,f in fixtures.items():
     addr=int(key,0);before=bytes.fromhex(f['before']);after=(r.out/f['file']).read_bytes();off=addr%8;assert struct.unpack_from('<H',after,off)[0]==state[addr]and all(before[i]==after[i]for i in range(8)if i not in[off,off+1]);f['after']=after.hex()
    assert inp.read_bytes()==raw and mf.read_bytes()==body;case.update(scenario=scenario,pattern=pattern,observer_enabled=enabled,input_file=inp.name,input_base='0x700000',input_length_bytes=126,argument1=hex(arg1),fixtures=fixtures,completed_memory_events=events,full_original_writer_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(events),'events',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,trace_identical=True,events=len(sequence)))
  assert outputs[2]==outputs[3]==outputs[4]==outputs[6]==outputs[7];fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FFC7000_BUFFER_WRITER',writer_entry='0x308a74',writer_end='0x308ed4',slots=slots,pairs=pairs,metamorphic_equivalences=[dict(patterns=[2,i],equal_ordered_MMIO_writes=True)for i in[3,4,6,7]],scalar_registers_admitted_from_transfer_cells=0,input_used_halfwords=38,input_ignored_halfwords=25,unwritten_between_ranges='0xffc717c',payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(mf),path=str(mf)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Thirty-eight transfer destinations remain two windows,not38independent control-register admissions.','32low9fields preserve high7;6full16fields discard prior value despite original reads.','Input span126bytes with38usedhalfwords is a selected software access contract,not a physical RAM or complete Nikon structure declaration.','Unwritten717C is not evidence of missing register/freeRAM;real caller domains/peripheral meaning/reset/IRQ/timing unknown.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
