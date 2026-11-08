#!/usr/bin/env python3
"""Run FF7 RMW, split-halfword writers and early packing windows unchanged."""
import json,re,struct,shutil
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
REUSED=ROOT/'outputs/gnu_arc700/20261025T104108Z_2704fcf9'
EARLY=[0xff70800,0xff70838,0xff70844,0xff70c00,0xff70c60,0xff70c64,0xff70cc4,0xff70cc8,0xff70ccc,0xff71000,0xff71004,0xff71008]
SINGLES=[(0x2e0318,0xff77000),(0x2e032c,0xff77004),(0x2e0340,0xff77008),(0x2e0354,0xff7700c),(0x2e04d0,0xff77058),(0x2e04e4,0xff7705c),(0x2e04f8,0xff77060)]
SPLITS=[(0x2e0368+0x28*i,0xff77010+8*i,0xff77014+8*i)for i in range(9)]
WINDOWS=[dict(name='nibble15',entry=0x2e01c8,end=0x2e0258,base=0xff70c68,count=4,pc=0x2e0248,aux_pcs=[0x2e0228,0x2e022e]),dict(name='sparse5',entry=0x2e02b0,end=0x2e0318,base=0xff7100c,count=3,pc=0x2e0308,aux_pcs=[0x2e02ea,0x2e02f0])]

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ff7-early-controls-and-packing'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256'];r.experimental_engine=LAB;old=json.loads((REUSED/'verified_evidence.json').read_text());assert sha(REUSED/'observer')==old['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),Path(__file__).with_name('s33_verify_ff7_transfer_windows.py'),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate'];main=r.out/'payload0_mmap.bin';main.write_bytes(body);r.input_hashes[str(directory/info['file'])]=sha(directory/info['file'])
  for e,a in SINGLES:assert struct.unpack_from('<H',body,e-base)[0]==0xc0f1 and struct.unpack_from('<I',body,e+8-base)[0]==a
  for e,lo,hi in SPLITS:assert struct.unpack_from('<H',body,e-base)[0]==0xc0f1 and struct.unpack_from('<I',body,e+12-base)[0]==lo and struct.unpack_from('<I',body,e+28-base)[0]==hi
  source_windows=[(0x2e0040,0x2e0318)]+[(e,e+20)for e,a in SINGLES]+[(e,e+40)for e,lo,hi in SPLITS];(r.out/'original_windows.txt').write_text('\n\n'.join(aligned_window(body,base,a,b)for a,b in source_windows));scalar=sorted(set(EARLY)|{a for e,a in SINGLES}|{a for e,lo,hi in SPLITS for a in[lo,hi]});assert len(scalar)==37
  scenarios=[('controls_zero',0),('controls_ones',65535),('word_split',0xa55a)]+[('nibble15_'+str(i),0xa55a)for i in[0,1,2]]+[('sparse5_'+str(i),0xa55a)for i in range(5)];pairs=[];outputs={}
  for scenario,seed in scenarios:
   expected={a:seed for a in scalar};sequence=[];calls=[];input_raw=None;window=None;pattern=None;packed=None;asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
   def call(entry,args,events):
    nonlocal asm
    asm+=''.join(f'mov r{i},{v&0xffffffff:#x}\n'for i,v in enumerate(args))+f'mov r12,{entry:#x}\njl [r12]\ncmp sp,r20\nbne fail\ncmp r13,0x13371337\nbne fail\ncmp r14,0x14471447\nbne fail\ncmp r15,0x15571557\nbne fail\ncmp r16,0x16671667\nbne fail\n';calls.append(dict(entry=hex(entry),arguments=list(map(hex,args)),expected_events=events));sequence.extend(events)
   def rw(entry,args,a,read,write,value):
    call(entry,args,[(read,'read',a,expected[a]),(write,'write',a,value)]);expected[a]=value
   if scenario.startswith('controls_'):
    rw(0x2e0040,[0xdeadbeef],0xff70800,0x2e004c,0x2e0054,expected[0xff70800]|1)
    for value in[0,1,2,3,0xffffffff]:
     for entry,a,rd,wr,rd0,wr0 in[(0x2e005c,0xff70838,0x2e0070,0x2e0078,0x2e0080,0x2e0088),(0x2e0090,0xff70844,0x2e00a4,0x2e00ac,0x2e00b4,0x2e00bc),(0x2e0258,0xff71000,0x2e026c,0x2e0274,0x2e027c,0x2e0284)]:rw(entry,[value],a,rd if value==1 else rd0,wr if value==1 else wr0,(expected[a]|1)if value==1 else(expected[a]&~1))
     rw(0x2e00c4,[value],0xff70c00,0x2e00d4,0x2e00e2,(expected[0xff70c00]&~3)|(value&3));rw(0x2e00ec,[value],0xff70c00,0x2e00fc,0x2e0110,(expected[0xff70c00]&~12)|((value<<2)&12));rw(0x2e0130,[value],0xff70c64,0x2e0140,0x2e0154,(expected[0xff70c64]&~0x30)|((value<<4)&0x30))
     extra=(value*0x1237+0xdeadbeef)&0xffffffff;v=(expected[0xff70c64]&~15)|(value&15);call(0x2e015c,[value,extra],[(0x2e0170,'read',0xff70c64,expected[0xff70c64]),(0x2e017e,'write',0xff70c64,v),(0x2e018c,'write',0xff70cc4,extra&65535)]);expected[0xff70c64]=v;expected[0xff70cc4]=extra&65535
     v=(value|(extra<<8))&65535;call(0x2e0118,[value,extra],[(0x2e0128,'write',0xff70c60,v)]);expected[0xff70c60]=v
     v1=(value|(extra<<4))&65535;v2=(extra|(value<<8))&65535;call(0x2e0194,[value,extra,extra,value],[(0x2e01ac,'write',0xff70cc8,v1),(0x2e01c0,'write',0xff70ccc,v2)]);expected[0xff70cc8]=v1;expected[0xff70ccc]=v2
     call(0x2e028c,[value,extra],[(0x2e029c,'write',0xff71004,value&65535),(0x2e02a8,'write',0xff71008,extra&65535)]);expected[0xff71004]=value&65535;expected[0xff71008]=extra&65535
   elif scenario=='word_split':
    for value in[0,0xffffffff,0x1234abcd,0x80000001]:
     for entry,a in SINGLES:call(entry,[value],[(entry+12,'write',a,value&65535)]);expected[a]=value&65535
     for entry,lo,hi in SPLITS:call(entry,[value],[(entry+16,'write',lo,value&65535),(entry+32,'write',hi,value>>16)]);expected[lo]=value&65535;expected[hi]=value>>16
   else:
    name,number=scenario.rsplit('_',1);pattern=int(number);window=next(s for s in WINDOWS if s['name']==name)
    if name=='nibble15':
     values=[(i*1237+0x91af)&65535 for i in range(15)];values[:4]=[0,15,16,65535]
     if pattern==1:values=[v^0xfff0 for v in values]
     elif pattern==2:values=[v^0xffff for v in values]
     input_raw=struct.pack('<15H',*values);v=[x&15 for x in values];packed=[(v[0]<<4)|(v[1]<<8)|(v[2]<<12)]+[sum(v[3+4*j+k]<<(4*k)for k in range(4))for j in range(3)];args=[0x700000]
    else:
     data=bytearray([0,0xa5,0x7f,0x5a,0x80,0xff,0xff,0xc3,0x81]);arg=7
     if pattern==1:
      for i in[1,3,5,7]:data[i]^=255
     elif pattern==2:arg=0xffffffff
     elif pattern==3:arg=8
     elif pattern==4:data=bytearray(x^255 for x in data);arg=2
     input_raw=bytes(data);packed=[data[0]|(data[2]<<8),data[4]|(data[6]<<8),data[8]|((arg&7)<<8)];args=[0x700000,arg]
    call(window['entry'],args,[(window['pc'],'write',window['base']+4*i,v)for i,v in enumerate(packed)]);outputs[scenario]=sequence
   asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
    for a in scalar:
     data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,a%8,seed);f=r.out/f'{name}_{a:x}.bin';f.write_bytes(data);fixtures[hex(a)]=dict(file=f.name,before=data.hex());options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},2']
    if window:
     inp=r.out/(scenario+'_input.bin');inp.write_bytes(input_raw);off=window['base']%8;before=b'\xa5'*(off+4*window['count']+8);table=r.out/(name+'_window.bin');table.write_bytes(before);want=bytearray(before)
     for i,v in enumerate(packed):struct.pack_into('<H',want,off+4*i,v)
     options+=['--memory-mapfile','/result/'+inp.name,'--memory-region',f'0x700000,{len(input_raw):#x}','--memory-mapfile','/result/'+table.name,'--memory-region',f'{window["base"]:#x},{4*window["count"]:#x}']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}'+(f',0x700000:{len(input_raw):#x}'if window else'');case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,log[-4000:];assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
    ev=[json.loads(line.removeprefix('S33_MEM '))for line in(r.out/(name+'.stderr.log')).read_text().splitlines()if line.startswith('S33_MEM ')];done=[e for e in ev if e['stage']=='result'];assert len(ev)==2*len(done)and all(e['width_bytes']==2 for e in ev);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(sequence if enabled else[])
    for key,f in fixtures.items():
     a=int(key,0);after=(r.out/f['file']).read_bytes();f['after']=after.hex();old=bytes.fromhex(f['before']);assert struct.unpack_from('<H',after,a%8)[0]==expected[a];assert all(after[j]==old[j]for j in range(8)if j not in[a%8,a%8+1])
    if window:assert table.read_bytes()==want and inp.read_bytes()==input_raw
    assert main.read_bytes()==body;case.update(scenario=scenario,observer_enabled=enabled,original_calls=calls,fixtures=fixtures,completed_memory_events=done,window_name=window['name']if window else None,window_file=table.name if window else None,input_file=inp.name if window else None,pattern=pattern,expected_packed_values=packed,full_original_paths_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(calls),'calls',len(done),'events',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,trace_identical=True,events=len(sequence),original_calls=len(calls)))
  assert outputs['nibble15_0']==outputs['nibble15_1']and outputs['sparse5_0']==outputs['sparse5_1']==outputs['sparse5_2'];assert outputs['nibble15_0'][0][3]&15==0 and outputs['sparse5_3'][-1][3]==0x81
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FF7_EARLY_CONTROLS_SPLITS_AND_SMALL_WINDOWS',pairs=pairs,small_windows=WINDOWS,single_halfword_entries=[dict(entry=hex(e),address=hex(a))for e,a in SINGLES],split_argument_entries=[dict(entry=hex(e),low_address=hex(lo),high_address=hex(hi))for e,lo,hi in SPLITS],scalar_addresses=list(map(hex,scalar)),payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main),path=str(main)),hardware_access=False,gnu_modified=False,limits=['Split32argument means two ordered16bit writes, not atomic physical32bit register width.','Small bounded write windows remain separate from independent control registers.','RMW masks and overlapping OR-pack formulas describe software only; physical roles/permissions/reset/timing unknown.','Synthetic callers, buffer700000, MMIO seeds and backing are fixtures, not hardware state or free RAM.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
