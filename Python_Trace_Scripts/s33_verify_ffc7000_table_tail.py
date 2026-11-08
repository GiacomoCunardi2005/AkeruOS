#!/usr/bin/env python3
"""Execute original table-parameterized FFC7000 wrappers and adjacent scalar controls."""
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
PACK5=[0xffc74fc,0xffc7504,0xffc750c,0xffc7514]
PACK7=[0xffc75e0,0xffc7624,0xffc7668,0xffc76ac]
PACK8=[0xffc76f0,0xffc7704]
SCALARS=[0xffc751c,0xffc7520,0xffc7524,0xffc7528,0xffc752c]
GROUPS=[('pack5',0x309188,16),('raw33',0x3092a0,66),('skip16',0x3093ac,16),('pack7',0x309430,132),('pack8',0x3094e8,18),('scalars',None,3)]
def make_input(group,pattern,length):
 if group=='raw33':
  values=[(i*1237+0x3412)&65535 for i in range(33)];values[:6]=[0,65535,0x8000,0x1ff,0x200,0x1234]
  if pattern==0:values=[0]*33
  elif pattern==1:values=[65535]*33
  elif pattern==3:values=[x^65535 for x in values]
  return struct.pack('<33H',*values)
 values=bytearray((i*37+0x51)&255 for i in range(length));special=[0,1,31,32,127,128,255,85]
 for i,v in enumerate(special[:length]):values[i]=v
 if group=='scalars':values=bytearray([128,127,255])
 if pattern==0:values=bytearray(length)
 elif pattern==1:values=bytearray([255]*length)
 elif pattern==3:values=bytearray(x^(0xe0 if group=='pack5'else 0x80 if group=='pack7'else 255)for x in values)
 return bytes(values)

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ffc7000-original-table-tail'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256'];r.experimental_engine=LAB;assert sha(REUSED/'observer')==json.loads((REUSED/'verified_evidence.json').read_text())['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json',Path(__file__).with_name('s33_verify_ff7_transfer_windows.py')]:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);body=ps[0];base=bs[0]['load_address_candidate'];mf=r.out/'payload0_mmap.bin';mf.write_bytes(body);r.input_hashes[str(bd/bs[0]['file'])]=sha(bd/bs[0]['file']);table=body[0x354e50-base:0x354e98-base];assert struct.unpack_from('<4I',table,8)==(0,8,31,7936)and struct.unpack_from('<4I',table,24)==(0,8,255,65280)and struct.unpack_from('<4I',table,40)==(0,8,127,32512)and struct.unpack_from('<4I',table,56)==(0,8,255,65280)
  (r.out/'linear_navigation_only.txt').write_text('\n\n'.join(aligned_window(body,base,lo,hi)for lo,hi in[(0x3090fc,0x309228),(0x309228,0x3092dc),(0x3092dc,0x309504)]));pairs=[];outputs={};sentinels={13:0x13371337,14:0x14471447,15:0x15571557,16:0x16671667,17:0x17771777,18:0x18871887,19:0x19971997}
  for group,entry,length in GROUPS:
   for pattern in range(4):
    scenario=group+'_'+str(pattern);raw=make_input(group,pattern,length);inp=r.out/(scenario+'_input.bin');inp.write_bytes(raw);seed=0 if pattern==0 else 65535 if pattern==1 else 0xa55a;addresses=sorted(set(SCALARS)if group=='scalars'else set(range(0xffc7530,0xffc75b4,4))if group=='raw33'else{0xffc75b8+4*i for i in[0,1,2,3,4,6,7,8]}if group=='skip16'else{a+4*i for a in(PACK5 if group=='pack5'else PACK7 if group=='pack7'else PACK8)for i in range(2 if group=='pack5'else 17 if group=='pack7'else 5)});state={a:seed for a in addresses};sequence=[];calls=[];asm='mov r20,sp\n'+''.join(f'mov r{i},{x:#x}\n'for i,x in sentinels.items())
    def call(target,argv,events):
     nonlocal asm
     asm+=''.join(f'mov r{i},{x:#x}\n'for i,x in enumerate(argv))+f'mov r12,{target:#x}\njl [r12]\ncmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{x:#x}\nbne fail\n'for i,x in sentinels.items());calls.append(dict(entry=hex(target),arguments=list(map(hex,argv))));sequence.extend(events)
     for _,op,a,x in events:
      if op=='write':state[a]=x
    if group=='scalars':
     aa,bb=0xffc751c,0xffc7520;x=(state[aa]&0xff00)|raw[0];y=(x&255)|(raw[1]<<8);z=(state[bb]&0xff00)|raw[2];call(0x3091b4,[0x700000],[(0x3091d8,'read',aa,state[aa]),(0x3091e8,'write',aa,x),(0x3091ec,'read',aa,x),(0x309208,'write',aa,y),(0x309214,'read',bb,state[bb]),(0x309220,'write',bb,z)])
     value=[0,65535,0x80018080,0x12345678][pattern];other=[0x12345678,0x80018080,65535,0][pattern];call(0x309228,[value],[(0x309234,'write',0xffc7524,value&65535)]);call(0x30923c,[other],[(0x309248,'write',0xffc7528,other&65535)])
     for flag in[0,1,2,0xffffffff]:
      a0=0xffc752c;first=(state[a0]&0xff00)|(value&255);last=first|0x8000 if flag else first&0x7fff;call(0x309250,[value,flag],[(0x309264,'read',a0,state[a0]),(0x309272,'write',a0,first),(0x30927e if flag else 0x30928e,'read',a0,first),(0x309286 if flag else 0x309296,'write',a0,last)])
    elif group=='raw33':
     ev=[(0x3092d0,'write',0xffc7530+4*i,v)for i,v in enumerate(struct.unpack('<33H',raw))];call(entry,[0x700000],ev)
    else:
     ev=[];temporary=dict(state)
     if group=='skip16':
      operations=[(i,raw[i],0x309324,0x309348)for i in range(10)]+[(j,raw[j-2],0x309374,0x30939e)for j in range(12,18)];segments=[(0xffc75b8,operations,8)]
     else:
      per=4 if group=='pack5'else 33 if group=='pack7'else 9;rd,wr=(0x309154,0x309178)if group=='pack5'else(0x3093fc,0x309420)if group=='pack7'else(0x3094b4,0x3094d8);segments=[(a0,[(i,raw[j*per+i],rd,wr)for i in range(per)],5 if group=='pack5'else 7 if group=='pack7'else 8)for j,a0 in enumerate(PACK5 if group=='pack5'else PACK7 if group=='pack7'else PACK8)]
     for a0,ops,width in segments:
      for i,value,rd,wr in ops:
       address=a0+4*(i//2);shift=8*(i%2);mask=((1<<width)-1)<<shift;new=(temporary[address]&~mask)|((value<<shift)&mask);ev.extend([(rd,'read',address,temporary[address]),(wr,'write',address,new)]);temporary[address]=new
     call(entry,[0x700000],ev)
    outputs[(group,pattern)]=[(a,x)for pc,op,a,x in sequence if op=='write'];asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
    for enabled in[False,True]:
     name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+mf.name,'--memory-region',f'{base:#x},{len(body):#x}','--memory-mapfile','/result/'+inp.name,'--memory-region',f'0x700000,{len(raw):#x}'];fixtures={}
     for address in addresses:
      before=bytearray(b'\xa5'*8);struct.pack_into('<H',before,address%8,seed);p=r.out/f'{name}_{address:x}.bin';p.write_bytes(before);fixtures[hex(address)]=dict(file=p.name,before=before.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{address:#x},2']
     r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x},0x700000:{len(raw):#x}';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,log[-5000:];assert all(x not in log for x in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:']);captured=[json.loads(line.removeprefix('S33_MEM '))for line in(r.out/(name+'.stderr.log')).read_text().splitlines()if line.startswith('S33_MEM ')];events=[e for e in captured if e['stage']=='result'];assert len(captured)==2*len(events)and all(e['width_bytes']==2 for e in captured);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==(sequence if enabled else[])
     for key,f in fixtures.items():
      address=int(key,0);before=bytes.fromhex(f['before']);after=(r.out/f['file']).read_bytes();off=address%8;assert struct.unpack_from('<H',after,off)[0]==state[address]and all(before[i]==after[i]for i in range(8)if i not in[off,off+1]);f['after']=after.hex()
     assert inp.read_bytes()==raw and mf.read_bytes()==body;case.update(scenario=scenario,group=group,pattern=pattern,observer_enabled=enabled,input_file=inp.name,input_bytes_hex=raw.hex(),original_calls=calls,fixtures=fixtures,completed_memory_events=events,full_original_calls_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(events),'events',flush=True)
    assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,events=len(sequence),trace_identical=True))
  assert outputs[('pack5',2)]==outputs[('pack5',3)]and outputs[('pack7',2)]==outputs[('pack7',3)];assert len(pairs)==24 and sum(x['events']for x in pairs)==1684;fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FFC7000_ORIGINAL_TABLE_TAIL',pairs=pairs,original_parameter_table=dict(address='0x354e50',bytes_hex=table.hex(),source='unchanged_original_Main'),metamorphic_equivalences=2,skipped_destination='0xffc75cc',payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(mf),path=str(mf)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Only original wrappers bind parameterized helper destinations;other caller domains remain unresolved.','Split skip16loops use indices0..9 and12..17 butconsume all16input bytes;gap75CC not accessed,not evidence ofmissing physical register/freeRAM.','5bit and7bitlane masks preserve unselected oldbits;odd final packed byte leaves highlane oldstate.','Input RAM,stack,MMIO seeds andbacking are fixtures;no physical role/reset/permissions/IRQ/timing inferred.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
