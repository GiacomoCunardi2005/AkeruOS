#!/usr/bin/env python3
"""Execute FFC7000 conditional masks, getters and ordered byte field updates."""
import json,shutil,struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
REUSED=ROOT/'outputs/gnu_arc700/20261025T104108Z_2704fcf9'
ADDRESSES=[0xffc7060,0xffc7064,0xffc7068,0xffc706c,0xffc7074,0xffc7080,0xffc7084,0xffc7088,0xffc708c,0xffc7090,0xffc7094,0xffc7098,0xffc709c]
VALUES=[0,1,0x7f,0x80,0xff,0x100,0x80000080,0xffffffff]
def low8(x):return x&255

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ffc7000-masks-and-byte-controls'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256'];r.experimental_engine=LAB;assert sha(REUSED/'observer')==json.loads((REUSED/'verified_evidence.json').read_text())['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json',Path(__file__).with_name('s33_verify_ff7_transfer_windows.py')]:r.input_hashes[str(p)]=sha(p)
  isa_source=LAB/'source/gnu-arc700-sim-src/cpu/ARCompact.cpu';isa_text=isa_source.read_text();start=isa_text.index('(dmfi extb\n');assert '(zext SI (cast QI C))'in isa_text[start:start+200];r.input_hashes[str(isa_source)]=sha(isa_source)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);body=ps[0];base=bs[0]['load_address_candidate'];mf=r.out/'payload0_mmap.bin';mf.write_bytes(body);r.input_hashes[str(bd/bs[0]['file'])]=sha(bd/bs[0]['file']);(r.out/'linear_navigation_only.txt').write_text(aligned_window(body,base,0x3087bc,0x308a74));pairs=[];sentinels={13:0x13371337,14:0x14471447,15:0x15571557,16:0x16671667,17:0x17771777,18:0x18871887,19:0x19971997}
  for pattern,v in enumerate(VALUES):
   scenario='controls_'+str(pattern);seed=[0,65535,0xa55a,0x5aa5,0xff00,0x00ff,0x8080,0x7f7f][pattern];state={a:seed for a in ADDRESSES};sequence=[];calls=[];asm='mov r20,sp\n'+''.join(f'mov r{i},{x:#x}\n'for i,x in sentinels.items())
   def call(entry,argv,events,ret=None):
    nonlocal asm
    asm+=''.join(f'mov r{i},{x:#x}\n'for i,x in enumerate(argv))+f'mov r12,{entry:#x}\njl [r12]\n'
    if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{x:#x}\nbne fail\n'for i,x in sentinels.items());calls.append(dict(entry=hex(entry),arguments=list(map(hex,argv)),expected_return=hex(ret)if ret is not None else None));sequence.extend(events)
    for _,op,a,x in events:
     if op=='write':state[a]=x
   for flag in[0,1,2,0xffffffff]:
    addr=0xffc7060;value=(state[addr]&~v)if flag==1 else(state[addr]|v);call(0x3087bc,[flag,v],[(0x3087d4 if flag==1 else 0x3087de,'read',addr,state[addr]),(0x3087e8,'write',addr,value&65535)])
   for entry,addr in[(0x3087f0,0xffc706c),(0x308808,0xffc7074)]:call(entry,[],[(entry+12,'read',addr,state[addr])],state[addr])
   for entry,addr,bit in[(0x308820,0xffc7064,0),(0x308854,0xffc7068,1)]:
    for flag in[0,1,2,0xffffffff]:
     off=20 if flag==1 else 36;value=state[addr]|1<<bit if flag==1 else state[addr]&~(1<<bit);call(entry,[flag],[(entry+off,'read',addr,state[addr]),(entry+off+8,'write',addr,value)])
   addr=0xffc7068;call(0x308888,[v],[(0x308894,'read',addr,state[addr]),(0x30889c,'write',addr,state[addr]|1)])
   addr=0xffc7080;call(0x3088a4,[],[(0x3088b0,'read',addr,state[addr])],state[addr]&31);call(0x3088bc,[v],[(0x3088c8,'write',addr,v&65535)]);call(0x3088a4,[],[(0x3088b0,'read',addr,state[addr])],state[addr]&31)
   for flag in[0,1,2,0xffffffff]:
    addr=0xffc7084;value=(state[addr]|v)if flag==1 else(state[addr]&~v);call(0x3088d0,[flag,v],[(0x3088e8 if flag==1 else 0x3088fa,'read',addr,state[addr]),(0x3088f2 if flag==1 else 0x308902,'write',addr,value&65535)]);call(0x30890c,[],[(0x308918,'read',addr,state[addr])],state[addr])
   for entry,base_addr,argv in[(0x308920,0xffc7088,[v,VALUES[(pattern+1)%8],VALUES[(pattern+3)%8],VALUES[(pattern+5)%8]]),(0x3089a0,0xffc7090,[VALUES[(pattern+i+2)%8]for i in range(4)])]:
    ev=[]
    for index,rd1,wr1,rd2,wr2 in[(0,entry+0x18,entry+0x26,entry+0x2a,entry+0x48),(1,entry+0x54,entry+0x64,entry+0x68,entry+0x78)]:
     addr=base_addr+4*index;first=((state[addr]&0xff00)|low8(argv[2*index]))&65535;last=(first&255)|((argv[2*index+1]<<8)&0xff00);ev.extend([(rd1,'read',addr,state[addr]),(wr1,'write',addr,first),(rd2,'read',addr,first),(wr2,'write',addr,last)])
    call(entry,argv,ev)
   first_addr,second_addr=0xffc7098,0xffc709c;other=VALUES[(pattern+4)%8];first=((state[first_addr]&0xff00)|low8(v))&65535;second=(state[second_addr]&255)|((other<<8)&0xff00);call(0x308a20,[v,other],[(0x308a34,'read',first_addr,state[first_addr]),(0x308a42,'write',first_addr,first),(0x308a50,'read',second_addr,state[second_addr]),(0x308a6c,'write',second_addr,second)])
   assert len(calls)==29 and len(sequence)==63;asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+mf.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
    for addr in ADDRESSES:
     raw=bytearray(b'\xa5'*8);struct.pack_into('<H',raw,addr%8,seed);p=r.out/f'{name}_{addr:x}.bin';p.write_bytes(raw);fixtures[hex(addr)]=dict(file=p.name,before=raw.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{addr:#x},2']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,log[-5000:];assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:']);raw_events=[json.loads(s.removeprefix('S33_MEM '))for s in(r.out/(name+'.stderr.log')).read_text().splitlines()if s.startswith('S33_MEM ')];events=[e for e in raw_events if e['stage']=='result'];assert len(raw_events)==2*len(events)and all(e['width_bytes']==2 for e in raw_events);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==(sequence if enabled else[])
    for key,f in fixtures.items():
     addr=int(key,0);before=bytes.fromhex(f['before']);after=(r.out/f['file']).read_bytes();assert struct.unpack_from('<H',after,addr%8)[0]==state[addr]and all(before[i]==after[i]for i in range(8)if i not in[addr%8,addr%8+1]);f['after']=after.hex()
    assert mf.read_bytes()==body;case.update(scenario=scenario,pattern=pattern,observer_enabled=enabled,original_calls=calls,fixtures=fixtures,completed_memory_events=events,full_original_calls_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(events),'events',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,events=len(sequence),trace_identical=True))
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FFC7000_CONDITIONAL_AND_BYTE_CONTROLS',pairs=pairs,scalar_addresses=list(map(hex,ADDRESSES)),selected_original_entries=13,extb_reference=dict(source=str(isa_source),sha256=sha(isa_source),semantics='zext SI (cast QI C)'),failed_initial_oracle_attempt=str(ROOT/'outputs/gnu_arc700/20261025T155940Z_9e4cf536/verified_evidence.json'),failed_initial_oracle_reason='verifier assumed sign extension;EXTB is zero extension;original code andGNU unchanged',callee_saved_sentinels={str(i):hex(x)for i,x in sentinels.items()},payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(mf),path=str(mf)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['FFC7060 clears mask only forflag1,whereasFFC7084 sets mask only forflag1.','EXTB zero-extends low8;first RMW preserves high8 and later RMW can replace high8 separately;ordered intermediate writes are retained,not atomicpacked writes.','FFC7080 getter masks low5 but setter writes full16;getter mask does not delimit hardwarewidth.','MMIO seeds,stack and backing are fixtures;peripheral identity/reset/permissions/IRQ/timing and actual caller domains unknown.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
