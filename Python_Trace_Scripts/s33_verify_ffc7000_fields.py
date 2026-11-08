#!/usr/bin/env python3
"""Run original FFC7000 masked halfword fields without changing GNU or Main."""
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
def field(address,pool,read,write,arg,shift,width,subtract=0):return dict(address=address,pool=pool,read_pc=read,write_pc=write,argument=arg,shift=shift,width_bits=width,subtract_before_mask=subtract)
SPECS=[dict(name='minus13_pair',kind='minus13_pair',entry=0x308438,end=0x308490,fields=[field(0xffc7000,0x308448,0x30844c,0x308464,0,0,13,1),field(0xffc7004,0x30846c,0x308470,0x308488,1,0,13,1)])]
for name,entry,base in [('split_a',0x308490,0xffc7008),('split_b',0x308598,0xffc7024),('split_c',0x3086b4,0xffc7100)]:SPECS.append(dict(name=name,kind='low16_high12',entry=entry,end=entry+0x4c,fields=[field(base,entry+0xc,entry+0x10,entry+0x22,0,0,16),field(base+4,entry+0x2c,entry+0x30,entry+0x44,0,16,12)]))
for name,entry,base,width in [('low12_a',0x3084dc,0xffc7010,12),('low12_b',0x3085e4,0xffc702c,12),('low13',0x308700,0xffc7118,13)]:SPECS.append(dict(name=name,kind='low'+str(width),entry=entry,end=entry+0x2c,fields=[field(base,entry+0xc,entry+0x10,entry+0x22,0,0,width)]))
for name,entry,base in [('dual_a',0x308508,0xffc7014),('dual_b',0x308610,0xffc7030),('dual_c',0x30872c,0xffc7108)]:SPECS.append(dict(name=name,kind='dual12_13',entry=entry,end=entry+0x90,fields=[field(base+4*i,entry+[0x10,0x30,0x50,0x70][i],entry+[0x14,0x34,0x54,0x74][i],entry+[0x28,0x48,0x68,0x88][i],i//2,16*(i%2),[16,12,16,13][i])for i in range(4)]))
SPECS.append(dict(name='direct16',kind='direct16',entry=0x3086a0,end=0x3086b4,fields=[field(0xffc7050,0x3086a8,None,0x3086ac,0,0,16)]));SPECS.sort(key=lambda s:s['entry'])
VALUES=[0,1,0x0fff,0x1000,0x1fff,0x2000,0x80018000,0xffffffff]
def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ffc7000-original-field-accessors'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256'];r.experimental_engine=LAB;assert sha(REUSED/'observer')==json.loads((REUSED/'verified_evidence.json').read_text())['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json',Path(__file__).with_name('s33_verify_ff7_transfer_windows.py')]:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);body=ps[0];base=bs[0]['load_address_candidate'];mf=r.out/'payload0_mmap.bin';mf.write_bytes(body);r.input_hashes[str(bd/bs[0]['file'])]=sha(bd/bs[0]['file']);addresses=sorted({f['address']for s in SPECS for f in s['fields']});assert len(addresses)==24 and len(SPECS)==11
  for s in SPECS:
   for f in s['fields']:assert struct.unpack_from('<I',body,f['pool']-base)[0]==f['address']
  (r.out/'linear_navigation_only.txt').write_text(aligned_window(body,base,0x308438,0x3087bc));pairs=[]
  for pattern,v in enumerate(VALUES):
   scenario='fields_'+str(pattern);seed=[0,65535,0xa55a,0x5aa5,0xf000,0xe000,0x8001,0x7ffe][pattern];initial={a:seed for a in addresses};state=dict(initial);args=[v,VALUES[(pattern+3)%len(VALUES)]];calls=[];sequence=[];asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
   for spec in SPECS:
    ev=[]
    for f in spec['fields']:
     address=f['address'];mask=(1<<f['width_bits'])-1;value=((args[f['argument']]>>f['shift'])-f['subtract_before_mask'])&mask
     if f['read_pc']is not None:ev.append((f['read_pc'],'read',address,state[address]));value|=state[address]&(~mask&65535)
     ev.append((f['write_pc'],'write',address,value));state[address]=value
    asm+=''.join(f'mov r{i},{x:#x}\n'for i,x in enumerate(args))+f'mov r12,{spec["entry"]:#x}\njl [r12]\ncmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{x:#x}\nbne fail\n'for i,x in[(13,0x13371337),(14,0x14471447),(15,0x15571557),(16,0x16671667)]);calls.append(dict(entry=hex(spec['entry']),arguments=list(map(hex,args)),expected_return=None));sequence.extend(ev)
   assert len(sequence)==47;asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+mf.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
    for address,x in initial.items():
     raw=bytearray(b'\xa5'*8);struct.pack_into('<H',raw,address%8,x);p=r.out/f'{name}_{address:x}.bin';p.write_bytes(raw);fixtures[hex(address)]=dict(file=p.name,before=raw.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{address:#x},2']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,log[-5000:];assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:']);raw_events=[json.loads(s.removeprefix('S33_MEM '))for s in(r.out/(name+'.stderr.log')).read_text().splitlines()if s.startswith('S33_MEM ')];events=[e for e in raw_events if e['stage']=='result'];assert len(raw_events)==2*len(events)and all(e['width_bytes']==2 for e in raw_events);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==(sequence if enabled else[])
    for key,f in fixtures.items():
     address=int(key,0);before=bytes.fromhex(f['before']);after=(r.out/f['file']).read_bytes();assert struct.unpack_from('<H',after,address%8)[0]==state[address]and all(before[j]==after[j]for j in range(8)if j not in[address%8,address%8+1]);f['after']=after.hex()
    assert mf.read_bytes()==body;case.update(scenario=scenario,pattern=pattern,observer_enabled=enabled,original_calls=calls,fixtures=fixtures,completed_memory_events=events,full_original_calls_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(events),'events',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,events=len(sequence),trace_identical=True))
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FFC7000_MASKED_FIELDS',specs=SPECS,pairs=pairs,scalar_addresses=list(map(hex,addresses)),payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(mf),path=str(mf)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Masks12/13 and subtract-one describe original software fields,not peripheral names,dimensions or legal hardware domains.','Halfword RMW reads before replacing low16 can discard all old bits;this does not establish32bit peripheral registers.','Argument split low16/high12 orhigh13 does not prove atomicity orphysical32bit transfer.','MMIO seed,stack and backing are synthetic fixtures;actual caller constraints/reset/permissions/IRQ/timing unknown.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
