#!/usr/bin/env python3
"""Observe original FF7 packing contracts and variants without treating cells as controls."""
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
SPECS=[dict(name='packed7_a',window='packed7_a',entry=0x2e06f0,end=0x2e0774,base=0xff74044,count=17,kind='pair7_wide',pc=0x2e074c,param_addresses=[0xff74088],param_pcs=[0x2e0768],aux_pcs=[0x2e072e,0x2e0734]),dict(name='packed7_b',window='packed7_b',entry=0x2e0774,end=0x2e07f8,base=0xff7408c,count=17,kind='pair7_wide',pc=0x2e07d0,param_addresses=[0xff740d0],param_pcs=[0x2e07ec],aux_pcs=[0x2e07b2,0x2e07b8]),dict(name='paired8_a_wide',window='paired8_a',entry=0x2e0884,end=0x2e0908,base=0xff740f0,count=17,kind='pair8_wide',pc=0x2e08dc,param_addresses=[0xff74138,0xff74134],param_pcs=[0x2e08f0,0x2e08fc],aux_pcs=[0x2e08bc,0x2e08c2]),dict(name='paired8_a_compact',window='paired8_a',entry=0x2e0908,end=0x2e098c,base=0xff740f0,count=17,kind='pair8_compact',pc=0x2e0960,param_addresses=[0xff74138,0xff74134],param_pcs=[0x2e0974,0x2e0980],aux_pcs=[0x2e0940,0x2e0946]),dict(name='paired8_b_wide',window='paired8_b',entry=0x2e098c,end=0x2e0a10,base=0xff7413c,count=17,kind='pair8_wide',pc=0x2e09e4,param_addresses=[0xff74184,0xff74180],param_pcs=[0x2e09f8,0x2e0a04],aux_pcs=[0x2e09c4,0x2e09ca]),dict(name='paired8_b_compact',window='paired8_b',entry=0x2e0a10,end=0x2e0a94,base=0xff7413c,count=17,kind='pair8_compact',pc=0x2e0a68,param_addresses=[0xff74184,0xff74180],param_pcs=[0x2e0a7c,0x2e0a88],aux_pcs=[0x2e0a48,0x2e0a4e]),dict(name='paired8_c_wide',window='paired8_c',entry=0x2e0a94,end=0x2e0b18,base=0xff74188,count=17,kind='pair8_wide',pc=0x2e0aec,param_addresses=[0xff741d0,0xff741cc],param_pcs=[0x2e0b00,0x2e0b0c],aux_pcs=[0x2e0acc,0x2e0ad2]),dict(name='paired8_c_compact',window='paired8_c',entry=0x2e0b18,end=0x2e0b9c,base=0xff74188,count=17,kind='pair8_compact',pc=0x2e0b70,param_addresses=[0xff741d0,0xff741cc],param_pcs=[0x2e0b84,0x2e0b90],aux_pcs=[0x2e0b50,0x2e0b56]),dict(name='raw12',window='raw12',entry=0x2e0bd0,end=0x2e0c30,base=0xff7600c,count=12,kind='raw16',pc=0x2e0c04,param_addresses=[0xff7603c,0xff76040],param_pcs=[0x2e0c18,0x2e0c28],aux_pcs=[0x2e0be4,0x2e0bea]),dict(name='raw17',window='raw17',entry=0x2e0c30,end=0x2e0c70,base=0xff76044,count=17,kind='raw16',pc=0x2e0c60,param_addresses=[],param_pcs=[],aux_pcs=[0x2e0c40,0x2e0c46])]

def make_input(spec,pattern):
 kind=spec['kind'];wide=kind.endswith('wide');n=spec['count'];special=[0,0x7f,0x80,0xff,0x100,0x7fff,0x8000,0xffff]
 if kind=='raw16':values=[((i*1237+0x3412)^(0xffff if pattern==2 else 0))&65535 for i in range(n)];return struct.pack('<'+'H'*n,*values),values
 values=[special[i]if i<len(special)else(i*1237+0x3412)&65535 for i in range(32)]
 if pattern==1:values=[v^(0xff80 if kind=='pair7_wide'else 0xff00)for v in values]
 elif pattern==2:values=[v^0xffff for v in values]
 tail=0x8001 if pattern==2 else 0xbeef
 if wide:raw=struct.pack('<33H',*(values+[tail]))
 else:raw=bytes([v&255 for v in values]+[tail&255])
 mask=0x7f if kind=='pair7_wide'else 255;packed=[(values[2*i]&mask)|((values[2*i+1]&mask)<<8)for i in range(16)]+[tail if wide else tail&255];return raw,packed

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ff7-packed-writer-contracts'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB;pinned=json.loads((REUSED/'verified_evidence.json').read_text());assert sha(REUSED/'observer')==pinned['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),Path(__file__).with_name('s33_verify_ff7_transfer_windows.py'),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate'];main=r.out/'payload0_mmap.bin';main.write_bytes(body);r.input_hashes[str(directory/info['file'])]=sha(directory/info['file'])
  (r.out/'original_windows.txt').write_text('\n\n'.join(aligned_window(body,base,s['entry'],s['end'])for s in SPECS));pairs=[];outputs={}
  for spec in SPECS:
   patterns=[0,1,2]if spec['kind'].endswith('wide')else[0,2]
   for pattern in patterns:
    scenario=spec['name']+'_'+str(pattern);raw,values=make_input(spec,pattern);p1,p2=(0x12345678,0x9abcdeff)if pattern!=2 else(0,0xabcdfc00);param_values=[((p1<<10)|p2)&65535]if spec['kind']=='pair7_wide'else[p1&65535,p2&65535]if spec['name']=='raw12'else[]if spec['name']=='raw17'else[p2&65535,p1&65535]
    ret=spec['param_addresses'][0]if spec['kind']=='pair7_wide'else p2 if spec['name']=='raw12'else spec['base']+4*(spec['count']-1)if spec['name']=='raw17'else spec['param_addresses'][-1]
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
  equivalences=[]
  for spec in SPECS:
   if spec['kind'].endswith('wide'):
    assert outputs[(spec['name'],0)]==outputs[(spec['name'],1)];equivalences.append(dict(spec_name=spec['name'],kind='ignored_high_input_bits',patterns=[0,1],all_MMIO_outputs_equal=True))
  for letter in['a','b','c']:
   wide=outputs[(f'paired8_{letter}_wide',0)];compact=outputs[(f'paired8_{letter}_compact',0)];assert[(a,v)for pc,op,a,v in wide[:16]]==[(a,v)for pc,op,a,v in compact[:16]];assert wide[16][3]==0xbeef and compact[16][3]==0xef;equivalences.append(dict(window='paired8_'+letter,kind='wide_vs_compact',first16_values_equal=True,tail_wide='0xbeef',tail_compact='0xef'))
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FF7_PACKED_WRITER_CONTRACTS',pairs=pairs,specs=SPECS,metamorphic_checks=equivalences,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main),path=str(main)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Seven bounded write windows are separate from independent control-register admissions.','Only first16 cells use pair packing; cell16 follows the distinct16bit or8bit tail load contract.','Input buffers/parameter seeds/backing and synthetic callers are fixtures, not physical reset/configuration or free RAM.','No physical peripheral meaning, access permissions, timing or complete Nikon caller reachability proved.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
