#!/usr/bin/env python3
"""Original FFB packed controls and FFC halfword accessors on the existing GNU CPU."""
import json,shutil,struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_verify_ff7_transfer_windows import SeparatedRunner,REUSED
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window

FFB_SINGLES=[(0x2e18ac,0x2e18c0,0xffb80a0),(0x2e1928,0x2e193c,0xffb80c0)]
FFB_SPLITS=[(0x2e18d4,0xffb80a4),(0x2e1950,0xffb80c4)]
PACK4=[(0x2e19a4,0xffb80ac),(0x2e19d8,0xffb80b4),(0x2e1a0c,0xffb80cc),(0x2e1a40,0xffb80d4)]
UNPACK=[(0x2e1a74,0xffb80ac),(0x2e1af4,0xffb80cc)]
FFC_SPLITS=[(0x2e2d88,0xffc2000),(0x2e2dc4,0xffc2020),(0x2e2e00,0xffc2028),(0x2e2e3c,0xffc2040),(0x2e2e78,0xffc2048),(0x2e2eb4,0xffc2050),(0x2e2ef0,0xffc206c),(0x2e2f2c,0xffc2074),(0x2e2f68,0xffc207c),(0x2e30c8,0xffc2000),(0x2e30f0,0xffc2008),(0x2e3168,0xffc2020),(0x2e3190,0xffc2028),(0x2e3208,0xffc2040),(0x2e3230,0xffc2050),(0x2e32a8,0xffc206c),(0x2e32d0,0xffc207c)]
FFC_SINGLES=[(0x2e2db0,0xffc2010),(0x2e2dec,0xffc2030),(0x2e2e28,0xffc2034),(0x2e2e64,0xffc2058),(0x2e2ea0,0xffc205c),(0x2e2edc,0xffc2060),(0x2e2f18,0xffc2084),(0x2e2f54,0xffc2088),(0x2e2f90,0xffc208c),(0x2e3118,0xffc2010),(0x2e312c,0xffc2014),(0x2e3140,0xffc2018),(0x2e3154,0xffc201c),(0x2e31b8,0xffc2030),(0x2e31cc,0xffc2034),(0x2e31e0,0xffc2038),(0x2e31f4,0xffc203c),(0x2e3258,0xffc2058),(0x2e326c,0xffc2060),(0x2e3280,0xffc2064),(0x2e3294,0xffc2068),(0x2e32f8,0xffc2084),(0x2e330c,0xffc208c),(0x2e3320,0xffc2090),(0x2e3334,0xffc2094)]
FFC_BITS=[(0x2e2fa4,2,False),(0x2e2fc0,6,False),(0x2e2fdc,6,True),(0x2e2ff8,3,True),(0x2e3014,3,False),(0x2e3030,4,True),(0x2e304c,4,False),(0x2e3068,5,True),(0x2e3084,5,False),(0x2e3348,2,True),(0x2e3364,11,True),(0x2e3380,11,False),(0x2e339c,7,True),(0x2e33b8,7,False),(0x2e33d4,8,True),(0x2e33f0,8,False),(0x2e340c,9,True),(0x2e3428,9,False),(0x2e3444,10,True),(0x2e3460,10,False),(0x2e347c,0,True),(0x2e3498,1,True),(0x2e34b4,1,False)]
FFC_READS=[(0x2e34d0+20*i,0xffc20a0+4*i)for i in range(6)]
VALUES=[0,0xffff,0x1fff0000,0x20000000,0x80008000,0xffffffff,0x12345678,0xa55a5aa5]
PACK5_ARGS=[[0]*5,[1]*5]+[[int(i==j)for i in range(5)]for j in range(5)]+[[0x12345678,0x8001,0xabcdef03,0x10010,0xffffffff]]

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ffb-packed-ffc-accessors'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB;prior=json.loads((REUSED/'verified_evidence.json').read_text());assert sha(REUSED/'observer')==prior['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),Path(__file__).with_name('s33_verify_ff7_transfer_windows.py'),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);body=ps[0];base=bs[0]['load_address_candidate'];main_file=r.out/'payload0_mmap.bin';main_file.write_bytes(body);r.input_hashes[str(bd/bs[0]['file'])]=sha(bd/bs[0]['file']);(r.out/'linear_navigation_only.txt').write_text('\n'.join(aligned_window(body,base,a,b)for a,b in[(0x2e1878,0x2e1c88),(0x2e2d88,0x2e3548)]));pairs=[]
  for group in['ffb','ffc']:
   addresses=({0xffb8090,0xffb80dc,0xffb80f0,0xffb80fc,*range(0xffb80e0,0xffb80f0,4)}|{a for _,_,a in FFB_SINGLES}|{a+off for _,a in FFB_SPLITS+PACK4 for off in[0,4]})if group=='ffb'else({a+off for _,a in FFC_SPLITS for off in[0,4]}|{a for _,a in FFC_SINGLES+FFC_READS}|{0xffc2098,0xffc209c})
   assert len(addresses)==(22 if group=='ffb'else 46)
   for pattern,v in enumerate(VALUES):
    scenario=f'{group}_{pattern}';initial={a:(0 if pattern==0 else 65535 if pattern==1 else((a*57+pattern*0x2345)^0xa55a)&65535)for a in addresses};state=dict(initial);buffers={};sequence=[];calls=[];asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
    def call(entry,args,events,ret=None):
     nonlocal asm
     asm+=''.join(f'mov r{i},{x&0xffffffff:#x}\n'for i,x in enumerate(args))+f'mov r12,{entry:#x}\njl [r12]\n'
     if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
     asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{x:#x}\nbne fail\n'for i,x in[(13,0x13371337),(14,0x14471447),(15,0x15571557),(16,0x16671667)]);sequence.extend(events);calls.append(dict(entry=entry,arguments=args,expected_return=ret))
     for _,op,a,x in events:
      if op=='write':state[a]=x
    def unpack(stage):
     for j,(entry,a)in enumerate(UNPACK):
      ptr=0x700000+0x100*(2*stage+j);before=b'\xa5'*32;after=bytearray(before);vals=[]
      for i in range(4):vals.extend([state[a+4*i]&255,state[a+4*i]>>8])
      struct.pack_into('<8H',after,8,*vals);buffers[ptr]=dict(file=f'{scenario}_{ptr:x}.bin',before=before.hex(),expected=after.hex());pcs=[0x10,0x18,0x30,0x38,0x4c,0x54,0x68,0x70];call(entry,[ptr+8],[(entry+off,'read',a+4*(i//2),state[a+4*(i//2)])for i,off in enumerate(pcs)])
    if group=='ffb':
     unpack(0)
     for setter,getter,a in FFB_SINGLES:call(getter,[],[(getter+12,'read',a,state[a])],state[a]);call(setter,[v],[(setter+12,'write',a,v&65535)]);call(getter,[],[(getter+12,'read',a,state[a])],state[a])
     for entry,a in FFB_SPLITS:
      for off,g in[(0,entry+44),(4,entry+64)]:call(g,[],[(g+12,'read',a+off,state[a+off])],state[a+off])
      call(entry,[v],[(entry+20,'write',a+4,(v>>16)&8191),(entry+36,'write',a,v&65535)])
      for off,g in[(0,entry+44),(4,entry+64)]:call(g,[],[(g+12,'read',a+off,state[a+off])],state[a+off])
     args=PACK5_ARGS[pattern];call(0x2e1878,args,[(0x2e18a4,'write',0xffb8090,(args[0]|args[1]<<1|args[2]<<2|args[3]<<3|args[4]<<4)&65535)])
     for j,(entry,a)in enumerate(PACK4):
      args=[VALUES[(pattern+j+i)%8]for i in range(4)];call(entry,args,[(entry+24,'write',a,(args[0]|args[1]<<8)&65535),(entry+44,'write',a+4,(args[2]|args[3]<<8)&65535)])
     unpack(1)
     for entry,a,bit in[(0x2e1b74,0xffb80dc,0),(0x2e1c3c,0xffb80f0,1)]:
      for x in[0,1,2,0xffffffff]:
       off=20 if x else 36;new=(state[a]|1<<bit)if x else(state[a]&~(1<<bit));call(entry,[x],[(entry+off,'read',a,state[a]),(entry+off+8,'write',a,new)])
     a=0xffb80f0;call(0x2e1c24,[],[(0x2e1c30,'read',a,state[a])],state[a]&1);call(0x2e1c08,[],[(0x2e1c14,'read',a,state[a]),(0x2e1c1c,'write',a,state[a]|1)]);call(0x2e1c24,[],[(0x2e1c30,'read',a,state[a])],state[a]&1)
     for entry,a in[(0x2e1ba8,0xffb80e0),(0x2e1bc0,0xffb80e4),(0x2e1bd8,0xffb80e8),(0x2e1bf0,0xffb80ec),(0x2e1c70,0xffb80fc)]:call(entry,[],[(entry+12,'read',a,state[a])],state[a]&(16383 if a==0xffb80fc else 255))
    else:
     for entry,a in FFC_SPLITS:call(entry,[v],[(entry+16,'write',a,v&65535),(entry+32,'write',a+4,v>>16)])
     for entry,a in FFC_SINGLES:call(entry,[v],[(entry+12,'write',a,v&65535)])
     for entry,bit,set_ in FFC_BITS:
      a=0xffc2098;new=state[a]|(1<<bit)if set_ else state[a]&~(1<<bit);call(entry,[],[(entry+12,'read',a,state[a]),(entry+20,'write',a,new)])
     a=0xffc209c;call(0x2e30a0,[v],[(0x2e30b0,'read',a,state[a]),(0x2e30be,'write',a,(state[a]&0xfff0)|(v&15))])
     for entry,a in FFC_READS:call(entry,[],[(entry+12,'read',a,state[a])],state[a])
    asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
    for enabled in[False,True]:
     name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+main_file.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
     for a,b in buffers.items():(r.out/b['file']).write_bytes(bytes.fromhex(b['before']));options+=['--memory-mapfile','/result/'+b['file'],'--memory-region',f'{a:#x},32']
     for a,x in sorted(initial.items()):
      raw=bytearray(b'\xa5'*8);struct.pack_into('<H',raw,a%8,x);p=r.out/f'{name}_{a:x}.bin';p.write_bytes(raw);fixtures[hex(a)]=dict(file=p.name,before=raw.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},2']
     r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}'+''.join(f',{a:#x}:32'for a in buffers);case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,(name,log[-4000:]);assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
     events=[json.loads(s.removeprefix('S33_MEM '))for s in(r.out/(name+'.stderr.log')).read_text().splitlines()if s.startswith('S33_MEM ')];done=[e for e in events if e['stage']=='result'];assert len(events)==2*len(done)and all(e['width_bytes']==2 for e in done);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(sequence if enabled else[]),(name,done,sequence)
     for key,f in fixtures.items():
      a=int(key,0);after=(r.out/f['file']).read_bytes();before=bytes.fromhex(f['before']);assert struct.unpack_from('<H',after,a%8)[0]==state[a]and all(after[j]==before[j]for j in range(8)if j not in[a%8,a%8+1]);f['after']=after.hex()
     for b in buffers.values():assert(r.out/b['file']).read_bytes()==bytes.fromhex(b['expected'])
     assert main_file.read_bytes()==body;case.update(scenario=scenario,group=group,pattern=pattern,observer_enabled=enabled,fixtures=fixtures,output_buffers=buffers,original_calls=calls,completed_memory_events=done,full_original_calls_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(done),'events',flush=True)
    assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,events=len(sequence),trace_identical=True))
  assert len(pairs)==16;fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FFB_PACKED_FFC',pairs=pairs,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main_file),path=str(main_file)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Original instructions run on GNU with synthetic callers, RAM and seeded halfword MMIO storage; no physical peripheral semantics established.','FFB unpack rereads each cell; stable synthetic storage does not establish coherent live hardware snapshots.','FFC low16/high16 pairs write in that order; no atomic32bit bus transfer, latch or transaction semantics inferred.','Wide arguments expose unmasked OR/truncation, not a safe physical hardware API; physical fields/reset/side effects and Nikon caller domains remain unknown.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
