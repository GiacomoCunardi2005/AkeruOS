#!/usr/bin/env python3
"""Observe the second bounded FE6 bank and its original mode-gated caller."""
import json,re,struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha,IMAGE
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_remaining_direct_mmio import ObservedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_verify_register_memory_observer import LIBS,SYMBOLS
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_fe6_original_loop import WINDOWS as MODE_WINDOWS
VALID=list(range(0x34,0x3e))+list(range(0x44,0x4d))
INVALID=[0,0x33,0x3e,0x43,0x4d,0x7fffffff,0x80000000,0xffffffff]
IDS={0xfef0020:0xa4,0xfe800bc:0,0xfed3000:0,0xfed3800:8}
WINDOWS=[(0x2c6738,0x2c679c),(0x2c679c,0x2c6834),(0x2c6834,0x2c6894),(0x2c6894,0x2c68d4),(0x2c68d4,0x2c6928),(0x2c6928,0x2c694c),(0x239f2c,0x239fc8)]+MODE_WINDOWS[3:10]

def address(s):return 0xfe64000+16*s if s in VALID else None

def main():
    r=ObservedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='fe6-second-bank-and-original-caller'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB
        sources=[Path(__file__),Path(__file__).with_name('s33_verify_fe6_original_loop.py'),Path(__file__).with_name('s33_verify_remaining_direct_mmio.py'),Path(__file__).with_name('s33_register_profile_observer.c'),Path(__file__).with_name('s33_register_memory_observer.c')]
        for p in sources+[BUILD,LAB/'install/bin/arc-elf32-run']+[LAB/'build-gnu89'/x for x in LIBS]:r.input_hashes[str(p)]=sha(p)
        for p in sources:(r.out/p.name).write_bytes(p.read_bytes())
        incs=['build-gnu89/sim/arc','build-gnu89/bfd','source/gnu-arc700-sim-src/include','source/gnu-arc700-sim-src/sim/arc','source/gnu-arc700-sim-src/sim/common','source/gnu-arc700-sim-src/opcodes']
        cmd=['podman','run','--rm','--network','none','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','-v',str(LAB)+':/work:ro','-v',str(sources[0].parent)+':/frontend:ro','-v',str(r.out)+':/newout:rw',IMAGE,'gcc','-std=gnu11','-fgnu89-inline','-O2','-g','-fsanitize=bounds','-fno-sanitize-recover=all']
        for p in incs:cmd+=['-I','/work/'+p]
        cmd+=['/frontend/s33_register_profile_observer.c','-Wl,--start-group']+['/work/build-gnu89/'+p for p in LIBS]+['-Wl,--end-group']+['-Wl,--wrap='+s for s in SYMBOLS]+['-lnsl','-lm','-o','/newout/observer']
        q=r.command('build_observer',cmd,timeout=90);assert q.returncode==0,q.stdout[-2000:]
        blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate'];main=r.out/'payload0_mmap.bin';main.write_bytes(body);r.input_hashes[str(directory/info['file'])]=sha(directory/info['file'])
        (r.out/'original_windows.txt').write_text('\n\n'.join(aligned_window(body,base,a,b)for a,b in WINDOWS));cells=sorted({address(s)+off for s in VALID for off in [0,4,8,12]});assert len(cells)==76;pairs=[]
        scenarios=[('domain_zero',VALID,0),('domain_ones',VALID,65535),('invalid',INVALID,0xa55a),('original_caller',VALID,0)]
        for scenario,selectors,seed in scenarios:
            original=scenario=='original_caller';expected={a:(0x200 if original and a%16==4 else seed)for a in cells};initial={**expected,**IDS};sequence=[];calls=[]
            if original:sequence.extend([(0x1f08f4,'read',0xfef0020,0xa4),(0x1f0930,'read',0xfe800bc,0),(0x1f0948,'read',0xfed3000,0),(0x1f0960,'read',0xfed3800,8)])
            asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
            def call(entry,args,events,ret=None):
                nonlocal asm
                asm+=''.join(f'mov r{i},{v&0xffffffff:#x}\n'for i,v in enumerate(args))+f'mov r12,{entry:#x}\njl [r12]\n'
                if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
                asm+='cmp sp,r20\nbne fail\ncmp r13,0x13371337\nbne fail\ncmp r14,0x14471447\nbne fail\ncmp r15,0x15571557\nbne fail\ncmp r16,0x16671667\nbne fail\n'
                calls.append(dict(entry=hex(entry),arguments=list(map(hex,args)),expected_events=events,expected_return=ret));sequence.extend(events)
            for s in selectors:
                a=address(s)
                if original:
                    events=[(0x2c6856,'read',a+4,0x200),(0x2c685e,'write',a+4,0x300),(0x2c68c6,'read',a+4,0x300),(0x2c6794,'write',a,0x1803),(0x2c6882,'read',a+4,0x300),(0x2c688a,'write',a+4,0x200)]
                    call(0x239f2c,[s,7,2,1],events);expected[a]=0x1803;continue
                value=3|((6<<10)&0xc00)|((5<<12)&0x3000)|((7<<14)&0xc000)
                call(0x2c6738,[s,7,6,5,7],[]if a is None else[(0x2c6794,'write',a,value)])
                if a is not None:expected[a]=value
                value=None if a is None else(expected[a]&0x3ff)|0x6c00
                call(0x2c679c,[s,3,2,1],[]if a is None else[(0x2c67e0 if s<0x44 else 0x2c6814,'read',a,expected[a]),(0x2c682c,'write',a,value)])
                if a is not None:expected[a]=value
                for flag in [1,0]:
                    value=None if a is None else(expected[a+4]|0x100 if flag else expected[a+4]&~0x100)
                    call(0x2c6834,[s,flag],[]if a is None else[(0x2c6856 if flag else 0x2c6882,'read',a+4,expected[a+4]),(0x2c685e if flag else 0x2c688a,'write',a+4,value)])
                    if a is not None:expected[a+4]=value
                    call(0x2c6894,[s],[]if a is None else[(0x2c68c6,'read',a+4,expected[a+4])],0 if a is None else expected[a+4]&0x200)
                call(0x2c68d4,[s,3,0xdeadbeef,0x6abc],[]if a is None else[(0x2c691a,'write',a+8,0xbeef),(0x2c6920,'write',a+12,0xaabc)])
                if a is not None:expected[a+8]=0xbeef;expected[a+12]=0xaabc
                call(0x2c6928,[s,0x1357],[]if s not in [0x4a,0x4c]else[(0x2c6944,'write',a+8,0x1357)])
                if s in [0x4a,0x4c]:expected[a+8]=0x1357
            asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
            for enabled in [False,True]:
                name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
                for a,value in initial.items():
                    data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,a%8,value);f=r.out/f'{name}_{a:x}.bin';f.write_bytes(data);fixtures[hex(a)]=dict(file=f.name,before=data.hex(),kind='modeled_mmio')
                    options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},2']
                flags=bytearray(b'\xa5'*8);flags[4:6]=b'\x01\x01';cache=bytearray(12)
                for a,data,size in [(0x36932c,flags,2),(0x423f00,cache,12)]:
                    f=r.out/f'{name}_ram_{a:x}.bin';f.write_bytes(data);fixtures[hex(a)]=dict(file=f.name,before=data.hex(),kind='synthetic_ram');options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},{size:#x}']
                r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x},0x36932c:2,0x423f00:12';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
                assert case['exit_code']==0 and case['fault']is None,log[-4000:];assert all(s not in log for s in ['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
                ev=[json.loads(x)for x in re.findall(r'S33_MEM (\{[^\n]+)',log)];done=[e for e in ev if e['stage']=='result'];assert len(ev)==2*len(done)and all(e['width_bytes']==2 for e in done)
                assert [(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(sequence if enabled else[]),(name,done[:10],sequence[:10])
                for key,f in fixtures.items():
                    after=(r.out/f['file']).read_bytes();f['after']=after.hex();before=bytes.fromhex(f['before']);a=int(key,0)
                    if f['kind']=='modeled_mmio':
                        assert struct.unpack_from('<H',after,a%8)[0]==expected.get(a,initial[a])
                        assert all(after[j]==before[j]for j in range(8)if j not in[a%8,a%8+1])
                    elif a==0x423f00:
                        assert after==(struct.pack('<HHII',0xa4,8,1,0x20002)if original else before)
                    else:
                        want=bytearray(before)
                        if original:want[4:6]=b'\0\0'
                        assert after==want
                assert main.read_bytes()==body
                case.update(scenario=scenario,observer_enabled=enabled,original_caller=original,selectors=list(map(hex,selectors)),fixtures=fixtures,completed_memory_events=done,original_calls=calls,expected_sequence=sequence,full_selected_paths_completed=True)
                traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(calls),'calls',len(done),'events',flush=True)
            assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,trace_identical=True,events=len(sequence),original_calls=len(calls)))
        fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0
        r.results.update(status='PASS_FE6_SECOND_BANK_AND_ORIGINAL_CALLER',pairs=pairs,windows=WINDOWS,valid_selectors=list(map(hex,VALID)),invalid_selectors_tested=list(map(hex,INVALID)),new_addresses=list(map(hex,cells)),payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main),path=str(main)),hardware_access=False,gnu_modified=False,limits=['Complete over the19 accepted input selectors of these six original helpers, not physical or whole-firmware completeness.','Raw MMIO, flag/cache initial state and caller arguments are explicit fixtures, not physical IDs/reset/configuration.','Original239F2C executes for all19 selectors; bit9 starts set to permit polling, no peripheral bit8-to-bit9 transition modeled.','Special2C6928 writes offset8 only for4A/4Chex; getterbit9 and setterbit8 remain distinct.']);r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
