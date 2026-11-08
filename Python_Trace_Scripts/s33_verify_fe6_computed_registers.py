#!/usr/bin/env python3
"""Execute bounded original FE6 selector accessors without physical assumptions."""
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

VALID=list(range(0x20,0x34))+list(range(0x40,0x44))
INVALID=[0,0x1f,0x34,0x3f,0x44,0x7fffffff,0x80000000,0xffffffff]
WINDOWS=[(0x2c5d58,0x2c5de8),(0x2c5de8,0x2c5e80),(0x2c5e80,0x2c5ee0),(0x2c5ee0,0x2c5f20),(0x2c5f20,0x2c5f74),(0x2c5f74,0x2c5f8c)]

def address(s):return 0xfe60200+16*(s-0x20) if 0x20<=s<=0x33 else 0xfe60400+16*(s-0x40) if 0x40<=s<=0x43 else None

def main():
    r=ObservedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='fe6-computed-register-domains'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB
        sources=[Path(__file__),Path(__file__).with_name('s33_verify_remaining_direct_mmio.py'),Path(__file__).with_name('s33_register_profile_observer.c'),Path(__file__).with_name('s33_register_memory_observer.c')]
        for p in sources+[BUILD,LAB/'install/bin/arc-elf32-run']+[LAB/'build-gnu89'/x for x in LIBS]:r.input_hashes[str(p)]=sha(p)
        for p in sources:(r.out/p.name).write_bytes(p.read_bytes())
        includes=['build-gnu89/sim/arc','build-gnu89/bfd','source/gnu-arc700-sim-src/include','source/gnu-arc700-sim-src/sim/arc','source/gnu-arc700-sim-src/sim/common','source/gnu-arc700-sim-src/opcodes']
        cmd=['podman','run','--rm','--network','none','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','-v',str(LAB)+':/work:ro','-v',str(sources[0].parent)+':/frontend:ro','-v',str(r.out)+':/newout:rw',IMAGE,'gcc','-std=gnu11','-fgnu89-inline','-O2','-g','-fsanitize=bounds','-fno-sanitize-recover=all']
        for p in includes:cmd+=['-I','/work/'+p]
        cmd+=['/frontend/s33_register_profile_observer.c','-Wl,--start-group']+['/work/build-gnu89/'+p for p in LIBS]+['-Wl,--end-group']+['-Wl,--wrap='+s for s in SYMBOLS]+['-lnsl','-lm','-o','/newout/observer']
        q=r.command('build_observer',cmd,timeout=90);assert q.returncode==0,q.stdout[-2000:]
        blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate'];main=r.out/'payload0_mmap.bin';main.write_bytes(body);r.input_hashes[str(directory/info['file'])]=sha(directory/info['file'])
        (r.out/'original_windows.txt').write_text('\n\n'.join(aligned_window(body,base,a,b) for a,b in WINDOWS))
        cells=sorted({address(s)+off for s in VALID for off in [0,4,8,12]});assert len(cells)==96
        pairs=[]
        for scenario,selectors,seed in [('domain_zero',VALID,0),('domain_ones',VALID,65535),('invalid',INVALID,0xa55a)]:
            expected={a:seed for a in cells};sequence=[];calls=[]
            asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\n'
            def call(entry,args,events,return_value=None):
                nonlocal asm
                asm+=''.join(f'mov r{i},{v&0xffffffff:#x}\n' for i,v in enumerate(args))+f'mov r12,{entry:#x}\njl [r12]\n'
                if return_value is not None:asm+=f'cmp r0,{return_value:#x}\nbne fail\n'
                asm+='cmp sp,r20\nbne fail\ncmp r13,0x13371337\nbne fail\ncmp r14,0x14471447\nbne fail\ncmp r15,0x15571557\nbne fail\n'
                calls.append(dict(entry=hex(entry),arguments=list(map(hex,args)),expected_events=events,expected_return=return_value))
                sequence.extend(events)
            for selector in selectors:
                a=address(selector)
                # Full field writer: low bits0..1,2,4,6 and upper2-bit fields.
                args=[selector,7,3,2,3,6,5,7]
                value=(7&3)|((3<<2)&4)|((2<<4)&16)|((3<<6)&64)|((6<<10)&0xc00)|((5<<12)&0x3000)|((7<<14)&0xc000)
                events=[] if a is None else [(0x2c5de0,'write',a,value)]
                call(0x2c5d58,args,events)
                if a is not None:expected[a]=value
                args=[selector,3,2,1];upper=((3<<10)|(2<<12)|(1<<14))&0xfc00
                value=None if a is None else (expected[a]&0x3ff)|upper
                events=[] if a is None else [(0x2c5e2c if selector<0x40 else 0x2c5e60,'read',a,expected[a]),(0x2c5e78,'write',a,value)]
                call(0x2c5de8,args,events)
                if a is not None:expected[a]=value
                for flag in [1,0]:
                    val=None if a is None else (expected[a+4]|0x100 if flag else expected[a+4]&~0x100)
                    events=[] if a is None else [(0x2c5ea2 if flag else 0x2c5ece,'read',a+4,expected[a+4]),(0x2c5eaa if flag else 0x2c5ed6,'write',a+4,val)]
                    call(0x2c5e80,[selector,flag],events)
                    if a is not None:expected[a+4]=val
                    # Getter tests bit9, while setter above changes bit8.
                    events=[] if a is None else [(0x2c5f12,'read',a+4,expected[a+4])]
                    call(0x2c5ee0,[selector],events,0 if a is None else expected[a+4]&0x200)
                events=[] if a is None else [(0x2c5f66,'write',a+8,0xbeef),(0x2c5f6c,'write',a+12,0xaabc)]
                call(0x2c5f20,[selector,3,0xdeadbeef,0x6abc],events)
                if a is not None:expected[a+8]=0xbeef;expected[a+12]=0xaabc
                events=[] if selector!=0x29 else [(0x2c5f84,'write',address(selector)+8,0x1357)]
                call(0x2c5f74,[selector,0x1357],events)
                if selector==0x29:expected[a+8]=0x1357
            asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
            elf=compile_probe(r,scenario,asm);traces=[]
            for enabled in [False,True]:
                name=scenario+('_observed' if enabled else '_reference');r.observe=enabled
                options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
                for a in cells:
                    raw=bytearray(b'\xa5'*8);struct.pack_into('<H',raw,a%8,seed);f=r.out/f'{name}_{a:08x}.bin';f.write_bytes(raw);fixtures[hex(a)]=dict(file=f.name,before=raw.hex(),seed=seed)
                    options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},2']
                r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}'
                case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
                assert case['exit_code']==0 and case['fault'] is None,log[-4000:]
                assert all(s not in log for s in ['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
                events=[json.loads(x) for x in re.findall(r'S33_MEM (\{[^\n]+)',log)];done=[e for e in events if e['stage']=='result']
                actual=[(e['pc'],e['operation'],e['address'],e['value']) for e in done]
                assert actual==(sequence if enabled else []),(name,actual[:10],sequence[:10]);assert len(events)==2*len(done) and all(e['width_bytes']==2 for e in done)
                for a in cells:
                    f=fixtures[hex(a)];after=(r.out/f['file']).read_bytes();f['after']=after.hex();before=bytes.fromhex(f['before'])
                    assert struct.unpack_from('<H',after,a%8)[0]==expected[a]
                    assert all(after[j]==before[j] for j in range(8) if j not in [a%8,a%8+1])
                assert main.read_bytes()==body
                case.update(scenario=scenario,selectors=list(map(hex,selectors)),observer_enabled=enabled,completed_memory_events=done,fixtures=fixtures,original_calls=calls,expected_sequence=sequence,expected_cells={hex(a):v for a,v in expected.items()},full_selected_paths_completed=True)
                traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(calls),'calls',len(done),'events',flush=True)
            assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,trace_identical=True,events=len(sequence),original_calls=len(calls)))
        fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0
        r.results.update(status='PASS_FE6_COMPUTED_ACCESSOR_DOMAINS',pairs=pairs,windows=WINDOWS,valid_selectors=list(map(hex,VALID)),invalid_selectors_tested=list(map(hex,INVALID)),address_expression='FE60200+16*(s-20hex) for s20..33hex; FE60400+16*(s-40hex) for s40..43hex; offsets0,4,8,C',addresses=list(map(hex,cells)),payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main),path=str(main)),hardware_access=False,gnu_modified=False,
          limits=['Original bounded accessors are invoked by a synthetic caller over their software input domains; actual Nikon caller selector values and physical implementation remain unknown.',
                  'Initial MMIO0/FFFF/A55A and caller inputs are explicit fixtures; no physical reset/access permission, timing, IRQ or peripheral effects verified.',
                  'Setter2C5E80 changes bit8, getter2C5EE0 tests bit9; they are not assumed to represent the same function.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
