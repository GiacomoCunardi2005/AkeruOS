#!/usr/bin/env python3
"""Execute original mode-cache producer and FE6 caller loops with explicit raw inputs."""
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
WINDOWS=[(0x239f00,0x239f2c),(0x23a270,0x23a2b0),(0x2c5d30,0x2c5d58),(0x1f08d0,0x1f090a),(0x1f090c,0x1f0940),(0x1f0948,0x1f095c),(0x1f0960,0x1f097e),(0x1f0980,0x1f09b0),(0x1f09be,0x1f0a6a),(0x1f0a6c,0x1f0a90),(0x2c5d58,0x2c5de8),(0x2c5e80,0x2c5ee0),(0x2c5ee0,0x2c5f20)]

def main():
    r=ObservedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='fe6-original-loop-and-mode-producer'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB
        sources=[Path(__file__),Path(__file__).with_name('s33_verify_remaining_direct_mmio.py'),Path(__file__).with_name('s33_register_profile_observer.c'),Path(__file__).with_name('s33_register_memory_observer.c')]
        for p in sources+[BUILD,LAB/'install/bin/arc-elf32-run']+[LAB/'build-gnu89'/x for x in LIBS]:r.input_hashes[str(p)]=sha(p)
        for p in sources:(r.out/p.name).write_bytes(p.read_bytes())
        incs=['build-gnu89/sim/arc','build-gnu89/bfd','source/gnu-arc700-sim-src/include','source/gnu-arc700-sim-src/sim/arc','source/gnu-arc700-sim-src/sim/common','source/gnu-arc700-sim-src/opcodes']
        cmd=['podman','run','--rm','--network','none','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','-v',str(LAB)+':/work:ro','-v',str(sources[0].parent)+':/frontend:ro','-v',str(r.out)+':/newout:rw',IMAGE,'gcc','-std=gnu11','-fgnu89-inline','-O2','-g','-fsanitize=bounds','-fno-sanitize-recover=all']
        for p in incs:cmd+=['-I','/work/'+p]
        cmd+=['/frontend/s33_register_profile_observer.c','-Wl,--start-group']+['/work/build-gnu89/'+p for p in LIBS]+['-Wl,--end-group']+['-Wl,--wrap='+s for s in SYMBOLS]+['-lnsl','-lm','-o','/newout/observer']
        q=r.command('build_observer',cmd,timeout=90);assert q.returncode==0,q.stdout[-2000:]
        blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate'];main=r.out/'payload0_mmap.bin';main.write_bytes(body);r.input_hashes[str(directory/info['file'])]=sha(directory/info['file'])
        (r.out/'original_windows.txt').write_text('\n\n'.join(aligned_window(body,base,a,b)for a,b in WINDOWS))
        # Each tuple: raw first/second, upstream gates, cached ready/word, caller arg, expected mode word.
        scenarios=[('cold_mode2_arg0',0xa4,8,0,0,0,0,0,0x20002),('cold_mode2_arg3',0xa4,8,0,0,0,0,3,0x20002),
                   ('cached_mode2_arg2',0,0,0,0,1,0x20002,2,0x20002),('cold_mode1',0xa0,8,0,0,0,0,1,0x10002),
                   ('cold_invalid',0x90,8,0,0,0,0,1,0),('cold_mode2_second0',0xa4,0,0,0,0,0,1,0x20004),
                   ('cold_mode2_gatebc',0xa4,8,0xc00,0,0,0,2,0x20004),('cold_mode2_gate3000',0xa4,8,0,0xc000,0,0,2,0x20004),
                   ('cold_mode3',0xa8,0,0,0,0,0,1,0x30004),('cold_mode4',0xac,0,0,0,0,0,1,0x40004),
                   ('cold_original_selector24',0xa4,8,0,0,0,0,7,0x20002)]
        addresses=sorted([0xfe60000+16*s for s in range(1,29)]+[0xfef0020,0xfe800bc,0xfed3000,0xfed3800,0xfe60240,0xfe60244]);pairs=[]
        for name,raw1,raw2,gatebc,gate3000,ready,cached,arg,expected_mode in scenarios:
            entry=0x23a270 if name=='cold_original_selector24'else 0x239f00
            expected_events=[]
            if not ready:
                expected_events.append((0x1f08f4,'read',0xfef0020,raw1))
                if raw1>>4==0xa and (raw1&15)in [0,4,8,12]:
                    expected_events.append((0x1f0930,'read',0xfe800bc,gatebc))
                    if not gatebc&0xc00:
                        expected_events.append((0x1f0948,'read',0xfed3000,gate3000))
                        if not gate3000&0xc000:expected_events.append((0x1f0960,'read',0xfed3800,raw2))
            mode=expected_mode>>16
            if mode==2:
                if entry==0x239f00:expected_events.extend((0x2c5d50,'write',0xfe60000+16*s,(arg&3)<<12)for s in range(1,29))
                else:expected_events.extend([(0x2c5ea2,'read',0xfe60244,0x200),(0x2c5eaa,'write',0xfe60244,0x300),(0x2c5f12,'read',0xfe60244,0x300),(0x2c5de0,'write',0xfe60240,arg&3),(0x2c5ece,'read',0xfe60244,0x300),(0x2c5ed6,'write',0xfe60244,0x200)])
            asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
            asm+=f'mov r0,{arg:#x}\nmov r12,{entry:#x}\njl [r12]\ncmp sp,r20\nbne fail\ncmp r13,0x13371337\nbne fail\ncmp r14,0x14471447\nbne fail\ncmp r15,0x15571557\nbne fail\ncmp r16,0x16671667\nbne fail\nmov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
            elf=compile_probe(r,name,asm);traces=[]
            for enabled in [False,True]:
                case_name=name+('_observed'if enabled else'_reference');r.observe=enabled
                options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={};expected_cells={a:0x5aa5 for a in addresses}
                expected_cells.update({0xfef0020:raw1,0xfe800bc:gatebc,0xfed3000:gate3000,0xfed3800:raw2,0xfe60244:0x200})
                for a in addresses:
                    data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,a%8,expected_cells[a]);f=r.out/f'{case_name}_{a:x}.bin';f.write_bytes(data);fixtures[hex(a)]=dict(file=f.name,before=data.hex(),kind='modeled_mmio')
                    options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},2']
                flags=bytearray(b'\xa5'*8);flags[4:6]=b'\x01\x01';cache=bytearray(12);cache[4]=ready;struct.pack_into('<I',cache,8,cached)
                for a,data,size in [(0x36932c,flags,2),(0x423f00,cache,12)]:
                    f=r.out/f'{case_name}_ram_{a:x}.bin';f.write_bytes(data);fixtures[hex(a)]=dict(file=f.name,before=data.hex(),kind='synthetic_ram')
                    options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},{size:#x}']
                r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x},0x36932c:2,0x423f00:12'
                case,log=r.run(case_name,'/result/'+elf.name,options,trace=True,extract=True)
                assert case['exit_code']==0 and case['fault']is None,log[-4000:]
                assert all(s not in log for s in ['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
                ev=[json.loads(x)for x in re.findall(r'S33_MEM (\{[^\n]+)',log)];done=[e for e in ev if e['stage']=='result']
                assert len(ev)==2*len(done) and all(e['width_bytes']==2 for e in done)
                assert [(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(expected_events if enabled else []),(case_name,done,expected_events)
                for pc,op,a,value in expected_events:
                    if op=='write':expected_cells[a]=value
                for key,f in fixtures.items():
                    after=(r.out/f['file']).read_bytes();f['after']=after.hex();before=bytes.fromhex(f['before']);a=int(key,0)
                    if f['kind']=='modeled_mmio':
                        assert struct.unpack_from('<H',after,a%8)[0]==expected_cells[a]
                        assert all(after[j]==before[j]for j in range(8)if j not in [a%8,a%8+1])
                flags_after=bytes.fromhex(fixtures['0x36932c']['after']);cache_after=bytes.fromhex(fixtures['0x423f00']['after'])
                expected_flags=bytes([1,1])if ready else bytes([0,0 if any(e[0]==0x1f0960 for e in expected_events)else 1])
                assert flags_after[4:6]==expected_flags and flags_after[:4]==flags[:4]and flags_after[6:]==flags[6:]
                assert cache_after[4]==1 and cache_after[5:8]==b'\0'*3 and struct.unpack_from('<I',cache_after,8)[0]==expected_mode
                assert struct.unpack_from('<H',cache_after,0)[0]==(0 if ready else raw1)
                assert struct.unpack_from('<H',cache_after,2)[0]==(raw2 if not ready and any(e[0]==0x1f0960 for e in expected_events)else 0)
                assert main.read_bytes()==body
                case.update(scenario=name,observer_enabled=enabled,entry=hex(entry),caller_argument=arg,raw_inputs=dict(first=raw1,second=raw2,gatebc=gatebc,gate3000=gate3000,ready=ready,cached=cached),expected_mode_word=hex(expected_mode),fixtures=fixtures,completed_memory_events=done,full_original_caller_completed=True,expected_sequence=expected_events)
                traces.append((r.out/(case_name+'.trace')).read_bytes());print(case_name,'PASS',len(done),'mode',hex(expected_mode),flush=True)
            assert traces[0]==traces[1];pairs.append(dict(scenario=name,trace_identical=True,events=len(expected_events),entry=hex(entry)))
        fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0
        r.results.update(status='PASS_FE6_ORIGINAL_LOOP_AND_MODE_PRODUCER',pairs=pairs,windows=WINDOWS,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main),path=str(main)),hardware_access=False,gnu_modified=False,
          limits=['Raw identification/gate words, cache-ready state, two RAM flags and caller arguments are explicit fixtures; not physical IDs, mode configuration or reset values.',
                  'Original routines compute the mode and loop selector values; this is CPU execution with storage MMIO, not camera boot/IRQ/peripheral execution.',
                  'Selector24 statusbit9 starts set as an explicit fixture; no real bit8-to-bit9 completion or peripheral timing modeled.',
                  'FE60010..FE601C0 writes are 28 original loop iterations, not an assumed 32-bit selector-space register census.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
