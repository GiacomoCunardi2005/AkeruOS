#!/usr/bin/env python3
"""Execute original synchronization wrappers/vector paths with explicit offline state."""
import json,re,struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha,IMAGE
from s33_verify_gnu_defined_memory import DefinedRunner,LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_register_memory_observer import LIBS,SYMBOLS

class ObservedRunner(DefinedRunner):
    def command(self,name,cmd,timeout=30):
        if '/engine/install/bin/arc-elf32-run' in cmd:
            cmd=list(cmd);cmd[cmd.index('/engine/install/bin/arc-elf32-run')]='/result/observer'
            cmd[2:2]=['--env','S33_MEM_OBSERVER='+str(int(self.observe))]
        return super().command(name,cmd,timeout)

def main():
    r=ObservedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='remaining-direct-mmio-original-code'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB
        c=Path(__file__).with_name('s33_register_memory_observer.c')
        for p in [Path(__file__),c,c.with_name('s33_register_profile_observer.c'),BUILD,LAB/'install/bin/arc-elf32-run']+[LAB/'build-gnu89'/x for x in LIBS]:r.input_hashes[str(p)]=sha(p)
        for p in [Path(__file__),c,c.with_name('s33_register_profile_observer.c')]:(r.out/p.name).write_bytes(p.read_bytes())
        includes=['build-gnu89/sim/arc','build-gnu89/bfd','source/gnu-arc700-sim-src/include','source/gnu-arc700-sim-src/sim/arc','source/gnu-arc700-sim-src/sim/common','source/gnu-arc700-sim-src/opcodes']
        cmd=['podman','run','--rm','--network','none','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','-v',str(LAB)+':/work:ro','-v',str(c.parent)+':/frontend:ro','-v',str(r.out)+':/newout:rw',IMAGE,'gcc','-std=gnu11','-fgnu89-inline','-O2','-g','-fsanitize=bounds','-fno-sanitize-recover=all']
        for p in includes:cmd+=['-I','/work/'+p]
        cmd+=['/frontend/s33_register_profile_observer.c','-Wl,--start-group']+['/work/build-gnu89/'+p for p in LIBS]+['-Wl,--end-group']+['-Wl,--wrap='+s for s in SYMBOLS]+['-lnsl','-lm','-o','/newout/observer']
        result=r.command('build_observer',cmd,timeout=90);assert result.returncode==0,result.stdout[-2000:]
        blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate']
        main=r.out/'payload0_mmap.bin';main.write_bytes(body);r.input_hashes[str(directory/info['file'])]=sha(directory/info['file'])
        windows=[(0x17a860,0x17a8a4),(0x17a8a4,0x17a8f8),(0x1786e8,0x178718),(0x179354,0x179388),(0x265214,0x26529c),(0x265f60,0x265fe8)]
        (r.out/'original_windows.txt').write_text('\n\n'.join(aligned_window(body,base,a,b) for a,b in windows))
        scenarios=[]
        for entry in [0x17a860,0x17a8a4]:
            for tag in [0,0xffff]:scenarios.append(dict(name=f'wrapper_{entry:x}_{tag:x}',entry=entry,tag=tag,kind='wrapper'))
        for entry,gate,target,bit in [(0x265214,0xfef0050,0xfef00e8,6),(0x265f60,0xfef0328,0xfef00f8,4)]:
            for active,newsp in [(False,False),(True,False),(True,True)]:scenarios.append(dict(name=f'vector_{entry:x}_{int(active)}_{int(newsp)}',entry=entry,gate=gate,target=target,bit=bit,active=active,newsp=newsp,kind='vector'))
        pairs=[]
        for s in scenarios:
            wrapper=s['kind']=='wrapper';asm='mov r9,sp\n'
            if wrapper:
                asm+='mov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r0,0x700400\nmov r1,0x35f0\nmov r2,0xa55a\n'
                asm+=f'mov r12,{s["entry"]:#x}\njl [r12]\ncmp r0,0\nbne fail\ncmp sp,r9\nbne fail\ncmp r13,0x13371337\nbne fail\ncmp r14,0x14471447\nbne fail\ncmp r15,0x15571557\nbne fail\n'
                cells={0xfef000c:s['tag']}
            else:
                # Seed only model storage; no real interrupt or physical vector base.
                asm+='mov r0,0x700800\nsr r0,[0x25]\nmov ilink,returned\n'
                asm+=f'mov r12,{s["entry"]:#x}\nj [r12]\nreturned:\n'
                asm+=('cmp sp,0x700f00\n' if s['active'] and s['newsp'] else 'cmp sp,r9\n')+'bne fail\n'
                cells={s['gate']:(1<<s['bit']) if s['active'] else 0,s['target']:0xa5a5}
            asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
            elf=compile_probe(r,s['name'],asm);traces=[];observed=None
            for enabled in [False,True]:
                name=s['name']+('_observed' if enabled else '_reference');r.observe=enabled
                options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
                ram=bytearray(b'\xa5'*0x1000)
                struct.pack_into('<I',ram,0x100+0x1c,0x700200);struct.pack_into('<I',ram,0x200+0x68,1)
                struct.pack_into('<H',ram,0x100+0x18,1);struct.pack_into('<H',ram,0x400,0xc35b)
                maps=[(0x700000,ram),(0x369348,struct.pack('<I',0x700100))]
                if not wrapper:
                    # Returned symbol address from this caller's disassembly.
                    listing=(r.out/(s['name']+'_disasm.log')).read_text()
                    returned=int(re.search(r'^([0-9a-f]+) <returned>:',listing,re.M)[1],16)
                    maps.append((0x423b00,struct.pack('<4I',returned,returned,0x700f00 if s['newsp'] else 0,0x700f00 if s['newsp'] else 0)))
                for address,data in maps:
                    f=r.out/f'{name}_ram_{address:x}.bin';f.write_bytes(data);fixtures[hex(address)]=dict(file=f.name,before=bytes(data).hex(),kind='synthetic_ram')
                    options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{address:#x},{len(data):#x}']
                for address,value in cells.items():
                    data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,address%8,value)
                    f=r.out/f'{name}_mmio_{address:x}.bin';f.write_bytes(data);fixtures[hex(address)]=dict(file=f.name,before=data.hex(),kind='modeled_mmio',seed=value)
                    options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{address:#x},2']
                r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}'+''.join(f',{a:#x}:{len(data):#x}' for a,data in maps)
                case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
                assert case['exit_code']==0 and case['fault'] is None,log[-4000:]
                assert 'S33_UNDEFINED' not in log and 'S33_AUX_UNKNOWN' not in log and 'runtime error:' not in log
                events=[json.loads(x) for x in re.findall(r'S33_MEM (\{[^\n]+)',log)];done=[e for e in events if e['stage']=='result']
                assert len(events)==2*len(done) and all(e['width_bytes']==2 for e in done)
                expected_events=1 if wrapper or not s['active'] else 3
                assert len(done)==(expected_events if enabled else 0),(name,done)
                for address,f in fixtures.items():
                    after=(r.out/f['file']).read_bytes();f['after']=after.hex()
                    if f['kind']=='modeled_mmio':
                        a=int(address,0);expected=0xa5a4 if not wrapper and s['active'] and a==s['target'] else f['seed']
                        assert struct.unpack_from('<H',after,a%8)[0]==expected
                        before=bytes.fromhex(f['before']);assert all(before[i]==after[i] for i in range(8) if i not in [a%8,a%8+1])
                after=bytes.fromhex(fixtures['0x700000']['after'])
                if wrapper:
                    expected=0x35f0 if s['entry']==0x17a860 else (0xc35b&~0x35f0)|(0x35f0&0xa55a)
                    assert struct.unpack_from('<H',after,0x400)[0]==expected and struct.unpack_from('<I',after,0x268)[0]==1
                elif s['active']:
                    at=0x24 if s['entry']==0x265214 else 0x2c;source=0x265210 if at==0x24 else 0x265f5c
                    word=struct.unpack_from('<I',body,source-base)[0];expected=((word&65535)<<16)|(word>>16)
                    assert struct.unpack_from('<I',after,0x800+at)[0]==expected
                assert main.read_bytes()==body
                case.update(scenario=s,completed_memory_events=done,observer_enabled=enabled,fixtures=fixtures,full_selected_path_completed=True)
                traces.append((r.out/(name+'.trace')).read_bytes())
                if enabled:observed=done
                print(name,'PASS',len(done),flush=True)
            assert traces[0]==traces[1];pairs.append(dict(scenario=s['name'],trace_identical=True,events=len(observed)))
        fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0
        r.results.update(status='PASS_REMAINING_DIRECT_MMIO_ORIGINAL_PATHS',pairs=pairs,windows=windows,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main),path=str(main)),hardware_access=False,gnu_modified=False,
          limits=['Synthetic caller, context RAM, MMIO seeds, vector base, saved stack and ilink; no real interrupt delivery or silicon verification.',
                  'Selected vector fallback paths return to a synthetic caller. This is not the full interrupt handler context-save/restore cycle.',
                  'FEF000C is only read in a fixed-count software delay; value+1 is not a demonstrated timing calibration.',
                  'Bit0 clear is software RMW only; W1C, IRQ acknowledgement, reset values and physical names are unknown.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
