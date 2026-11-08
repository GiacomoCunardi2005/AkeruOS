#!/usr/bin/env python3
"""Run original direct MMIO sequence with explicit external fixture transitions."""
import json,re,struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha,IMAGE
from s33_verify_gnu_defined_memory import DefinedRunner,LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_register_memory_observer import LIBS,SYMBOLS


class StepRunner(DefinedRunner):
    def command(self,name,cmd,timeout=30):
        if '/engine/install/bin/arc-elf32-run'in cmd:
            cmd=list(cmd);cmd[cmd.index('/engine/install/bin/arc-elf32-run')]='/result/step_observer'
            envs={'S33_MEM_OBSERVER':str(int(self.observe)),'S33_MEM_HIGH':'1','S33_STEP_BUDGET':str(self.budget),
                  'S33_FIXTURE_COMPLETION':str(int(self.completion)),'S33_FIXTURE_REPEAT':str(int(self.repeat))}
            for key,value in envs.items():cmd[2:2]=['--env',key+'='+value]
        return super().command(name,cmd,timeout)


def main():
    r=StepRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='direct-mmio-sequence-external-fixtures'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB
        sources=[Path(__file__),Path(__file__).with_name('s33_register_memory_observer.c'),Path(__file__).with_name('s33_register_step_observer.c')]
        for p in sources+[BUILD,LAB/'install/bin/arc-elf32-run']+[LAB/'build-gnu89'/rel for rel in LIBS]:r.input_hashes[str(p)]=sha(p)
        for p in sources:(r.out/p.name).write_bytes(p.read_bytes())
        includes=['build-gnu89/sim/arc','build-gnu89/bfd','source/gnu-arc700-sim-src/include','source/gnu-arc700-sim-src/sim/arc','source/gnu-arc700-sim-src/sim/common','source/gnu-arc700-sim-src/opcodes']
        cmd=['podman','run','--rm','--network','none','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m',
             '-v',str(LAB)+':/work:ro','-v',str(sources[0].parent)+':/frontend:ro','-v',str(r.out)+':/newout:rw',IMAGE,
             'gcc','-std=gnu11','-fgnu89-inline','-O2','-g','-fsanitize=bounds','-fno-sanitize-recover=all']
        for p in includes:cmd+=['-I','/work/'+p]
        cmd+=['/frontend/s33_register_step_observer.c','-Wl,--start-group']+['/work/build-gnu89/'+p for p in LIBS]+['-Wl,--end-group']
        cmd+=['-Wl,--wrap='+s for s in SYMBOLS]+['-lnsl','-lm','-o','/newout/step_observer']
        result=r.command('build_step_observer',cmd,timeout=90);assert result.returncode==0,result.stdout[-2000:]
        r.input_hashes[str(r.out/'step_observer')]=sha(r.out/'step_observer')
        blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0);body=payloads[0];base=info['load_address_candidate']
        main=r.out/'payload0_mmap.bin';main.write_bytes(body);r.input_hashes[str(directory/info['file'])]=sha(directory/info['file'])
        listing=aligned_window(body,base,0x178d08,0x1792f8);assert '.word'not in listing and 'out of bounds'not in listing.lower()
        (r.out/'original_sequence_disassembly.txt').write_text(listing+'\n')
        addresses=sorted({int(a,16)for a in re.findall(r'(?:ldh|sth)\.di\s+\w+,\[(0x[0-9a-f]+)\]',listing)})
        assert len(addresses)==22,(len(addresses),list(map(hex,addresses)))
        scenarios=[('plain',0,None,True,False,0,2000),('script_high',1,0x2000,True,True,0,4000),
                   ('script_low',0,0x4000,True,True,0,4000),('no_completion',0,None,False,False,0,500),
                   ('cache_busy',0,None,False,False,0x100,80)]
        pairs=[]
        for scenario,mode,high,completion,repeat,dc,budget in scenarios:
            descriptor=r.out/(scenario+'_descriptor.bin');raw=struct.pack('<5I',0xfe20144,0xabcdef12,0xfe2013c,0x56789abc,0xffffffff)
            descriptor.write_bytes(raw);script_address=0x600000 if high is not None else 0
            asm=f'mov r9,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r0,{dc:#x}\nsr r0,[0x48]\n'
            args=[1,0x12345678,0x9abc,script_address,mode,0x2468,0x789a]
            asm+=''.join(f'mov r{i},{v:#x}\n'for i,v in enumerate(args))
            asm+='mov r12,0x178d08\njl [r12]\ncmp r0,1\nbne fail\ncmp sp,r9\nbne fail\ncmp r13,0x13371337\nbne fail\ncmp r14,0x14471447\nbne fail\ncmp r15,0x15571557\nbne fail\nmov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
            elf=compile_probe(r,scenario,asm);traces=[];records=[]
            for observe in [False,True]:
                name=scenario+('_observed'if observe else'_reference');r.observe=observe;r.completion=completion;r.repeat=repeat;r.budget=budget
                options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}']
                fixtures={};initial={}
                for i,address in enumerate(addresses):
                    value=0x4100+37*i
                    if address==0xfe2014c:value=0x17
                    if address==0xffe2014c:value=high or 0
                    cell=r.out/f'{name}_{address:08x}.bin';data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,address%8,value);cell.write_bytes(data)
                    fixtures[hex(address)]=dict(file=cell.name,before=data.hex(),value=value);initial[address]=value
                    options+=['--memory-mapfile','/result/'+cell.name,'--memory-region',f'{address:#x},2']
                if script_address:options+=['--memory-mapfile','/result/'+descriptor.name,'--memory-region',f'{script_address:#x},{len(raw):#x}']
                r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}'+(f',{script_address:#x}:{len(raw):#x}'if script_address else'')
                case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
                assert case['fault']is None and 'S33_AUX_UNKNOWN'not in log and 'runtime error:'not in log,log[-2000:]
                negative=scenario in ['no_completion','cache_busy'];assert case['exit_code']==(75 if negative else 0),log[-2000:]
                stop=json.loads(re.findall(r'S33_STEP_STOP (\{[^\n]+)',log)[-1]);assert stop['kind']==('budget'if negative else'terminal')
                transitions=[json.loads(x)for x in re.findall(r'S33_FIXTURE (\{[^\n]+)',log)]
                assert len(transitions)==(0 if negative else 3 if repeat else 1)
                events=[json.loads(x)for x in re.findall(r'S33_MEM (\{[^\n]+)',log)];completed=[e for e in events if e['stage']=='result']
                assert all(e['width_bytes']==2 for e in completed)
                assert len(events)==2*len(completed)
                if not observe:assert not events
                expected=dict(initial)
                if scenario!='cache_busy':
                    expected.update({0xffe40044:0,0xffe20024:300,0xfe20000:initial[0xfe20000]|(2 if negative else 6),
                                     0xfe20008:2 if negative else 4,0xfe80148:0,0xfe80040:initial[0xfe80040]&~0x8001,
                                     0xfe80144:initial[0xfe80144]&~4,0xfef0348:16,0xfe800f8:initial[0xfe800f8]&~0x100,
                                     0xfe80118:0x1234,0xfe8011c:0x5678,0xfe80120:0x9abc,0xfe20018:0x789a,
                                     0xfe20140:0,0xfe20144:0x80 if negative else 0x800,0xfe2013c:0x1115 if negative else 0x110a,
                                     0xfe20150:512,0xfe20154:115 if negative else 113})
                    if not negative:expected.update({0xffe2013c:0x1081,0xffe20150:512,0xffe2014c:0})
                for address in addresses:
                    f=fixtures[hex(address)];after=(r.out/f['file']).read_bytes();f['after']=after.hex()
                    assert struct.unpack_from('<H',after,address%8)[0]==expected[address],(scenario,hex(address),after.hex(),hex(expected[address]))
                    before=bytes.fromhex(f['before']);assert all(after[j]==before[j]for j in range(8)if j not in [address%8,address%8+1])
                if scenario=='cache_busy':assert not completed and stop['pc']in [0x178d18,0x178d1c,0x178d1e]
                if scenario=='no_completion':assert stop['pc']in [0x179098,0x1790a0,0x1790a4,0x1790a8,0x1790ac]
                assert main.read_bytes()==body and descriptor.read_bytes()==raw
                case.update(scenario=scenario,observer_enabled=observe,full_routine_completed=not negative,step_stop=stop,
                            fixtures=fixtures,fixture_transitions=transitions,completed_memory_events=completed,
                            synthetic_dc_ctrl=dc,arguments=list(map(hex,args)),expected_cells={hex(k):v for k,v in expected.items()})
                traces.append((r.out/(name+'.trace')).read_bytes());records.append(case)
                print(name,'PASS',case['exit_code'],case['instructions'],len(completed),flush=True)
            assert traces[0]==traces[1]
            pairs.append(dict(scenario=scenario,trace_identical=True,completed_events=len(records[1]['completed_memory_events'])))
        fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0
        r.results.update(status='PASS_DIRECT_MMIO_SEQUENCE_EXTERNAL_FIXTURES',pairs=pairs,
                         source_entry='0x178d08',source_end_exclusive='0x1792f8',addresses=list(map(hex,addresses)),
                         payloads={'0':dict(path=str(main),base=base,size=len(body),firmware_offset=offset,sha256=sha(main))},
                         hardware_access=False,gnu_modified=False,
                         limits=['External step frontend and declared fixture transitions; not peripheral timing or hardware execution.',
                                 'FE20008 bit4 is supplied before its poll. Repeat scenarios clear FFE2014C on the second pass. Host fixture writes are separate from guest accesses.',
                                 'DC_CTRL is seeded0 or100hex by the synthetic caller, not a Nikon reset value.',
                                 'Low FE and high FFE addresses are distinct modeled cells; physical aliasing unknown.',
                                 'Optional descriptor addresses/values are synthetic caller data and do not prove runtime Nikon tables.',
                                 'Three full scenarios and two budget-limited negative scenarios, each replayed with observer disabled/enabled.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
