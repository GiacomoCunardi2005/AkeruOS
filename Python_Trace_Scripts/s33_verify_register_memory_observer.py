#!/usr/bin/env python3
"""Replay recorded offline probes with external, delegating libsim memory observers.

The original engine/lab/result inputs are mounted read-only. Mapfiles are copied
to a new laboratory output because sim_open requires writable mapfile handles.
Exact trace equality checks that the instrumented frontend preserved each run.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
IMAGE='localhost/arc700-legacy:gcc10'
LIBS=['sim/arc/libsim.a','bfd/libbfd.a','opcodes/libopcodes.a','libiberty/libiberty.a']
SYMBOLS=['sim_core_'+direction+'_'+alignment+'_'+str(width)
         for direction in ['read','write']
         for alignment,width in [('aligned',1),('unaligned',2),('unaligned',4)]]


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--engine',type=Path,required=True)
    parser.add_argument('--cases',required=True,help='Comma-separated recorded case names')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args();source=args.source.resolve();engine=args.engine.resolve()
    out=args.output or ROOT/'Risultati/Processor_Registers'/('observer_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out=out.resolve();out.mkdir(parents=True,exist_ok=False)
    inputs={str(p):sha(p)for p in [Path(__file__),Path(__file__).with_suffix('.c')] if p.exists()}
    c_source=ROOT/'Python_Trace_Scripts/s33_register_memory_observer.c'
    inputs[str(c_source)]=sha(c_source)
    for rel in LIBS:
        path=engine/'build-gnu89'/rel;inputs[str(path)]=sha(path)
    includes=['/work/build-gnu89/sim/arc','/work/build-gnu89/bfd',
              '/work/source/gnu-arc700-sim-src/include','/work/source/gnu-arc700-sim-src/sim/arc',
              '/work/source/gnu-arc700-sim-src/sim/common','/work/source/gnu-arc700-sim-src/opcodes']
    build=['podman','run','--rm','--network','none','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m',
           '-v',str(engine)+':/work:ro','-v',str(c_source.parent)+':/frontend:ro',
           '-v',str(out)+':/newout:rw',IMAGE,'gcc','-std=gnu11','-fgnu89-inline','-O2','-g',
           '-fsanitize=bounds','-fno-sanitize-recover=all']
    for inc in includes:build+=['-I',inc]
    build+=['/frontend/'+c_source.name,'-Wl,--start-group']+['/work/build-gnu89/'+x for x in LIBS]+['-Wl,--end-group']
    build+=['-Wl,--wrap='+x for x in SYMBOLS]+['-lnsl','-lm','-o','/newout/observer']
    (out/'build.command.json').write_text(json.dumps(build,indent=2)+'\n')
    result=subprocess.run(build,capture_output=True,text=True,timeout=90)
    (out/'build.log').write_text(result.stdout+result.stderr);assert result.returncode==0,result.stderr[-2000:]
    original_manifest=source/'verified_evidence.json'
    source_cases={}
    payload_initial={}
    if original_manifest.exists():
        inputs[str(original_manifest)]=sha(original_manifest)
        original_data=json.loads(original_manifest.read_text())
        source_cases={case['name']:case for case in original_data.get('cases',[])}
        # Some original routines write ordinary initialized data in payloads.
        # Their retained mmap files can therefore be final snapshots. Recreate
        # declared initial payload bytes from the independently hashed container.
        if original_data.get('payloads'):
            firmware=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin'
            inputs[str(firmware)]=sha(firmware)
            assert inputs[str(firmware)]==original_data['firmware_sha256']
            body=firmware.read_bytes()
            for payload in original_data['payloads'].values():
                start=payload['firmware_offset'];initial=body[start:start+payload['size']]
                assert hashlib.sha256(initial).hexdigest()==payload['sha256']
                payload_initial[Path(payload['path']).name]=initial
    cases=[]
    for name in args.cases.split(','):
        command_file=source/(name+'.command.json');inputs[str(command_file)]=sha(command_file)
        command=json.loads(command_file.read_text());assert command[:2]==['podman','run']
        assert IMAGE in command and '--network' in command
        expected_engine=str(engine)+':/engine:ro'
        assert expected_engine in command,'Replay engine differs from recorded command'
        assert str(source)+':/result:rw' in command
        command=[x.replace(str(source)+':/result:rw',str(source)+':/result:ro') for x in command]
        command[2:2]=['--volume',str(out)+':/newout:rw']
        fixture_initial={cell['file']:cell['before'] for cell in source_cases.get(name,{}).get('fixtures',{}).values()}
        restored_initial=[];restored_payloads=[]
        for i,word in enumerate(command):
            if word=='--memory-mapfile':
                old=command[i+1];assert old.startswith('/result/')
                path=source/old.removeprefix('/result/');inputs[str(path)]=sha(path)
                # Distinct copy per run preserves the original fixture initial state.
                dest=out/(name+'_'+path.name);shutil.copyfile(path,dest)
                if path.name in payload_initial:
                    dest.write_bytes(payload_initial[path.name]);restored_payloads.append(path.name)
                if path.name in fixture_initial:
                    # The retained source mapfile may contain the earlier run's
                    # final value. Restore the independently recorded host input,
                    # never a value inferred from the trace being compared.
                    before=bytes.fromhex(fixture_initial[path.name]);assert len(before)==dest.stat().st_size
                    dest.write_bytes(before);restored_initial.append(path.name)
                command[i+1]='/newout/'+dest.name
        elf=command[-1];assert elf.startswith('/result/')
        elf_path=source/elf.removeprefix('/result/');inputs[str(elf_path)]=sha(elf_path)
        trace_path=source/(name+'.trace');inputs[str(trace_path)]=sha(trace_path)
        old_trace='--trace-file=/result/'+name+'.trace';assert old_trace in command
        command[command.index(old_trace)]='--trace-file=/newout/'+name+'.trace'
        command[command.index('/engine/install/bin/arc-elf32-run')]='/newout/observer'
        (out/(name+'.command.json')).write_text(json.dumps(command,indent=2)+'\n')
        result=subprocess.run(command,capture_output=True,text=True,timeout=30)
        (out/(name+'.log')).write_text(result.stdout+result.stderr)
        events=[json.loads(line.removeprefix('S33_MEM ')) for line in result.stderr.splitlines() if line.startswith('S33_MEM ')]
        stop=re.search(r'S33_OBSERVER_STOP reason=(\d+) code=(\d+) observed=(\d+)',result.stderr)
        assert stop,'Observer failed to reach sim_stop_reason'
        assert (out/(name+'.trace')).read_bytes()==trace_path.read_bytes(),'Guest trace changed'
        begins={};completed=[]
        for event in events:
            if event['stage']=='begin':
                assert event['id'] not in begins;begins[event['id']]=event
            else:
                before=begins[event['id']]
                assert all(before[k]==event[k]for k in ['pc','address','width_bytes','operation'])
                completed.append(event)
        successful={e['id']for e in completed};attempts=[e for i,e in begins.items()if i not in successful]
        cases.append(dict(name=name,exit_code=result.returncode,stop_reason=int(stop[1]),stop_code=int(stop[2]),
                          trace_identical=True,restored_fixture_inputs=restored_initial,
                          restored_payload_inputs=restored_payloads,
                          events=events,completed=completed,attempts_without_result=attempts))
        print(name,'completed',len(completed),'attempted-only',len(attempts),'trace-identical',flush=True)
    assert all(sha(Path(path))==digest for path,digest in inputs.items()),'An original input changed'
    manifest=dict(status='PASS_DELEGATING_MEMORY_OBSERVER',source=str(source),engine=str(engine),
                  cases=cases,input_sha256=inputs,observer_sha256=sha(out/'observer'),gnu_modified=False,
                  scope='Core memory calls: read aligned1/unaligned2/unaligned4 and corresponding writes; address0F000000..0FFFFFFF.',
                  limits=['Begin without result is an attempted transfer, not a completed read/write.',
                          'Write result means the existing accessor returned, not physical persistence.',
                          'Read begin.value is a placeholder and not an observed register value.',
                          'No DMA, device-internal transfers, other widths or bypassed helper callbacks are observed.',
                          'Fixtures and all probe inputs remain laboratory data, not physical device responses.'])
    (out/'verified_evidence.json').write_text(json.dumps(manifest,indent=2)+'\n')
    shutil.copyfile(c_source,out/c_source.name);shutil.copyfile(Path(__file__),out/Path(__file__).name)
    print('Evidence:',out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
