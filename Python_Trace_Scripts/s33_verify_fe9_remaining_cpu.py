#!/usr/bin/env python3
"""Execute original FE9 wrappers at newly witnessed indices; GNU stays read-only."""
import argparse
import json
import shutil
import struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, sha
from s33_verify_gnu_defined_memory import LAB, BUILD, known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_integrate_ffc7000_table_tail import load

REUSED = ROOT/'outputs/gnu_arc700/20261025T192726Z_57e5a91c'


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('static',type=Path)
    source = ap.parse_args().static.resolve(); static = load(source/'verified_evidence.json')
    assert static['status'] == 'PASS_FE9_SEVEN_LOCAL_CALLER_WITNESSES_STATIC'
    assert all(sha(Path(k)) == v for k,v in static['input_sha256'].items())
    assert all(sha(source/k) == v for k,v in load(source/'sha256.json').items())
    r = SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='fe9-remaining-original-indices'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare(); r.known_ranges = ''; r.experimental_engine = LAB
        assert sha(LAB/'install/bin/arc-elf32-run') == load(BUILD)['engine_sha256']
        assert sha(REUSED/'observer') == load(REUSED/'verified_evidence.json')['files']['observer']
        shutil.copy2(REUSED/'observer',r.out/'observer'); shutil.copy2(Path(__file__),r.out/Path(__file__).name)
        r.input_hashes.update(static['input_sha256'])
        for q in [Path(__file__),source/'verified_evidence.json',source/'sha256.json',BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:
            r.input_hashes[str(q)] = sha(q)
        for name in ['s33_verify_ff7_transfer_windows','s33_verify_gnu_defined_memory','s33_verify_gnu_dsp_lab','s33_run_gnu_arc700']:
            q = Path(__file__).with_name(name+'.py');r.input_hashes[str(q)] = sha(q)
        blocks,payloads,directory = verified_payloads(ROOT); mappings = []
        firmware = (ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()
        for i in [0,1]:
            q = r.out/f'payload{i}_mmap.bin'; q.write_bytes(payloads[i]); offset = firmware.find(payloads[i])
            assert offset >= 0 and firmware.find(payloads[i],offset+1)<0
            mappings.append(dict(index=i,base=blocks[i]['load_address_candidate'],size=len(payloads[i]),path=str(q),sha256=sha(q),firmware_offset=offset))
        pairs = []; groups = {}; sentinels = {i:i*0x01100110 for i in range(13,20)}
        for pattern,(seed,value) in enumerate([(0,0xffffffff),(0xffff,0x12345678)]):
            for channel in [0,1,2,0xffffffff]:
                bank = int(channel!=0); scenario = f'remaining_{pattern}_{channel:x}'
                state = {}; initial = {}; events = []; calls = []
                asm = 'mov r20,sp\n'+''.join(f'mov r{i},{v:#x}\n' for i,v in sentinels.items())
                for selection in static['new_index_table_selections']:
                    if selection['bank'] != bank: continue
                    entry,index,address,mask = int(selection['wrapper'],0),selection['index'],int(selection['address'],0),int(selection['mask'],0)
                    helper = (0x3098b8 if entry==0x2ee760 else 0x309944) if not bank else (0x309ad0 if entry==0x2ee760 else 0x309b88)
                    old = state.setdefault(address,(seed^(address>>2))&0xffff);initial.setdefault(address,old)
                    shift = (mask&-mask).bit_length()-1
                    new = ((old&~mask)|((value<<shift)&mask))&0xffff
                    ev = [(helper+12,'read',address,old),(helper+34,'write',address,new)]
                    events.extend(ev); state[address] = new
                    asm += f'mov r0,{index:#x}\nmov r1,{value:#x}\nmov r2,{channel:#x}\nmov r12,{entry:#x}\njl [r12]\n'
                    asm += 'cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{v:#x}\nbne fail\n' for i,v in sentinels.items())
                    calls.append(dict(entry=hex(entry),index=index,channel=channel,value=value,selection=selection,events=ev))
                assert len(calls)==4
                asm += 'mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
                elf = compile_probe(r,scenario,asm); traces=[]
                for enabled in [False,True]:
                    name=scenario+('_observed' if enabled else '_reference');r.observe=enabled;options=[];fixtures={}
                    for m in mappings: options += ['--memory-mapfile','/result/'+Path(m['path']).name,'--memory-region',f"{m['base']:#x},{m['size']:#x}"]
                    for address in sorted(state):
                        before=bytearray(b'\xa5'*8);struct.pack_into('<H',before,address%8,initial[address])
                        q=r.out/f'{name}_{address:x}.bin';q.write_bytes(before);fixtures[hex(address)]=dict(file=q.name,before=before.hex())
                        options += ['--memory-mapfile','/result/'+q.name,'--memory-region',f'{address:#x},2']
                    r.range_override=known_sections(elf,False)+''.join(f",{m['base']:#x}:{m['size']:#x}" for m in mappings)
                    case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
                    assert case['exit_code']==0 and case['fault'] is None,log[-4000:]
                    assert not any(x in log for x in ['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
                    raw=[json.loads(line.removeprefix('S33_MEM ')) for line in (r.out/(name+'.stderr.log')).read_text().splitlines() if line.startswith('S33_MEM ')]
                    completed=[e for e in raw if e['stage']=='result']
                    assert len(raw)==2*len(completed) and all(e['width_bytes']==2 for e in raw)
                    assert [(e['pc'],e['operation'],e['address'],e['value']) for e in completed] == (events if enabled else [])
                    for b,e in zip(raw[::2],raw[1::2]):
                        assert b['stage']=='begin' and e['stage']=='result' and all(b[k]==e[k] for k in ['id','pc','operation','address'])
                    for key,f in fixtures.items():
                        a=int(key,0);before=bytes.fromhex(f['before']);after=(r.out/f['file']).read_bytes();off=a%8
                        assert struct.unpack_from('<H',after,off)[0]==state[a]
                        assert all(before[j]==after[j] for j in range(8) if j not in [off,off+1]);f['after']=after.hex()
                    assert all(Path(m['path']).read_bytes()==payloads[m['index']] for m in mappings)
                    trace=(r.out/(name+'.trace')).read_bytes();traces.append(trace)
                    case.update(scenario=scenario,pattern=pattern,seed=seed,value=value,channel=channel,bank=bank,observer_enabled=enabled,
                        calls=calls,completed_memory_events=completed,fixtures=fixtures,original_calls_completed=True)
                    print(name,'PASS',len(completed),'events',flush=True)
                assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,trace_identical=True,events=len(events)))
                groups[(pattern,channel)]=events
        for pattern in range(2):
            assert groups[(pattern,1)]==groups[(pattern,2)]==groups[(pattern,0xffffffff)]
        r.results.update(status='PASS_FE9_REMAINING_ORIGINAL_INDICES',static_evidence=str(source/'verified_evidence.json'),payloads=mappings,
            pairs=pairs,capture_streams_separate=True,channel_equivalences=4,
            metamorphic_scope='Only channel changes1→2/FFFFFFFF;index,seed,value,harness andoriginal bytes unchanged;MMIO sequences compared,not whole traces across channels.',
            hardware_access=False,gnu_modified=False,global_reachability_proven=False,
            limits=['New indices executed through full original wrappers/helpers against original tables;original callers not executed.',
                'Stack,seeds,value,channel andMMIO backing are fixtures;physical meanings/reset/permissions/IRQ/timing unknown.',
                'IndirectJL localtarget depends onr14 preservation;wrapper preservation is tested for these fixtures only.',
                'No evidence that allprocessor registers orall legalindexdomains are known.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
