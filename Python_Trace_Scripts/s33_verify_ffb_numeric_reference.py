#!/usr/bin/env python3
"""Independent integer reference for the 38 sampled FFB output values.

Positive dimensions only. Does not certify DSP hardware or all caller domains.
"""
import json
import shutil
import struct
from types import SimpleNamespace
from pathlib import Path
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_integrate_ffc7000_table_tail import load,save

PARENT=ROOT/'Risultati/Processor_Registers/20261025T201031Z'
REUSED=ROOT/'outputs/gnu_arc700/20261025T200821Z_064bd124'


def signed_divrem(n,d):
    assert d>0
    q=abs(n)//d
    if n<0:q=-q
    return q,n-q*d


def reference(fields):
    """Predict structure offsets without consulting traces or observed outputs."""
    assert len(fields)==15
    h=fields[:6];b=fields[6:]
    assert all(0<=x<=65535 for x in h) and all(0<=x<=255 for x in b)
    assert 0<h[0]<=32767 and 0<h[1]<=32767 and h[2]>0 and h[3]>0
    x=(h[2]+h[0]-1)//h[0];y=(h[3]+h[1]-1)//h[1]
    assert 0<x<=32767 and 0<y<=32767
    result={38:x,40:y}
    for i in range(8):
        q,r=signed_divrem(b[i]+1,x if i<4 else y)
        result[50+2*i]=q;result[66+2*i]=r
    for i in range(8):
        n=(b[i]+1) if i<4 else (b[i]+1-b[8] if i==4 else b[i]+1+b[8])
        q,r=signed_divrem(n,x if i<4 else y)
        result[82+2*i]=q;result[98+2*i]=r
    for i,(n,d) in enumerate([(h[4],x),(h[5],y)]):
        q,r=signed_divrem(n,d);result[118+2*i]=q;result[122+2*i]=r
    assert len(result)==38
    return {k:v&65535 for k,v in result.items()}


def main():
    ledger=load(PARENT/'sha256.json');assert all(sha(PARENT/k)==v for k,v in ledger.items())
    old=load(PARENT/'evidence/ffc3000_ffb_computed_audit.json');historical=[]
    for c in old['computed_output_provenance']:
        pred=reference(c['input_fields']);actual={x['structure_offset']:x['value'] for x in c['outputs']}
        assert pred==actual,(c['case'],pred,actual)
        historical.append(dict(case=c['case'],comparisons=38,match=True))
    r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ffb-independent-numeric-reference'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';r.experimental_engine=LAB
        assert sha(LAB/'install/bin/arc-elf32-run')==load(BUILD)['engine_sha256']
        assert sha(REUSED/'observer')==load(REUSED/'verified_evidence.json')['files']['observer']
        shutil.copy2(REUSED/'observer',r.out/'observer');shutil.copy2(Path(__file__),r.out/Path(__file__).name)
        for q in [Path(__file__),PARENT/'sha256.json',PARENT/'evidence/ffc3000_ffb_computed_audit.json',BUILD,LAB/'install/bin/arc-elf32-run',
            REUSED/'observer',REUSED/'verified_evidence.json']:
            r.input_hashes[str(q)]=sha(q)
        for n in ['s33_run_gnu_arc700','s33_verify_gnu_defined_memory','s33_verify_ff7_transfer_windows','s33_verify_gnu_dsp_lab',
            's33_trace_state_dispatch','s33_integrate_ffc7000_table_tail']:
            q=Path(__file__).with_name(n+'.py');r.input_hashes[str(q)]=sha(q)
        blocks,payloads,directory=verified_payloads(ROOT);body=payloads[0];base=blocks[0]['load_address_candidate']
        q=r.out/'payload0_mmap.bin';q.write_bytes(body);r.input_hashes[str(directory/blocks[0]['file'])]=sha(directory/blocks[0]['file'])
        fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();off=fw.find(body);assert off>=0 and fw.find(body,off+1)<0
        slots=[]
        for i in range(38):
            source=0x2e2a24+16*i;pc=source+12;a=struct.unpack_from('<I',body,pc-4-base)[0]
            # Offset is checked independently by the post-run audit against GNU.
            offset=old['computed_output_provenance'][0]['outputs'][i]['structure_offset']
            slots.append(dict(source_pc=source,store_pc=pc,address=a,structure_offset=offset))
        assert {s['address'] for s in slots}==set(range(0xffb9f2c,0xffb9fc4,4))
        inputs=[
            [7,11,20,32,65535,65534,0,1,2,3,0,1,2,3,255],
            [1,1,32767,32767,65535,65535,255,254,253,252,0,1,2,3,255],
            [32767,32767,65535,65535,65535,0,0,1,127,255,0,127,128,255,255],
            [3,5,4,6,65535,12345,1,2,3,4,0,1,2,3,254],
            [17,19,16,18,0,65535,255,0,255,0,0,0,255,255,255],
            [100,101,101,102,500,501,0,0,0,0,0,0,0,0,0],
            [13,17,130,170,27,37,9,19,29,39,0,1,2,3,23],
            [101,103,1000,1001,1234,5678,1,17,33,65,0,1,3,7,31],
        ]
        pairs=[]
        for number,fields in enumerate(inputs):
            pred=reference(fields);name=f'math_{number}';raw=struct.pack('<6H9B',*fields)
            inp=r.out/(name+'_input.bin');inp.write_bytes(raw)
            asm='mov r20,sp\n'+''.join(f'mov r{i},{i*0x01100110:#x}\n' for i in range(13,20))
            asm+='mov r0,0x700000\nmov r12,0x2e29b4\njl [r12]\ncmp sp,r20\nbne fail\n'
            asm+=''.join(f'cmp r{i},{i*0x01100110:#x}\nbne fail\n' for i in range(13,20))
            asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
            elf=compile_probe(r,name,asm);traces=[]
            for observed in [False,True]:
                run=name+('_observed' if observed else '_reference');r.observe=observed;fixtures={}
                options=['--memory-mapfile','/result/payload0_mmap.bin','--memory-region',f'{base:#x},{len(body):#x}',
                    '--memory-mapfile','/result/'+inp.name,'--memory-region',f'0x700000,{len(raw):#x}']
                for s in slots:
                    a=s['address'];buf=r.out/f'{run}_{a:x}.bin';buf.write_bytes(b'\xa5'*8);fixtures[hex(a)]=dict(file=buf.name,before=('a5'*8))
                    options+=['--memory-mapfile','/result/'+buf.name,'--memory-region',f'{a:#x},2']
                r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x},0x700000:{len(raw):#x}'
                case,log=r.run(run,'/result/'+elf.name,options,trace=True,extract=True)
                assert case['exit_code']==0 and case['fault'] is None,(run,log[-3000:])
                assert not any(x in log for x in ['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
                ev=[json.loads(x.removeprefix('S33_MEM ')) for x in (r.out/(run+'.stderr.log')).read_text().splitlines() if x.startswith('S33_MEM ')]
                done=[x for x in ev if x['stage']=='result'];assert len(ev)==2*len(done)
                expected=[(s['store_pc'],'write',s['address'],pred[s['structure_offset']]) for s in slots]
                assert [(e['pc'],e['operation'],e['address'],e['value']) for e in done]==(expected if observed else [])
                for s in slots:
                    f=fixtures[hex(s['address'])];after=(r.out/f['file']).read_bytes();offset=s['address']%8
                    assert struct.unpack_from('<H',after,offset)[0]==pred[s['structure_offset']]
                    assert all(after[j]==0xa5 for j in range(8) if j not in [offset,offset+1]);f['after']=after.hex()
                assert inp.read_bytes()==raw and q.read_bytes()==body
                case.update(fields=fields,predicted_output_by_offset=pred,observer_enabled=observed,fixtures=fixtures,completed_memory_events=done,input_file=inp.name)
                traces.append((r.out/(run+'.trace')).read_bytes());print(run,'PASS',len(done),'events',flush=True)
            assert traces[0]==traces[1];pairs.append(dict(name=name,trace_identical=True,comparisons=38))
        assert all(sha(PARENT/k)==v for k,v in ledger.items())
        r.results.update(status='PASS_FFB_INDEPENDENT_INTEGER_REFERENCE_SAMPLES',parent_atlas=str(PARENT),historical_checks=historical,pairs=pairs,slots=slots,
            payload=dict(base=base,path=str(q),sha256=sha(q),firmware_offset=off,size=len(body)),hardware_access=False,gnu_modified=False,
            independent_mathematical_reference=True,full_mathematics_domain_proven=False,physical_DSP_semantics_proven=False,
            limits=['38outputs compared for4old+8newselectedinputs only;not alllegalNikoninputs orzero/negative/nonfinite domains.',
                'Ceilingratios andsignedquotient/remainder are integer reference hypotheses checked against originalCPUsoftware routines.',
                'GNU DSP remainsprovisional;nohardwaremeaning,fullinstructionsemantics,physicalreset,permissions,IRQ ortimingclaim.',
                'No newregisteraddresses andno scalaradmissions from38-cellwindow.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
