#!/usr/bin/env python3
"""Re-decode AUX sites at GNU trace PCs, preserving original ELF/firmware bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from s33_inventory_processor_registers import ROOT, aux_names, scan_listing
from s33_run_gnu_arc700 import elf_loads


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    args=parser.parse_args();out=args.directory.resolve()
    trace_path=out/'evidence/firmware_aux_trace.json'
    trace=json.loads(trace_path.read_text())
    original=Path(trace['firmware_path']);firmware=original.read_bytes()
    assert hashlib.sha256(firmware).hexdigest()==trace['firmware_sha256']
    tool=ROOT/'work/build-arc/binutils/objdump'
    before={str(p):sha(p)for p in [original,tool,trace_path,Path(__file__)]}
    names,_,_=aux_names();checks=[];listings=[]
    for run in trace['runs']:
        elf=Path(run['elf']);assert sha(elf)==run['elf_sha256'];before[str(elf)]=sha(elf)
        _,segments=elf_loads(elf)
        if not segments:
            # Analysis ELF from objcopy has sections but no PT_LOAD. The runtime
            # uses the original mmap payload, so independently extract and bind
            # the analysis section to those same original firmware bytes.
            assert run.get('elf_role')=='source_mmap_ELF_for_static_verification'
            info=run['runtime_original_code_mmap'];payload=Path(info['path'])
            assert sha(payload)==info['sha256'];before[str(payload)]=sha(payload)
            with tempfile.TemporaryDirectory(prefix='s33-aux-source-') as td:
                binary=Path(td)/'text.bin'
                subprocess.run([str(ROOT/'work/build-arc/binutils/objcopy'),'-O','binary',
                                '--only-section=.text',str(elf),str(binary)],check=True,capture_output=True)
                data=binary.read_bytes()
            assert data==payload.read_bytes()
            assert data==firmware[info['firmware_offset']:info['firmware_offset']+info['size']]
            segments=[dict(address=info['base'],file_size=len(data),data=data)]
        sites={event['pc']:event for event in run['semantic_result_observed_records']}
        for pc,event in sorted(sites.items()):
            segment=next(s for s in segments if s['address']<=pc and pc+8<=s['address']+s['file_size'])
            actual=segment['data'][pc-segment['address']:pc-segment['address']+8]
            assert actual==firmware[event['firmware_offset']:event['firmware_offset']+8]
            cmd=[str(tool),'-d','-m','arc:ARC700','-EL',f'--start-address={pc:#x}',f'--stop-address={pc+8:#x}',str(elf)]
            result=subprocess.run(cmd,check=True,capture_output=True,text=True)
            accesses,_,_=scan_listing(result.stdout,run['name'],names)
            first=next(row for row in accesses if int(row['pc'],16)==pc)
            assert first['index']==event['aux_index'],(event,first)
            assert first['operation']==event['operation'],(event,first)
            checks.append(dict(run=run['name'],pc=hex(pc),aux_index=first['index'],
                               operation=first['operation'],listing=first['listing'],
                               source_firmware_offset=hex(event['firmware_offset']),
                               original_bytes_next8=actual.hex(),classification='trace_anchored_static_decode'))
            listings.append(run['name']+' '+hex(pc)+'\n'+result.stdout)
    assert all(sha(Path(p))==value for p,value in before.items())
    manifest=dict(status='PASS_TRACE_ANCHORED_AUX_SITES',checks=checks,
                  input_sha256=before,hardware_access=False,
                  limits=['Trace PCs anchor decoding but do not prove physical implementation or full retirement.',
                          'Only the first instruction at each trace PC is admitted from each window.'])
    (out/'aux_trace_site_verification.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (out/'aux_trace_site_disassembly.txt').write_text('\n'.join(listings))
    print('PASS',len(checks),'trace-anchored AUX sites')


if __name__=='__main__':main()
