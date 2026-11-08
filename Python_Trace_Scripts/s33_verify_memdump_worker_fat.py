#!/usr/bin/env python3
"""Run the candidate's task against original Nikon file code and synthetic FAT."""
from datetime import datetime, timezone
from pathlib import Path
import json
import re
import subprocess
import tempfile
import sys
from s33_trace_state_dispatch import verified_payloads
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS


def main():
    _,payloads,_=verified_payloads(ROOT)
    bundle=ROOT/'Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261106T142642215902Z'
    firmware=bundle/'firmware.bin';package=firmware.read_bytes();manifest=json.loads((bundle/'delta.json').read_text())
    import hashlib
    assert hashlib.sha256(package).hexdigest()==manifest['candidate_sha256']
    import struct
    tbm=struct.unpack_from('<I',package,0x480ac)[0];b=BS[9];resource=package[tbm+b['offset']:tbm+b['offset']+b['size']]
    symbols=(bundle/'payload_symbols.log').read_text();match=re.search(r'^([0-9a-f]+)\s+t\s+memdump_task$',symbols,re.M);assert match
    entry=int(match[1],16)
    out=ROOT/'Risultati/Runtime_Kernel/MEMDUMP_Worker_FAT'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ');out.mkdir(parents=True)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts';(out/'probe_snapshot.java').write_bytes((scripts/'ProbeMemdumpWorkerFat.java').read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-worker-fat-') as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        (temp/'resource.bin').write_bytes(resource)
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'model','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeMemdumpWorkerFat.java',str(out/'trace.txt'),str(temp/'p1.bin'),str(temp/'resource.bin'),hex(entry),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n');print('Prove:',out,flush=True)
        p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=300);(out/'headless.log').write_text(p.stdout)
        assert p.returncode==0 and 'SCRIPT ERROR' not in p.stdout,p.stdout[-6000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=2\n'),trace
    print(trace,flush=True)


if __name__=='__main__':main()
