#!/usr/bin/env python3
"""Execute original USB consumers with original event APIs and explicit nested notifications."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import disasm, u32


def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/AkeruUSB_RAM_Debug/Event_Consumer'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False);print('Evidence:',out,flush=True)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ('ProbeAkeruUSBEventConsumer.java','ProbeAkeruUSBTransfers.java','ProbeAkeruUSBDescriptors.java','ProbeStatusRead.java')]
    inputs={str(p):sha(p) for p in sources+[ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin']}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    result=dict(status='RUNNING',hardware_tested=False,installable=False)
    try:
        spans=[(0x1906b4,0x1907a4),(0x190824,0x1908dc),(0x1908dc,0x1909f4),
               (0x19199c,0x1919d0),(0x1910c4,0x19110e),(0x158c8c,0x158d04),
               (0x158d04,0x158e1e),(0x158e28,0x158e48),(0x23c758,0x23c8ac),(0x2c9994,0x2c9a28)]
        listing='\n'.join(disasm(a,b) for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
        for pc,token in {0x190834:';0x158d04',0x1909a4:';0x158d04',0x190868:'btst_s',
                         0x1909da:'btst_s',0x1919c6:';0x158cbc',0x158cd0:';0x23c758',
                         0x158db8:';0x23c938',0x2c9a04:'st'}.items():
            lines=[x for x in listing.splitlines() if re.match(rf'\s*{pc:x}:',x)]
            assert len(lines)==1 and token in lines[0],(hex(pc),lines)
        assert [u32(x) for x in (0x373308,0x37330c,0x373310,0x190b90,0x190b98)]==[0x45564e4c,0x2200001,2,0x2200001,0x2200341]
        with tempfile.TemporaryDirectory(prefix='s33-usb-event-consumer-') as td:
            tmp=Path(td)
            for i in (0,1):(tmp/f'p{i}.bin').write_bytes(payloads[i])
            cmd=[ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless',tmp,'usb',
                 '-import',tmp/'p0.bin','-loader','BinaryLoader','-loader-baseAddr','0xad800',
                 '-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',scripts,
                 '-postScript','ProbeAkeruUSBEventConsumer.java',out/'trace.txt',tmp/'p1.bin','-deleteProject']
            (out/'command.json').write_text(json.dumps([str(x) for x in cmd],indent=2)+'\n')
            p=subprocess.run([str(x) for x in cmd],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180)
            (out/'headless.log').write_text(p.stdout)
            assert p.returncode==0 and 'SCRIPT ERROR' not in p.stdout,p.stdout[-5000:]
        trace=(out/'trace.txt').read_text()
        assert trace.endswith('COMPLETE cases=8\n') and trace.count('PASS event-consumer ')==8
        for rx in ('tx','rx'):
            for auto in (0,1):
                for cause in ('completion','close'):
                    status='2200341' if cause=='close' and auto==0 else '0'
                    pattern=rf'^PASS event-consumer {rx} auto={auto} cause={cause} status={status} query=[0-9a-f]+ count=0 active=0 closes={2 if cause=="close" else 0} precancel={1 if cause=="close" and rx=="rx" else 0} steps=\d+$'
                    assert re.search(pattern,trace,re.M),pattern
        for name,digest in inputs.items():assert sha(Path(name))==digest,name
        result.update(status='PASS_ORIGINAL_CONSUMER_WITH_ORIGINAL_EVENT_AND_MODELED_NESTED_CALL',cases=8,
            cpu='Ghidra ARCompact P-code',source_hashes=inputs,payload_hashes={str(x['index']):x['sha256'] for x in blocks},
            trace_sha256=sha(out/'trace.txt'),original_static_windows=[(hex(a),hex(b)) for a,b in spans],
            assumptions=['Event record, kernel/current/ready task, empty event waiter ring and endpoint objects prepared in laboratory',
                         'Notification invoked as controlled nested C-ABI call at WAIT entry, with stack and callee-register checks; not physical IRQ delivery',
                         'Completion-only control publishes event bit directly; neither path transfers payload data'],
            boundaries=['Resource acquire/release, connected/halt predicate, cache registration/cleanup, class endpoint close/pre-cancel and logger are fixtures',
                        'Original class close, event SET/WAIT/query/CLEAR and original TX/RX consumers are executed for the injected path',
                        'RX uses timeout zero via prepared ninth argument; no blocking wait or timer expiry'],
            limits=['No boot, live scheduler, real endpoint/DMA/cache, USB transfer, interrupt context, physical RAM map, device installation or recovery',
                    'Auto-clear 1 and close timing are synthetic; do not infer hardware configuration or a real Nikon defect'])
    except Exception as exc:result.update(status='FAIL',error=repr(exc));raise
    finally:(out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n')
    print(trace,end='');print(result['status'],out,flush=True)


if __name__=='__main__':main()
