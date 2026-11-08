#!/usr/bin/env python3
"""Execute original upper USB transfer bodies with explicit event/controller boundaries."""
from datetime import datetime, timezone
from pathlib import Path
import json,re,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import raw,u32,disasm,sha
from s33_trace_state_dispatch import verified_payloads


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/AkeruUSB_RAM_Debug/Transfers'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False);print('Evidence:',out,flush=True)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeAkeruUSBTransfers.java','ProbeAkeruUSBDescriptors.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    spans=[(0x1906B4,0x1907A4),(0x190824,0x1908DC),(0x1908DC,0x1909F4),(0x190528,0x190538)]
    listing=''.join(disasm(a,b) for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x1906BC:'r17,r1',0x1906C0:'r18,r2',0x190788:'[sp,0x2c]',
        0x190834:';0x158d04',0x190856:'[r19]',0x190888:'[r0,8]',
        0x19096E:'[r14]',0x19097E:'[r14,16]',0x1909A4:';0x158d04',
        0x1909AE:';0x1909e4',0x1909C8:'[r19]',0x1909E0:'[r14,16]'}
    for pc,token in checks.items():
        line=next(line for line in listing.splitlines() if re.match(rf'\s*{pc:x}:',line));assert token in line,(hex(pc),line)
    constants={hex(a):hex(u32(a)) for a in [0x1907D8,0x1907DC,0x1907EC,0x190818,0x19081C,0x190B90,0x190BA4]}
    assert u32(0x1907EC)==0x423C00 and u32(0x1907DC)==0x368114 and u32(0x190818)==u32(0x190BA4)==0x2200005
    with tempfile.TemporaryDirectory(prefix='s33-usb-transfers-') as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless',temp,'usb',
            '-import',temp/'p0.bin','-loader','BinaryLoader','-loader-baseAddr','0xad800',
            '-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',scripts,
            '-postScript','ProbeAkeruUSBTransfers.java',out/'trace.txt',temp/'p1.bin','-deleteProject']
        (out/'command.json').write_text(json.dumps([str(x) for x in cmd],indent=2)+'\n')
        r=subprocess.run([str(x) for x in cmd],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180)
        (out/'headless.log').write_text(r.stdout);assert r.returncode==0 and 'SCRIPT ERROR' not in r.stdout,r.stdout[-6000:]
    trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=35\n') and trace.count('PASS usb-transfer ')==35
    assert all(sha((ROOT/p).read_bytes())==v for p,v in inputs.items())
    result=dict(status='PASS_ORIGINAL_UPPER_USB_TRANSFER_CONTRACT_WITH_DECLARED_BOUNDARIES',cpu_cases=35,
        sources=inputs,gnu_windows=len(spans),instruction_checks=len(checks),constants=constants,
        payload_hashes={str(b['index']):b['sha256'] for b in blocks},trace=trace,hardware_tested=False,installable=False,
        limits=['Original1908DC/1906B4 and190528 bodies executed; no payload bytes transferred',
            'Controller connected/halt/pre-receive/cancel, critical, buffer registration/cleanup, resource and RTOS events are explicit fixtures',
            'Completion counts/event bits are injected, including impossible oversized counts to test upper validation',
            'Wait-error receive cancel1905D8 is a boundary; active flag observations do not prove actual controller cancellation or DMA lifetime',
            'No original USB worker, IRQ, endpoint controller/DMA, actual timeout scheduling, device enumeration or RAM service; NON_INSTALLARE'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print(trace,end='');print(out)


if __name__=='__main__':main()
