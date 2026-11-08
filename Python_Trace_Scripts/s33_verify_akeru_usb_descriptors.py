#!/usr/bin/env python3
"""Original USB descriptors and fixed-layout consumer evidence; never opens USB hardware."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, struct, subprocess, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, raw, disasm, sha
from s33_trace_state_dispatch import verified_payloads


def descriptors(data):
    assert data[:2]==b'\x09\x02' and int.from_bytes(data[2:4],'little')==len(data)
    records=[];at=0
    while at<len(data):
        size=data[at];assert size>=2 and at+size<=len(data)
        records.append(dict(offset=at,type=data[at+1],bytes=data[at:at+size].hex()));at+=size
    assert at==len(data)
    interfaces=[r for r in records if r['type']==4]
    assert len(interfaces)==data[4]==1 and interfaces[0]['offset']==9
    endpoints=[r for r in records if r['type']==5]
    assert len(endpoints)==data[13] and [r['offset'] for r in endpoints]==[18+7*i for i in range(len(endpoints))]
    return dict(raw=data.hex(),interface_class=data[14],subclass=data[15],protocol=data[16],
        interfaces=len(interfaces),endpoints=[dict(address=data[r['offset']+2],type=data[r['offset']+3]&3,
            max_packet=int.from_bytes(data[r['offset']+4:r['offset']+6],'little')) for r in endpoints],records=records)


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/AkeruUSB_RAM_Debug/Descriptors'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False);print('Evidence:',out,flush=True)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__),scripts/'ProbeAkeruUSBDescriptors.java',scripts/'ProbeStatusRead.java']
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    templates={name:descriptors(raw(address,length)) for name,address,length in [('ptp',0x3900F0,39),('msdc',0x3901B0,32)]}
    assert [(e['address'],e['type'],e['max_packet']) for e in templates['msdc']['endpoints']]==[(0x81,2,64),(2,2,64)]
    assert [(e['address'],e['type'],e['max_packet']) for e in templates['ptp']['endpoints']]==[(0x81,2,512),(2,2,512),(0x83,3,8)]
    spans=[(0x190C3C,0x190C7A),(0x191110,0x191150),(0x19127A,0x19133A),
        (0x19133C,0x191378),(0x191378,0x1913CC),(0x1913CC,0x191440),
        (0x191490,0x191570),(0x191570,0x1915B4),(0x1916D6,0x1916F2),(0x19177C,0x1917A2),
        (0x1917F8,0x191838),(0x1392CC,0x1392FA),(0x1393DE,0x13940E)]
    listing=''.join(disasm(a,b) for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x191128:'[r1,13]',0x19112C:'r17,r1,0x12',0x191130:'r19,r1,0x20',
        0x191134:'r16,r1,0x19',0x191322:'[r0,0xe]',0x1912EC:'r20,0x2',
        0x1913B2:'[r5,13]',0x1913BC:'r2,r1,0x3',0x1913BE:'r2,r2,r1',
        0x1913C4:'[r0,0x15]',0x191416:'[r0,0x16]',0x191436:'r0,0x2',
        0x191598:'r2,0x9',0x19177C:'[pcl,0xd4]',0x191832:';0x191110',
        0x1392E6:'r15,0x6',0x1392F2:';0x1393de',0x1393DE:'r0,0x1e',0x1393F4:';0x81dc38'}
    for pc,token in checks.items():
        line=next(line for line in listing.splitlines() if re.match(rf'\s*{pc:x}:',line));assert token in line,(hex(pc),line)
    request_targets=[0x1915B4+2*x for x in struct.unpack('<9h',raw(0x1915B4,18))]
    descriptor_targets=[0x1916F2+2*x for x in struct.unpack('<8h',raw(0x1916F2,16))]
    assert request_targets[6]==0x1916DA and descriptor_targets[2]==0x19177C
    with tempfile.TemporaryDirectory(prefix='s33-usb-descriptors-') as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        for name in templates:(temp/(name+'.bin')).write_bytes(bytes.fromhex(templates[name]['raw']))
        cmd=[ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless',temp,'usb',
            '-import',temp/'p0.bin','-loader','BinaryLoader','-loader-baseAddr','0xad800',
            '-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',scripts,
            '-postScript','ProbeAkeruUSBDescriptors.java',out/'trace.txt',temp/'p1.bin',temp/'msdc.bin',temp/'ptp.bin','-deleteProject']
        (out/'command.json').write_text(json.dumps([str(x) for x in cmd],indent=2)+'\n')
        r=subprocess.run([str(x) for x in cmd],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180)
        (out/'headless.log').write_text(r.stdout);assert r.returncode==0 and 'SCRIPT ERROR' not in r.stdout,r.stdout[-6000:]
    trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=8\n') and trace.count('PASS usb-descriptors ')==8
    assert all(sha((ROOT/p).read_bytes())==digest for p,digest in inputs.items())
    result=dict(status='PASS_ORIGINAL_USB_SPEED_PREPARATION_AND_SINGLE_INTERFACE_LAYOUT',cpu_cases=8,
        sources=inputs,templates=templates,gnu_windows=len(spans),instruction_checks=len(checks),
        ep0_request_targets=[hex(x) for x in request_targets],descriptor_type_targets=[hex(x) for x in descriptor_targets],
        payload_hashes={str(b['index']):b['sha256'] for b in blocks},trace=trace,
        decision='Dedicated AkeruRAM mode first; existing fixed-offset stack is not a demonstrated composite implementation',
        hardware_tested=False,installable=False,
        limits=['Only 19133C executed; speed query27DD74 supplies explicit0/1, RAM global pointers/descriptor device header/output buffer prepared',
            '191110 first-interface endpoint bindings and class extraction checked statically, not executed by this suite',
            'EP0 dispatcher191570 identified statically; no full enumeration/SET_CONFIGURATION/IRQ/controller/DMA execution',
            'Synthetic vendor/composite descriptors in emulator only; no assigned AkeruOS VID/PID, USB command or firmware change',
            'Does not prove silicon incapable of composite USB; proves current routine leaves second interface endpoint packet sizes unchanged',
            'Read-only RAM service, protocol/client, RAM whitelist, buffer ownership, task residency and recovery remain incomplete; NON_INSTALLARE'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print(trace,end='');print(out)


if __name__=='__main__':main()
