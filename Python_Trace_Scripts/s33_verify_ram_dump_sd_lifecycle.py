#!/usr/bin/env python3
"""Execute original open/close wrappers with service fixtures, never a camera."""
from datetime import datetime, timezone
from pathlib import Path
import json, subprocess, tempfile, sys
from s33_trace_state_dispatch import verified_payloads, sha

ROOT = Path(__file__).resolve().parents[1]


def main():
    blocks, payloads, _ = verified_payloads(ROOT)
    out = ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Lifecycle'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    scripts = ROOT/'S33-sections/analysis_ghidra/scripts'
    probe = scripts/'ProbeDumpSDLifecycle.java'
    helper = scripts/'ProbeStatusRead.java'
    inputs = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in [Path(__file__), probe, helper]}
    with tempfile.TemporaryDirectory(prefix='s33-sd-lifecycle-') as name:
        temp = Path(name)
        for i in (0, 1):
            (temp/f'p{i}.bin').write_bytes(payloads[i])
        command = [str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(temp), 'lifecycle', '-import', str(temp/'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', probe.name, str(out/'trace.txt'), str(temp/'p1.bin'), '-deleteProject']
        (out/'command.json').write_text(json.dumps(command, indent=2)+'\n')
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
        (out/'headless.log').write_text(result.stdout)
        assert result.returncode == 0 and 'SCRIPT ERROR' not in result.stdout, result.stdout[-4000:]
        trace = (out/'trace.txt').read_text()
        assert trace.endswith('COMPLETE cases=25\n') and trace.count('PASS ') == 25
    sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    assert [u32(a) for a in [0x12de24, 0x12d700, 0x12de2c, 0x12d708, 0x12d70c]] == [0x376018, 0x376018, 0x1594a4, 0x3038, 0x3015]
    assert [u32(a) for a in [0x1f4374,0x2a068c,0x376054,0x1f3918,0x1f391c,0x1f3920]] == [0xa0a1,0x376054,0x168990,0x3693b4,0x1f6270,0x1f6250]
    spans=[(0x12dbfc,0x12dd24),(0x12d604,0x12d6fc),(0x1f22c0,0x1f2348),(0x1f3f7e,0x1f3fac),(0x1f35d4,0x1f3608),(0x2a05f4,0x2a0674),(0x168970,0x168998),(0x1688ac,0x168970)]
    listing=''.join(disasm(a,b) for a,b in spans)
    import re
    checks={0x1f3f82:';0x1f2348',0x168990:'mov_s\tr1,r0',0x168994:';0x168970',0x16898e:';0x1688ac',0x168920:'stb_s\tr0,[r13,0x4]',0x168936:'st\tr17,[r13,12]',0x16893e:'stw_s\tr0,[r13,0x10]',0x1f35f4:'st_s\tr0,[r14,0x70]'}
    for address,expected in checks.items():
        lines=[line for line in listing.splitlines() if re.match(rf'^\s*{address:x}:',line)]
        assert len(lines)==1 and expected in lines[0], (hex(address),expected,lines)
    (out/'gnu_verified.txt').write_text(listing)
    for p in [Path(__file__), probe, helper]:
        assert sha(p.read_bytes()) == inputs[str(p.relative_to(ROOT))]
        (out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    manifest = dict(status='PASS_ORIGINAL_SD_WRAPPER_LIFECYCLE_WITH_SERVICE_FIXTURES', cpu_cases=25,
        payload_sha256={str(b['index']): b['sha256'] for b in blocks}, sources=inputs,
        assumptions=['Upper wrapper cases: resolver, volume lock/unlock/check, error getter, generic open/close and ioctl are fixtures', 'Three separate generic-close cases: original 1F22C0, device callback/mutex/free are fixtures', 'Six backend selection fragments: original 1F3F90 and 1F35D4, inputs at sp+10/sp+18 explicit, registration 2A4528 fixture; not whole mount', 'Volume index zero, three occupied slots, controlled slot table in original payload1', 'Original 12DBFC/12D604 and millicode execute; stack preservation checked'],
        backend_selection=dict(predicate='record byte+4==7 and unsigned word+12>=0x04000000',writer='1F35D4 stores7 at context+70; flag0 leaves previous field unchanged',record_query='1F3F82 ioctl A0A1 -> 2A05F4 -> table376054 -> 168990/168970/1688AC',scope='Static route; record synthesis branch requires its original predicates. Six CPU cases start after query, not whole mount',gnu_instruction_checks=len(checks)),
        limits=['Not FAT, actual synchronization, SD persistence, concurrency, current backend identity or hardware execution', 'Does not prove complete physical RAM map or installable dumper', 'Close may retain ownership before lower close; open error may publish a live handle'])
    (out/'verified_evidence.json').write_text(json.dumps(manifest, indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps({'evidence': str((out/'verified_evidence.json').relative_to(ROOT))}, indent=2)+'\n')
    print(trace, end='')
    print(out)


if __name__ == '__main__':
    main()
