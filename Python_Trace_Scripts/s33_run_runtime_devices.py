#!/usr/bin/env python3
"""Execute original Nikon service dispatch/GPIO code using an opt-in P-code MMIO model."""
from pathlib import Path
from datetime import datetime, timezone
import json
import subprocess
import tempfile
import uuid

from s33_run_gnu_arc700 import ROOT, FW_SHA, sha
from s33_trace_state_dispatch import verified_payloads


def main():
    out = ROOT/'Risultati/Runtime_Kernel/Emulator_Devices'/(
        datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8])
    out.mkdir(parents=True)
    print('Evidence:', out, flush=True)
    scripts = ROOT/'S33-sections/analysis_ghidra/scripts'
    ghidra = ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV'
    firmware = ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin'
    sources = [Path(__file__), scripts/'S33RuntimeDevices.java',
               scripts/'ProbeRuntimeDevices.java', scripts/'ProbeStatusRead.java']
    inputs = [firmware, *sources,
              ghidra/'Ghidra/Framework/Emulation/lib/Emulation.jar',
              ghidra/'Ghidra/Processors/ARC/data/languages/ARCompactLoopFix.sla',
              ROOT/'S33-sections/TBM_blocks/manifest.json']
    before = {str(p.relative_to(ROOT)): sha(p) for p in inputs}
    report = dict(status='RUNNING', input_hashes=before,
        assumptions=['Explicit empty pending/enable laboratory context, not physical reset values',
                     'W1C acknowledgement is an inferred peripheral hypothesis',
                     'IRQ lock/unlock are explicit return stubs; no scheduler emulation',
                     'Completion delay 500 is a checked return stub; no elapsed time claim',
                     'TIMER1 handler is called by the host with scale=2 and count1=0; no automatic ticks',
                     'Injected requests and an original empty callback replace the physical event source'],
        limits=['No automatic IRQ delivery, timing, complete boot or photography',
                'Request-setter semantics at FED3818 remain unmodeled; host injection only',
                'GPIO values are software register effects, not electrical validation',
                'Boot bank supports observed writes; device reads stop',
                'GNU installations and firmware remain unchanged'])
    try:
        assert before[str(firmware.relative_to(ROOT))] == FW_SHA
        blocks, payloads, _ = verified_payloads(ROOT)
        assert len(blocks) == 16
        with tempfile.TemporaryDirectory(prefix='s33-runtime-') as td:
            temp = Path(td)
            for index in (0, 1):
                (temp/f'payload{index}.bin').write_bytes(payloads[index])
            output = out/'runtime_trace.txt'
            command = [str(ghidra/'support/analyzeHeadless'), str(temp), 'runtime_devices',
                '-import', str(temp/'payload0.bin'), '-loader', 'BinaryLoader',
                '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix',
                '-noanalysis', '-scriptPath', str(scripts), '-postScript',
                'ProbeRuntimeDevices.java', str(output), str(temp/'payload1.bin'), '-deleteProject']
            (out/'command.json').write_text(json.dumps(command, indent=2)+'\n')
            proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, timeout=180)
            (out/'headless.log').write_text(proc.stdout)
            assert proc.returncode == 0 and 'SCRIPT ERROR' not in proc.stdout and 'error: ' not in proc.stdout, proc.stdout[-7000:]
            trace = output.read_text()
            assert trace.endswith('COMPLETE cases=39\n')
            cases = [line for line in trace.splitlines() if line.startswith('PASS ')]
            assert len(cases) == 39
            report.update(status='PASS_CONDITIONAL_RUNTIME_MODEL', cases=cases,
                          firmware_instructions_preserved=True, full_boot=False)
        for p in inputs:
            assert sha(p) == before[str(p.relative_to(ROOT))], f'Input changed: {p}'
        for p in sources:
            (out/p.name).write_bytes(p.read_bytes())
    except Exception as exc:
        report.update(status='FAIL', error=repr(exc))
        raise
    finally:
        report['files'] = {p.name: sha(p) for p in out.iterdir() if p.is_file()}
        (out/'verified_evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps(dict(
        evidence=str((out/'verified_evidence.json').relative_to(ROOT)), status=report['status']), indent=2)+'\n')
    print(report['status'], 'cases=39', out/'verified_evidence.json', flush=True)


if __name__ == '__main__':
    main()
