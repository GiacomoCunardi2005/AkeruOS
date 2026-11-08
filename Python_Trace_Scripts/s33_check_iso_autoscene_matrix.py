#!/usr/bin/env python3
"""Run the additional ISO/scene matrix offline with compact, auditable results."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
probe = ROOT / 'Python_Trace_Scripts/s33_probe_gui_iso_autoscene_to_calc_cpu.py'
assert sys.argv[1:] in ([], ['--time'])
time_matrix = sys.argv[1:] == ['--time']
prefix = 'time_autoscene_matrix_' if time_matrix else 'iso_autoscene_matrix_'
out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime(prefix + '%Y%m%dT%H%M%S%fZ')
out.mkdir(parents=True, exist_ok=False)

def run_case(arguments):
    number = '_'.join(map(str, arguments))
    command = [sys.executable, str(probe), *map(str, arguments)]
    try:
        run = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=120, check=False)
        code, output = run.returncode, run.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        code, output = None, str(exc)
    (out / f'{number}.log').write_text(output, encoding='utf-8')
    lines = [s.removeprefix('Prove: ').strip() for s in output.splitlines() if s.startswith('Prove: ')]
    result = {'case': number, 'exit_code': code, 'log': f'{number}.log'}
    if len(lines) == 1:
        path = Path(lines[0])
        try:
            evidence = json.loads((path / 'verified_evidence.json').read_text())
            result.update(evidence=str(path.relative_to(ROOT)), status=evidence['status'],
                          selection=evidence['selection'], scene_mode=evidence['scene_mode'],
                          update_operational=evidence['update_operational'], final_iso=evidence['final_iso'],
                          time_choice=evidence['time_choice'], time_operational_update=evidence['time_operational_update'],
                          time_after_confirm=evidence['time_after_confirm'], time_after_fragment=evidence['time_after_fragment'],
                          final_time=evidence['final_time'])
        except (OSError, ValueError, KeyError) as exc:
            result['evidence_error'] = str(exc)
    return result

matrix = [(index, choice, update) for index in (2, 6) for choice in (0, 42, 84) for update in (0, 1)] if time_matrix else [(index,) for index in range(8, 28)]
with ThreadPoolExecutor(max_workers=3) as executor:
    cases = list(executor.map(run_case, matrix))
passed = all(c['exit_code'] == 0 and c.get('status') == 'PASS_ISO_AUTOSCENE_FRAGMENT' for c in cases)
(out / 'summary.json').write_text(json.dumps({'status': 'PASS' if passed else 'FAIL', 'cases': cases,
    'limits': 'Synthetic events, scene, callbacks and call order; no camera, AE or physical exposure.'}, indent=2) + '\n')
print(f'{sum(c.get("status") == "PASS_ISO_AUTOSCENE_FRAGMENT" and c["exit_code"] == 0 for c in cases)}/{len(cases)} PASS; {out}')
sys.exit(0 if passed else 1)
