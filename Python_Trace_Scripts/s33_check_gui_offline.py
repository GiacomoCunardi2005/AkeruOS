#!/usr/bin/env python3
"""Run the recurring GUI checks offline; keep full logs in a new results directory."""
from datetime import datetime, timezone
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('checks_offline_%Y%m%dT%H%M%S%fZ')
out.mkdir(parents=True, exist_ok=False)
monitor = 'Python_Trace_Scripts/s33_verify_gui_monitor_rearm_four_routes_cpu.py'
checks = [
    ('mapping', [sys.executable, 'Python_Trace_Scripts/s33_verify_four_button_candidate_mapping.py']),
    ('menu', ['make', '-C', 'AkeruOS', 'menu-model-verify']),
    ('mono', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_s33_mono*', '-v']),
    ('ghidra_exposure', [sys.executable, 'Python_Trace_Scripts/s33_verify_ghidra_exposure_evidence.py']),
    ('autoscene_flow', [sys.executable, 'Python_Trace_Scripts/s33_check_autoscene_ghidra_flow.py']),
    *[('monitor' + (option or '_baseline'), [sys.executable, monitor] + ([option] if option else []))
      for option in ('', '--combined', '--timeout', '--producer')],
]
results = []
for name, command in checks:
    try:
        run = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, timeout=300, check=False)
        code, output = run.returncode, run.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        code, output = None, str(exc)
    (out / (name + '.log')).write_text(output, encoding='utf-8')
    results.append({'name': name, 'command': command, 'exit_code': code, 'log': name + '.log'})
    print(f'{name}: {"PASS" if code == 0 else "FAIL"}', flush=True)
summary = {'status': 'PASS' if all(x['exit_code'] == 0 for x in results) else 'FAIL', 'checks': results,
           'scope': 'offline fixtures and CPU models; not physical camera or installability'}
(out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
print('Dettagli:', out)
sys.exit(0 if summary['status'] == 'PASS' else 1)
