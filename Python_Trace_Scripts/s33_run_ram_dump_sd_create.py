#!/usr/bin/env python3
"""Original duplicate decision CPU probe; lower directory lookup is an explicit fixture."""
from pathlib import Path
import json,subprocess,tempfile,sys
from s33_trace_state_dispatch import verified_payloads,sha
ROOT=Path(__file__).resolve().parents[1]
def main():
 bs,p,_=verified_payloads(ROOT);out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_ABI/cpu_duplicate';out.mkdir(parents=True,exist_ok=True)
 gh=ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV';scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
 with tempfile.TemporaryDirectory(prefix='s33-sd-duplicate-') as d:
  d=Path(d);(d/'p0.bin').write_bytes(p[0]);(d/'p1.bin').write_bytes(p[1]);trace=out/'trace.txt'
  cmd=[str(gh/'support/analyzeHeadless'),str(d),'duplicate','-import',str(d/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDCreate.java',str(trace),str(d/'p1.bin'),'-deleteProject']
  r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
  assert r.returncode==0 and 'SCRIPT ERROR' not in r.stdout and 'error: ' not in r.stdout,r.stdout[-5000:]
  t=trace.read_text();assert t.endswith('COMPLETE cases=9\n');assert t.count('PASS ')==9
  result=dict(status='PASS_CONDITIONAL_ORIGINAL_CPU',cases=9,payload0_sha256=bs[0]['sha256'],script_sha256=sha((scripts/'ProbeDumpSDCreate.java').read_bytes()),assumptions=['Directory lookup 2A2D88 is fixture returning existing pointer or absent null','Context field +190*4 is zero','Absent case stops before actual create, existing returns through original millicode'],limits=['No FAT/SD execution or atomicity proof','Existing-directory lookup itself is stubbed','No backend7 equivalence'])
  (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');print(t)
if __name__=='__main__':main()
