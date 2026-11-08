#!/usr/bin/env python3
"""Variante di laboratorio v9: parte dalla v8 e aggiunge un segnalatore modellato (env S33_POKE="addr,valore,ogni").
Ogni `ogni` istruzioni esegue [addr] |= valore (parola a 32 bit). Fa le veci dell'altro task/interrupt che nella fotocamera
imposta i bit degli event group; il profilo non ha scheduler. Senza S33_POKE il comportamento e' identico alla v8.
Non cambia i byte Nikon."""
from pathlib import Path
import hashlib, json, shutil, subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'work/gnu_arc700_dsp_lab_v8_dcctrl'
PARENT = ROOT / 'outputs/gnu_arc700_dsp/build_v8_dcctrl/verified_evidence.json'
LAB = ROOT / 'work/gnu_arc700_dsp_lab_v9_poke'
OUT = ROOT / 'outputs/gnu_arc700_dsp/build_v9_poke'
ANCHOR = 'execute (SIM_CPU *current_cpu, SCACHE *sc, int fast_p)\n{\n  SEM_PC vpc;\n'
HOOK = '''
  {
    static int s33_init; static USI s33_addr, s33_val, s33_every; static unsigned long s33_n;
    if (!s33_init) {
      const char *s33_e = getenv ("S33_POKE");
      s33_init = 1;
      if (s33_e && sscanf (s33_e, "%x,%x,%u", &s33_addr, &s33_val, &s33_every) != 3) s33_every = 0;
    }
    if (s33_every && ++s33_n % s33_every == 0)
      SETMEMSI (current_cpu, 0, s33_addr, GETMEMSI (current_cpu, 0, s33_addr) | s33_val);
  }
'''


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parent = json.loads(PARENT.read_text())
    assert sha(BASE / 'install/bin/arc-elf32-run') == parent['experimental_sha256']
    assert not LAB.exists(), 'variante v9 gia presente: non la ricostruisco'
    OUT.mkdir(parents=True, exist_ok=True)
    shutil.copytree(BASE, LAB, symlinks=True)
    for rel in ('source/gnu-arc700-sim-src/sim/arc/mloop7.in', 'build-gnu89/sim/arc/mloop7.c'):
        p = LAB / rel
        t = p.read_text()
        assert t.count(ANCHOR) == 1, rel
        p.write_text(t.replace(ANCHOR, ANCHOR + HOOK))
    (LAB / 'build-gnu89/sim/arc/mloop7.o').unlink()
    cmd = ['podman', 'run', '--rm', '--network', 'none', '--memory', '2g', '--volume', f'{LAB}:/work:rw', '--workdir', '/work/build-gnu89/sim/arc',
           'localhost/arc700-legacy:gcc10', 'make', '-j2', 'CFLAGS=' + parent['instrumentation'], 'run']
    (OUT / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
    with (OUT / 'build.log').open('w') as stream:
        p = subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT, timeout=1500)
    assert p.returncode == 0, (OUT / 'build.log').read_text()[-3000:]
    dest = LAB / 'install/bin/arc-elf32-run'
    shutil.copyfile(LAB / 'build-gnu89/sim/arc/run', dest)
    dest.chmod(0o755)
    (OUT / 'verified_evidence.json').write_text(json.dumps(dict(status='BUILD_ONLY', parent_v8_sha256=parent['experimental_sha256'], experimental_sha256=sha(dest),
        binary=str(dest), change='mloop7: env S33_POKE=addr,valore,ogni -> [addr] |= valore ogni N istruzioni (segnalatore modellato)',
        limits=['Modello di laboratorio: non e\' uno scheduler ne\' un interrupt reale', 'Serve test di esecuzione'], instrumentation=parent['instrumentation']), indent=2) + '\n')
    print(dest, sha(dest), flush=True)


if __name__ == '__main__':
    main()
