#!/usr/bin/env python3
"""Variante di laboratorio v11: parte dalla v10 e aggiunge l'osservatore S33_WATCH=addr,... (stampa pc e valori a ogni variazione).
Dopo ogni istruzione-guardia confronta le parole osservate e stampa le variazioni su stderr. Fa le veci dell'altro task/interrupt che nella fotocamera
imposta i bit degli event group; il profilo non ha scheduler. Senza S33_POKE il comportamento e' identico alla v8.
Non cambia i byte Nikon."""
from pathlib import Path
import hashlib, json, shutil, subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'work/gnu_arc700_dsp_lab_v10_pokemulti'
PARENT = ROOT / 'outputs/gnu_arc700_dsp/build_v10_pokemulti/verified_evidence.json'
LAB = ROOT / 'work/gnu_arc700_dsp_lab_v11_watch'
OUT = ROOT / 'outputs/gnu_arc700_dsp/build_v11_watch'
ANCHOR = 'execute (SIM_CPU *current_cpu, SCACHE *sc, int fast_p)\n{\n  SEM_PC vpc;\n'
HOOK = '''
  {
    static int s33w_init; static USI s33w_a[8], s33w_last[8]; static int s33w_cnt; static unsigned long s33w_n;
    if (!s33w_init) {
      const char *s33w_e = getenv ("S33_WATCH");  /* "addr,addr,..." */
      s33w_init = 1;
      while (s33w_e && *s33w_e && s33w_cnt < 8) {
        unsigned a; int k = 0;
        if (sscanf (s33w_e, "%x%n", &a, &k) < 1) break;
        s33w_a[s33w_cnt++] = a; s33w_e += k; if (*s33w_e == ',') s33w_e++;
      }
      { int j; for (j = 0; j < s33w_cnt; j++) s33w_last[j] = GETMEMSI (current_cpu, 0, s33w_a[j]); }
    }
    if (s33w_cnt) {
      int j;
      s33w_n++;
      for (j = 0; j < s33w_cnt; j++) {
        USI cur = GETMEMSI (current_cpu, 0, s33w_a[j]);
        if (cur != s33w_last[j]) {
          sim_io_eprintf (CPU_STATE (current_cpu), "S33_WATCH n=%lu addr=%08x old=%08x new=%08x prev_pc_next=%08x\\n", s33w_n, s33w_a[j], s33w_last[j], cur, (USI) CPU (h_pc));
          s33w_last[j] = cur;
        }
      }
    }
  }
'''


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parent = json.loads(PARENT.read_text())
    assert sha(BASE / 'install/bin/arc-elf32-run') == parent['experimental_sha256']
    assert not LAB.exists(), 'variante v11 gia presente: non la ricostruisco'
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
        binary=str(dest), change='mloop7: env S33_WATCH=addr,... -> stampa le variazioni delle parole osservate',
        limits=['Modello di laboratorio: non e\' uno scheduler ne\' un interrupt reale', 'Serve test di esecuzione'], instrumentation=parent['instrumentation']), indent=2) + '\n')
    print(dest, sha(dest), flush=True)


if __name__ == '__main__':
    main()
