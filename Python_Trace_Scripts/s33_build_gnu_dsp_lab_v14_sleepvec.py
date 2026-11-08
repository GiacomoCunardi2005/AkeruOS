#!/usr/bin/env python3
"""Variante di laboratorio v14: parte dalla v13 e aggiunge env S33_SLEEPVEC=<indirizzo>: dopo l'istruzione `sleep 0` dello scheduler inattivo
(0xB2E08, il simulatore la tratta come no-op) il flusso salta a <indirizzo>, uno stub del probe che esegue il gestore TIMER0 originale (0x29F740)
al posto dell'interrupt hardware che nel modello non esiste. Senza S33_SLEEPVEC il comportamento e' identico alla v13. Non cambia i byte Nikon."""
from pathlib import Path
import hashlib, json, shutil, subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'work/gnu_arc700_dsp_lab_v13_curtask'
PARENT = ROOT / 'outputs/gnu_arc700_dsp/build_v13_curtask/verified_evidence.json'
LAB = ROOT / 'work/gnu_arc700_dsp_lab_v14_sleepvec'
OUT = ROOT / 'outputs/gnu_arc700_dsp/build_v14_sleepvec'
OLD = '\n  return vpc;\n}\n'
NEW = '''
  {
    static int s33_sv_init; static USI s33_sv;
    if (!s33_sv_init) { const char *s33_e = getenv ("S33_SLEEPVEC"); s33_sv_init = 1; if (s33_e) sscanf (s33_e, "%x", &s33_sv); }
    if (s33_sv && (USI) vpc == 0xb2e0c) vpc = s33_sv;  /* dopo `sleep 0` a 0xB2E08: interrupt TIMER0 modellato */
  }
  return vpc;
}
'''


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parent = json.loads(PARENT.read_text())
    assert sha(BASE / 'install/bin/arc-elf32-run') == parent['experimental_sha256']
    assert not LAB.exists(), 'variante v14 gia presente'
    OUT.mkdir(parents=True, exist_ok=True)
    shutil.copytree(BASE, LAB, symlinks=True)
    for rel in ('source/gnu-arc700-sim-src/sim/arc/mloop7.in', 'build-gnu89/sim/arc/mloop7.c'):
        p = LAB / rel
        t = p.read_text()
        assert t.count(OLD) == 1, (rel, t.count(OLD))
        p.write_text(t.replace(OLD, NEW))
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
    (OUT / 'verified_evidence.json').write_text(json.dumps(dict(status='BUILD_ONLY', parent_v13_sha256=parent['experimental_sha256'], experimental_sha256=sha(dest),
        binary=str(dest), change="mloop7: env S33_SLEEPVEC=<addr> -> dopo `sleep 0` (0xB2E08) il flusso salta allo stub che simula l'interrupt TIMER0",
        limits=["Modello di laboratorio: non e' un interrupt reale", 'Serve test di esecuzione'], instrumentation=parent['instrumentation']), indent=2) + '\n')
    print(dest, sha(dest), flush=True)


if __name__ == '__main__':
    main()
