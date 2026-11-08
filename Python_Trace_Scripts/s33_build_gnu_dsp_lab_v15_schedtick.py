#!/usr/bin/env python3
"""Variante di laboratorio v15: parte dalla v14 e aggiunge env S33_SCHEDVEC=<stub>,<flag>: quando il flusso sta per entrare nello scheduler
(0xB2D50, salvataggio del contesto del task che si blocca) salta allo stub del probe, che salva i registri, esegue il gestore TIMER0 originale
(0x29F740) e rientra in 0xB2D50 impostando <flag> perche' il rientro non venga dirottato di nuovo. Modella un interrupt del timer che arriva a
ogni cambio di contesto. Senza S33_SCHEDVEC il comportamento e' identico alla v14. Non cambia i byte Nikon."""
from pathlib import Path
import hashlib, json, shutil, subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'work/gnu_arc700_dsp_lab_v14_sleepvec'
PARENT = ROOT / 'outputs/gnu_arc700_dsp/build_v14_sleepvec/verified_evidence.json'
LAB = ROOT / 'work/gnu_arc700_dsp_lab_v15_schedtick'
OUT = ROOT / 'outputs/gnu_arc700_dsp/build_v15_schedtick'
OLD = '\n  return vpc;\n}\n'
NEW = '''
  {
    static int s33_st_init; static USI s33_st, s33_sf;
    if (!s33_st_init) { const char *s33_e = getenv ("S33_SCHEDVEC"); s33_st_init = 1; if (s33_e && sscanf (s33_e, "%x,%x", &s33_st, &s33_sf) != 2) s33_st = 0; }
    if (s33_st && (USI) vpc == 0xb2d50) {  /* ingresso nello scheduler: interrupt TIMER0 modellato */
      if (GETMEMSI (current_cpu, 0, s33_sf)) SETMEMSI (current_cpu, 0, s33_sf, 0);
      else vpc = s33_st;
    }
  }
  return vpc;
}
'''


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parent = json.loads(PARENT.read_text())
    assert sha(BASE / 'install/bin/arc-elf32-run') == parent['experimental_sha256']
    assert not LAB.exists(), 'variante v15 gia presente'
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
    (OUT / 'verified_evidence.json').write_text(json.dumps(dict(status='BUILD_ONLY', parent_v14_sha256=parent['experimental_sha256'], experimental_sha256=sha(dest),
        binary=str(dest), change='mloop7: env S33_SCHEDVEC=<stub>,<flag> -> all ingresso dello scheduler 0xB2D50 il flusso passa per lo stub che esegue il tick TIMER0',
        limits=["Modello di laboratorio: non e' un interrupt reale", 'Serve test di esecuzione'], instrumentation=parent['instrumentation']), indent=2) + '\n')
    print(dest, sha(dest), flush=True)


if __name__ == '__main__':
    main()
