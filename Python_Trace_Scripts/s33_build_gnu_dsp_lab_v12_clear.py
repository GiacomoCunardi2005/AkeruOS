#!/usr/bin/env python3
"""Variante di laboratorio v12: parte dalla v11 e estende S33_POKES con l'operazione di azzeramento: "addr!maschera" fa [addr] &= ~maschera a ogni istruzione ("addr:valore" resta [addr] |= valore).
Serve a modellare il pari (altro processore/task) che svuota lo slot di una mailbox condivisa. Il profilo non ha scheduler ne' coprocessori.
Senza S33_POKES il comportamento e' identico alla v11. Non cambia i byte Nikon.
"""
from pathlib import Path
import hashlib, json, shutil, subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'work/gnu_arc700_dsp_lab_v11_watch'
PARENT = ROOT / 'outputs/gnu_arc700_dsp/build_v11_watch/verified_evidence.json'
LAB = ROOT / 'work/gnu_arc700_dsp_lab_v12_clear'
OUT = ROOT / 'outputs/gnu_arc700_dsp/build_v12_clear'
ANCHOR = 'execute (SIM_CPU *current_cpu, SCACHE *sc, int fast_p)\n{\n  SEM_PC vpc;\n'
OLD_PARSE = 'if (sscanf (s33_e, "%x:%x%n", &a, &v, &k) < 2) break;\n        s33_a[s33_cnt] = a; s33_v[s33_cnt++] = v;'
NEW_PARSE = 'if (sscanf (s33_e, "%x%n", &a, &k) < 1) break;\n        { char s33_c = s33_e[k]; if ((s33_c != \':\' && s33_c != \'!\') || sscanf (s33_e + k + 1, "%x%n", &v, &k2) < 1) break; s33_clr[s33_cnt] = (s33_c == \'!\'); k += 1 + k2; }\n        s33_a[s33_cnt] = a; s33_v[s33_cnt++] = v;'
OLD_DECL = 'static USI s33_a[256], s33_v[256];'
NEW_DECL = 'static USI s33_a[256], s33_v[256]; static int s33_clr[256];'
OLD_VARS = 'unsigned a, v; int k = 0;\n        if (sscanf (s33_e, "%x'
OLD_APPLY = 'SETMEMSI (current_cpu, 0, s33_a[s33_j], GETMEMSI (current_cpu, 0, s33_a[s33_j]) | s33_v[s33_j]);'
NEW_APPLY = 'SETMEMSI (current_cpu, 0, s33_a[s33_j], s33_clr[s33_j] ? (GETMEMSI (current_cpu, 0, s33_a[s33_j]) & ~s33_v[s33_j]) : (GETMEMSI (current_cpu, 0, s33_a[s33_j]) | s33_v[s33_j]));'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parent = json.loads(PARENT.read_text())
    assert sha(BASE / 'install/bin/arc-elf32-run') == parent['experimental_sha256']
    assert not LAB.exists(), 'variante v12 gia presente: non la ricostruisco'
    OUT.mkdir(parents=True, exist_ok=True)
    shutil.copytree(BASE, LAB, symlinks=True)
    for rel in ('source/gnu-arc700-sim-src/sim/arc/mloop7.in', 'build-gnu89/sim/arc/mloop7.c'):
        p = LAB / rel
        t = p.read_text()
        for old, new in ((OLD_PARSE, NEW_PARSE), (OLD_DECL, NEW_DECL), (OLD_APPLY, NEW_APPLY), ('unsigned a, v; int k = 0;', 'unsigned a, v; int k = 0, k2 = 0;')):
            assert t.count(old) == 1, (rel, old)
            t = t.replace(old, new)
        p.write_text(t)
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
