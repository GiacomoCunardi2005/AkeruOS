#!/usr/bin/env python3
"""Validazione indipendente della semantica provvisoria di muludw: la routine Nikon 0x3342A8 (__mulsi3, 32x32->32 costruita con
muludw) viene eseguita sul motore DSP sperimentale e confrontata con (a*b) mod 2^32. Nessun hardware; RAM del dump solo come contesto."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, random, struct, subprocess, sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_run_gnu_arc700 import ROOT, TOOLCHAIN, IMAGE, sha
from s33_verify_gnu_dsp_lab import LAB, BUILD

DUMP = ROOT / 'Risultati/Dump_fotocamera/MEMDUMP_20261106/MEMDUMP.BIN'
DUMP_SHA = 'c91888b23a8def81dc0afbf5a62a6210361308fea030bfbafcf6a43338286107'
BASE, CODE, RES, STACK_BASE = 0x100, 0x1041000, 0x3000000, 0x1048000
STACK_TOP = STACK_BASE + 16384
OUT_OFF = 0x2000

def pairs():
    edge = [0, 1, 2, 3, 0xFFFF, 0x10000, 0x10001, 0x8000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFFFE, 0x12345678, 0xDEADBEEF, 0x0000FFFF, 0xFFFF0000, 0x00010000]
    rnd = random.Random(0x33AC)  # seme fisso: riproducibile
    out = [(a, b) for a in edge[:12] for b in edge[:12]]
    out += [(rnd.getrandbits(32), rnd.getrandbits(32)) for _ in range(30)]
    out += [(rnd.getrandbits(16), rnd.getrandbits(16)) for _ in range(30)]
    out += [(rnd.getrandbits(12), rnd.getrandbits(32)) for _ in range(20)]
    return out

ASM = '''
 .text
 .global _start
_start:
 mov sp,{stack:#x}
 mov r13,{n}
 mov r14,{res:#x}
 mov r15,{out:#x}
loop:
 ld r0,[r14]
 ld r1,[r14,4]
 mov r12,0x3342a8
 jl [r12]
 st r0,[r15]
 add r14,r14,8
 add r15,r15,4
 sub.f r13,r13,1
 bne loop
 mov r0,0
 mov r8,1
 trap_s 1
 .section .stack,"aw",@nobits
 .align 16
 .space 16384
'''

def main():
    root = ROOT / 'Risultati/Runtime_Kernel/Muludw_Mul32_Profile' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    root.mkdir(parents=True)
    raw = DUMP.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == DUMP_SHA
    P = pairs()
    n = len(P)
    assert OUT_OFF + 4 * n <= 0x4000
    (root / 'probe.s').write_text(ASM.format(stack=STACK_TOP, res=RES, out=RES + OUT_OFF, n=n))
    (root / 'ram_working_copy.bin').write_bytes(raw[BASE:])
    (root / 'image.ld').write_text(f'PHDRS {{ ram PT_LOAD FLAGS(7); stk PT_LOAD FLAGS(6); }}\nSECTIONS {{\n . = {BASE:#x}; .dumpram : {{ *(.dumpram) }} :ram\n . = {CODE:#x}; .text : {{ *(.text) }} :ram\n . = {STACK_BASE:#x}; .stack (NOLOAD) : {{ *(.stack) }} :stk\n}}\n')
    for cmd in ([TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL', '-o', root / 'probe.o', root / 'probe.s'],
                [TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc', '--rename-section', '.data=.dumpram,alloc,load,contents', root / 'ram_working_copy.bin', root / 'ram.o'],
                [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-e', hex(CODE), '-T', root / 'image.ld', '-o', root / 'image.elf', root / 'probe.o', root / 'ram.o']):
        pr = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
        assert pr.returncode == 0, pr.stderr
    assert sha(LAB / 'install/bin/arc-elf32-run') == json.loads(BUILD.read_text())['experimental_sha256']
    import os
    from concurrent.futures import ThreadPoolExecutor

    def one(i):
        a_, b_ = P[i]
        d = root / f'run_{i:04d}'
        d.mkdir()
        os.link(root / 'image.elf', d / 'image.elf')
        buf = bytearray(0x4000)
        struct.pack_into('<II', buf, 0, a_, b_)
        (d / 'result.bin').write_bytes(bytes(buf))
        cmd = ['podman', 'run', '--rm', '--network', 'none', '--memory', '1g', '--volume', f'{LAB}:/engine:ro', '--volume', f'{d}:/result:rw', IMAGE,
               'timeout', '30s', '/engine/install/bin/arc-elf32-run', '--memory-mapfile', '/result/result.bin', '--memory-region', f'{RES:#x},16384', '/result/image.elf']
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        got = struct.unpack_from('<I', (d / 'result.bin').read_bytes(), OUT_OFF)[0]
        (d / 'image.elf').unlink()
        return i, r.returncode, got, ('unsupported' in (r.stdout + r.stderr))

    results = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(one, range(n)))
    ok_, refused, wrong = [], [], []
    for i, rc, got, unsup in results:
        a_, b_ = P[i]
        exp = (a_ * b_) & 0xFFFFFFFF
        rec = dict(a=hex(a_), b=hex(b_), got=hex(got), expected=hex(exp), exit=rc)
        if rc == 0 and got == exp:
            ok_.append(rec)
        elif unsup or rc != 0:
            refused.append(rec)
        else:
            wrong.append(rec)
    bad = wrong
    prov = len(ok_)
    run = type('R', (), dict(returncode=0))
    assert hashlib.sha256(DUMP.read_bytes()).hexdigest() == DUMP_SHA
    ev = dict(status='PASS' if not wrong else 'FAIL', pairs=n, exact=len(ok_), refused_by_engine=len(refused), wrong_result=len(wrong), wrong=wrong[:10],
              refused_examples=refused[:12], exact_examples=ok_[:6], limits='Verifica la semantica di muludw solo come usata da 0x3342A8 (prodotti parziali 32x16 con r56/r57); non la CPU fisica; non altre forme di muludw/muldw.')
    (root / 'evidence.json').write_text(json.dumps(ev, indent=2) + '\n')
    print(ev['status'], dict(pairs=n, exact=len(ok_), refused=len(refused), wrong=len(wrong)), root)
    sys.exit(0 if ev['status'] == 'PASS' else 1)

if __name__ == '__main__':
    main()
