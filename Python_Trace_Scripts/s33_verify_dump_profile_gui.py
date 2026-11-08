#!/usr/bin/env python3
"""Profilo di emulazione dal dump hardware: esegue codice GUI Nikon originale sulla RAM reale (nessuna fixture).
Nessun accesso alla fotocamera; il dump originale non viene modificato (si mappa una copia)."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, re, shutil, struct, subprocess, sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, IMAGE, sha
from s33_verify_gnu_dsp_lab import LAB, BUILD

DUMP = ROOT / 'Risultati/Dump_fotocamera/MEMDUMP_20261106/MEMDUMP.BIN'
DUMP_SHA = 'c91888b23a8def81dc0afbf5a62a6210361308fea030bfbafcf6a43338286107'
SIM = LEGACY / 'install/bin/arc-elf32-run'
HI_BASE, HI_SIZE = 0x0F680000, 0x40000  # piano OSD osservato: 0x0F68B39E (8 bit/pixel, passo 320)
XY = (20, 30)
if '--draw' in sys.argv:
    i = sys.argv.index('--draw')
    if len(sys.argv) > i + 2: XY = (int(sys.argv[i + 1]), int(sys.argv[i + 2]))
BASE = 0x100  # i primi 256 byte (vettori) restano fuori dall'immagine ELF
CODE, RES, STACK_BASE = 0x1041000, 0x3000000, 0x1044000
STACK_TOP = STACK_BASE + 16384

# (nome, indirizzo funzione, argomenti r0/r1 come offset in RES o 0, atteso)
PROBE = '''
 .text
 .global _start
_start:
 mov sp,{stack:#x}
 mov r20,{res:#x}
 mov r12,0x1453f4          ; finestra attiva [[0x14579C]]
 jl [r12]
 st r0,[r20,0]
 mov r12,0x20e320          ; contesto di disegno [0x20E3A0]
 jl [r12]
 st r0,[r20,4]
 mov r0,{res8:#x}          ; &larghezza
 mov r1,{res12:#x}         ; &altezza
 mov r12,0x20dbc8          ; dimensioni schermo
 jl [r12]
 mov r0,0
 mov r8,1
 trap_s 1
 .section .stack,"aw",@nobits
 .align 16
 .space 16384
'''

DRAW = '''
 .text
 .global _start
_start:
 mov sp,{stack:#x}
 mov r20,{res:#x}
 mov r0,{x}                ; x0
 mov r1,{y}                ; y0
 mov r2,300                ; x1
 mov r3,60                 ; y1
 mov r4,{res_text:#x}      ; "AKERU" (in RAM, finestra mappata a parte)
 mov r5,0x00ffffff         ; colore
 mov r6,0                  ; flags (allineamento a sinistra)
 mov r12,0x186d08          ; testo in rettangolo
 jl [r12]
 st r0,[r20,0]
 mov r0,0
 mov r8,1
 trap_s 1
 .section .stack,"aw",@nobits
 .align 16
 .space 16384
'''

CALL = '''
 .text
 .global _start
_start:
 mov sp,{stack:#x}
 mov r20,{res:#x}
 mov r0,{a0:#x}
 mov r1,{a1:#x}
 mov r2,{a2:#x}
 mov r12,{fn:#x}
 jl [r12]
 st r0,[r20,0]
 mov r0,0
 mov r8,1
 trap_s 1
 .section .stack,"aw",@nobits
 .align 16
 .space 16384
'''

def main():
    out = ROOT / 'Risultati/Runtime_Kernel/Dump_Profile_GUI' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    raw = DUMP.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == DUMP_SHA, 'dump cambiato'
    # La RAM del dump diventa una sezione .dumpram a BASE; il probe (ARC700, flag corretti) resta a CODE.
    draw = '--draw' in sys.argv
    call = '--call' in sys.argv
    if call:
        i = sys.argv.index('--call'); fn, a0, a1, a2 = (int(x, 0) for x in sys.argv[i + 1:i + 5])
    (out / 'probe.s').write_text((CALL if call else DRAW if draw else PROBE).format(fn=fn if call else 0, a0=a0 if call else 0, a1=a1 if call else 0, a2=a2 if call else 0, x=XY[0], y=XY[1], stack=STACK_TOP, res=RES, res8=RES + 8, res12=RES + 12, res_text=RES + 0x40))
    (out / 'ram_working_copy.bin').write_bytes(raw[BASE:])  # copia di lavoro; l'originale resta intatto
    (out / 'image.ld').write_text(f'PHDRS {{ ram PT_LOAD FLAGS(5); stk PT_LOAD FLAGS(6); }}\nSECTIONS {{\n . = {BASE:#x}; .dumpram : {{ *(.dumpram) }} :ram\n . = {CODE:#x}; .text : {{ *(.text) }} :ram\n . = {STACK_BASE:#x}; .stack (NOLOAD) : {{ *(.stack) }} :stk\n}}\n')
    steps = ([TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL', '-o', out / 'probe.o', out / 'probe.s'],
             [TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
              '--rename-section', '.data=.dumpram,alloc,load,contents', out / 'ram_working_copy.bin', out / 'ram.o'],
             [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-e', hex(CODE), '-T', out / 'image.ld', '-o', out / 'image.elf', out / 'probe.o', out / 'ram.o'])
    for cmd in steps:
        pr = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
        assert pr.returncode == 0, pr.stderr
    res = out / 'result.bin'
    (out / 'hi_ram.bin').write_bytes(bytes(HI_SIZE))
    res.write_bytes(bytes(0x40) + b'AKERU\0' + bytes(0x100 - 0x46))
    # come Runner.run: simulatore GNU nel container, cartella dei risultati montata read-write
    # motore sperimentale con DSP (muludw): hash verificato come negli altri probe GUI
    assert sha(LAB / 'install/bin/arc-elf32-run') == json.loads(BUILD.read_text())['experimental_sha256']
    cmd = ['podman', 'run', '--rm', '--network', 'none', '--memory', '2g',
           '--volume', f'{LAB}:/engine:ro', '--volume', f'{out}:/result:rw', IMAGE,
           'timeout', '60s', '/engine/install/bin/arc-elf32-run',
           '--memory-mapfile', '/result/result.bin', '--memory-region', f'{RES:#x},256',
           '--memory-mapfile', '/result/hi_ram.bin', '--memory-region', f'{HI_BASE:#x},{HI_SIZE:#x}', '/result/image.elf']
    (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    (out / 'sim.log').write_text(run.stdout + run.stderr)
    got = struct.unpack('<4I', res.read_bytes()[:16])
    assert hashlib.sha256(DUMP.read_bytes()).hexdigest() == DUMP_SHA, 'originale modificato'
    if call:
        print('CALL r0 =', hex(got[0]), 'exit', run.returncode, out)
        sys.exit(0)
    if draw:
        log = run.stdout + run.stderr
        m = re.search(r'(\d+) byte (read|write) to unmapped address (0x[0-9a-f]+) at (0x[0-9a-f]+)', log)
        ev = dict(exit_code=run.returncode, return_value=hex(got[0]),
                  xy=list(XY), fault=dict(size=int(m[1]), operation=m[2], address=m[3], pc=m[4]) if m else None)
        (out / 'evidence.json').write_text(json.dumps(dict(status='DRAW_RAN', dump_sha256=DUMP_SHA, result=ev,
            limits='Disegno originale 0x186D08 su RAM reale; MMIO non mappato -> fault; nessun display emulato.'), indent=2) + '\n')
        hi = (out / 'hi_ram.bin').read_bytes()
        nz = [i for i, b in enumerate(hi) if b]
        if nz:
            first, last = HI_BASE + nz[0], HI_BASE + nz[-1]
            ev.update(pixels_written=len(nz), first_addr=hex(first), last_addr=hex(last), values=sorted({hi[i] for i in nz}))
            row0 = (first - HI_BASE) // 320
            rows = range(row0, (last - HI_BASE) // 320 + 1)
            x0 = min((i % 320) for i in nz); x1 = max((i % 320) for i in nz)
            art = ['%03d ' % r + ''.join('#' if hi[r * 320 + x] else '.' for x in range(x0, x1 + 1)) for r in rows]
            (out / 'ascii.txt').write_text('\n'.join(art) + '\n')
            ev.update(rect_rows=[rows[0], rows[-1]], rect_cols=[x0, x1])
        print('DRAW', ev, out)
        sys.exit(0)
    ev = dict(exit_code=run.returncode, active_window=hex(got[0]), draw_ctx=hex(got[1]), screen_w=got[2], screen_h=got[3])
    ok = run.returncode == 0 and got == (0x783AE8, 0x3E8950, 640, 480)
    (out / 'evidence.json').write_text(json.dumps(dict(status='PASS' if ok else 'FAIL', dump_sha256=DUMP_SHA, result=ev,
        limits='Funzioni pure del dump eseguite su RAM reale; MMIO/interrupt/scheduler non emulati; stato istantaneo non atomico.'), indent=2) + '\n')
    print(('PASS' if ok else 'FAIL'), ev, out)
    sys.exit(0 if ok else 1)

if __name__ == '__main__':
    main()
