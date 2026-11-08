#!/usr/bin/env python3
"""MACCHINA TASTI 0x16F630..0x16FA00: mappa bit fisico -> evento (it.50,
punto it.49(a)). Decodifica statica + 9 casi CPU su byte ORIGINALI
(motore pinnato GNU ARC700).

Scoperta centrale (statica, verificata qui in CPU):
- La "macchina tasti" p0 registra 128 classi evento a 0x446808, record da
  4 byte {byte0=stato, byte1=indice descrittore, halfword@2=flag}, e 10
  callback a 0x446A08+4i (fuori dal dump: RAM runtime).
- L'INSTALLER 0x16F66C(base, count) = unico chiamante bl 0x16E306 con
  r0 = pool 0x16E388 = 0x392F04 (TABELLA DESCrittori STATICA nel dump,
  16 record stride 20) e r1 = 0x10. Per ogni descrittore scrive
  byte[0x446808+4*classe+1] = indice e salva base/count nel ctx
  0x3678E4: {+0 abilitato, +4 puntatore array, +8 count}.
- DESCrittore (stride 20): {+0 u32 mask_lo, +4 u32 mask_hi, +8 u8 numero
  di BIT dell'input fisico 64-bit, +9 u8 classe evento, +0xA u32 flag
  (bit15=repeat armato), +0xC u16 press_ev (periodo repeat per le
  classi >= 0x61)}.
- MAPPA BIT -> EVENTO (16 tasti, byte del dump):
    bit20 classe 7  -> 0x380/0x381 (zoom)   bit16 classe 8 -> 0x400/0x401
    bit21 classe 9  -> 0x480/0x481          bit15 classe 10 -> 0x500/0x501
    bit31 classe 98 -> 0x3100 repeat 500ms  bit3 classe 3  -> 0x180/0x181
    bit12 classe 11 -> 0x580/0x581 (slot)   bit7 classe 14 -> 0x700/0x701 (slot)
    bit8 classe 67  -> 0x2180/0x2181 (slot) bit13 classe 78 -> 0x2700/0x2701 (slot)
    bit30 classe 106 -> 0x3500 repeat? no: flag 0 (no repeat, high class)
    bit35 classe 102 -> 0x3300 repeat 300ms bit60 classe 99 -> 0x3180 repeat 300
    bit61 classe 101 -> 0x3280 repeat 300   bit37 classe 100 -> 0x3200 repeat 200
    bit32 classe 118 -> 0x3B00 repeat 200
- GENERATORE 0x16F72C(idx, classe, stato, flag): stato a 1 -> evento
  classe<<7 (0x700 ecc.); stato 0 -> (classe<<7)|1 (0x701 ecc.).
  Al trigger preme 0x17C150(array {classe<<7, (classe<<7)|1}, 2, 1).
  Classi >= 0x61 con press_ev != 0: al primo trigger posta classe<<7,
  setta bit15 del descrittore e arma 0x14905C(0x3678F8, idx, press_ev,
  0, 0x16FA64); con bit15 gia' settato posta classe<<7 con flag 0 e
  chiama 0x1491E8(0x3678F8, idx).
- SCANNER 0x16F86C(lo, hi, genera): XOR col ctx, per ogni descrittore
  con bit cambiato calcola il bit (maschera & stato) >> numero via
  0x335C4C (shift-right 64-bit) e chiama il generatore.
- SYNC 0x16F8EC(lo, hi): porta il ctx al complemento, poi scanner con
  genera=0 (aggiorna solo gli stati, NESSUN evento): usato all'init.
- QUERY 0x16F920(classe) = byte[0x446808+4*classe] (521 chiamanti bl).
- INJECTION runtime: 0x16EC38(lo, hi) (gate 0x16E6E0) e 0x16E3A2(classe,
  bit) (preserva gli altri tasti via 0x16F914 AND-ctx; shift-left 64-bit
  0x334E9C): NESSUN chiamante bl -> registrazione indiretta
  (pool 0x16E390 = 0x16EC38 -> 0x140634; pool 0x16E38C = 0x16E588 ->
  callback slot via 0x16F988 all'init 0x16E2F4).
- FAN-OUT 0x16F6B0: fino a 10 callback 0x446A08+4i con (classe, stato,
  &evento); se byte[0x3678F9] != 0 e flag-arg != 0 ed esito callback != 0
  e 0x16F6A4(classe) bit0 != 0 -> inserisce (0, evento, r3arg, 1) nel
  ring 0x17BC7C.
- INPUT FISICO: init 0x16E2F4 legge 0x14066C ( = ~0x22C434(), active-low
  -> 1 = premuto) e sincronizza; unico chiamante bl dell'init = 0xC5D9E.

CPU (9 casi, byte originali): installer/query/scanner/fan-out/generatore/
0x16F950/0x16E3A2/0x16EC38 REALI; descrittori ORIGINALI dal dump; stub
con log per callback, 0x17C150, 0x17BC7C, 0x149028/0x14905C/0x1491E8,
0x1593AC/0x1594A4, 0x16E6E0, 0xAD90C. RAM sintetiche: ctx, key record
0x446808 (gap del dump). NESSUN hardware; NON_INSTALLARE.
"""
import hashlib
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha, elf_loads

LISTING = ROOT / 'Risultati/Disassemblati/Firmware1.1.asm'
STACK = 0xC8F000
LOG = 0x367000
PROBE_AT = 0x300000
CB_STUB = 0x300800

# log layout (word-sized fields)
CB_COUNT = LOG + 80
CB_ENT = LOG + 96            # 12 bytes: classe, stato, evento (32 max)
RING_COUNT = LOG + 488
RING_ENT = LOG + 504          # 16 bytes: r0, ev, r2, r3 (8 max)
C150_COUNT = LOG + 640
C150_ENT = LOG + 656          # 16 bytes: count, flag, h0, h1 (4 max)
T905C_COUNT = LOG + 728       # slot fisso per stub 0x14905C (arm)
T905C_FIELDS = LOG + 732      # node, id, val, r4 (una chiamata per caso)
T91E8_COUNT = LOG + 752       # slot fisso per stub 0x1491E8 (cancel)
T91E8_FIELDS = LOG + 756
T9028_COUNT = LOG + 776       # slot fisso per stub 0x149028 (mai atteso)
E6E0_COUNT = LOG + 908
Q_LOG = LOG + 40
W_MILI = (0, 0x334100, 0x3341E4, '.mili')
W_KMACH = (0, 0x16F630, 0x16FA60, '.kmach')
W_DESC = (1, 0x392F04, 0x393044, '.desc')
W_SHIFT64 = (0, 0x335C4C, 0x335C74, '.shift64')
W_SHIFTL = (0, 0x334E9C, 0x334EC4, '.shiftl')
W_EC38 = (0, 0x16EC38, 0x16EC88, '.ec38')
W_E3A2 = (0, 0x16E388, 0x16E41C, '.e3a2')

# ---------------------------------------------------------------- frozen ----
# (mask_lo, mask_hi, bit, classe, flag, press_ev) — byte del dump a 0x392F04
DESC_TABLE = [
    (0x00100000, 0x00000000, 20, 7, 0x00000000, 0x0000),
    (0x00010000, 0x00000000, 16, 8, 0x00000000, 0x0000),
    (0x00200000, 0x00000000, 21, 9, 0x00000000, 0x0000),
    (0x00008000, 0x00000000, 15, 10, 0x00000000, 0x0000),
    (0x80000000, 0x00000000, 31, 98, 0x01F40000, 0x01F4),
    (0x00000008, 0x00000000, 3, 3, 0x00000000, 0x0000),
    (0x00001000, 0x00000000, 12, 11, 0x00000000, 0x0000),
    (0x00000080, 0x00000000, 7, 14, 0x00000000, 0x0000),
    (0x00000100, 0x00000000, 8, 67, 0x00000000, 0x0000),
    (0x00002000, 0x00000000, 13, 78, 0x00000000, 0x0000),
    (0x40000000, 0x00000000, 30, 106, 0x00000000, 0x0000),
    (0x00000000, 0x00000008, 35, 102, 0x012C0000, 0x012C),
    (0x00000000, 0x10000000, 60, 99, 0x012C0000, 0x012C),
    (0x00000000, 0x20000000, 61, 101, 0x012C0000, 0x012C),
    (0x00000000, 0x00000020, 37, 100, 0x00C80000, 0x00C8),
    (0x00000000, 0x00000001, 32, 118, 0x00C80000, 0x00C8),
]
KEYMAP = {          # classe -> (bit, evento press, evento release)
    3: (3, 0x180, 0x181), 7: (20, 0x380, 0x381), 8: (16, 0x400, 0x401),
    9: (21, 0x480, 0x481), 10: (15, 0x500, 0x501), 11: (12, 0x580, 0x581),
    14: (7, 0x700, 0x701), 67: (8, 0x2180, 0x2181),
    78: (13, 0x2700, 0x2701), 98: (31, 0x3100, 0x3101),
    99: (60, 0x3180, 0x3181), 100: (37, 0x3200, 0x3201),
    101: (61, 0x3280, 0x3281), 102: (35, 0x3300, 0x3301),
    106: (30, 0x3500, 0x3501), 118: (32, 0x3B00, 0x3B01),
}
POOL_WORDS = {
    0x16E388: 0x392F04, 0x16E38C: 0x16E588, 0x16E390: 0x16EC38,
    0x16E394: 0x16ECB4, 0x16E398: 0x16EC88, 0x16E39C: 0x16EE7C,
    0x16FA30: 0x446A08, 0x16FA34: 0x446808, 0x16FA38: 0x3678E4,
    0x16FA3C: 0x446808, 0x16FA40: 0x3678F9, 0x16FA44: 0x3678E8,
    0x16FA48: 0x3678F8, 0x16FA4C: 0x16FA64, 0x16FA50: 0x300005,
    0x16FA54: 0x307F, 0x16FA58: 0x57FF, 0x16FA5C: 0x300006,
    0x16FA60: 0x4469F8,
}
# bl censuses congelate
CENSUS = {
    0x16F66C: [0x16E306], 0x16F8EC: [0x16E336],
    0x16F86C: [0x16E3FA, 0x16EC74, 0x16F90A],
    0x16F72C: [0x00144A82, 0x16E8A6, 0x16E8CA, 0x16E8F6, 0x16E9D8,
               0x16EA2A, 0x16EA7A, 0x16EA94, 0x16EAD4, 0x16EC28,
               0x16ECA2, 0x16EDFE, 0x16EF64, 0x16EF7A, 0x16EFC8,
               0x16EFEC, 0x16F00E, 0x16F176, 0x16F8D4],
    0x16F950: [0x2B37CC, 0x2CA34C, 0x2CABCC, 0x2CAC64, 0x2CBB28,
               0x6531DE, 0x6531E6],
    0x16F988: [0x16E30A, 0x323856],
    0x16F638: [0x15AF58], 0x16E2F4: [0x0C5D9E],
    0x16F6A4: [0x16F710],
    0x16E3A2: [], 0x16EC38: [],
}
CENSUS_16F920_COUNT = 521
# LE scans attese (payload, indirizzo)
LE_EXPECT = {
    0x16EC38: [(0, 0x16E390)],
    0x16E588: [(0, 0x16E38C)],
}


def cb_entry(k, classe, stato, evento):
    return [(CB_ENT + 12 * k + 0, 4, classe),
            (CB_ENT + 12 * k + 4, 4, stato),
            (CB_ENT + 12 * k + 8, 4, evento)]


def ring_entry(k, ev, arg2, arg3):
    return [(RING_ENT + 16 * k + 0, 4, 0),
            (RING_ENT + 16 * k + 4, 4, ev),
            (RING_ENT + 16 * k + 8, 4, arg2),
            (RING_ENT + 16 * k + 12, 4, arg3)]


def c150_entry(k, count, flag, h0, h1):
    return [(C150_ENT + 16 * k + 0, 4, count),
            (C150_ENT + 16 * k + 4, 4, flag),
            (C150_ENT + 16 * k + 8, 4, h0),
            (C150_ENT + 16 * k + 12, 4, h1)]


def timer_none():
    return [(T9028_COUNT, 4, 0), (T905C_COUNT, 4, 0),
            (T91E8_COUNT, 4, 0)]


REC = lambda classe: 0x446808 + 4 * classe   # record di classe


def setup_asm():
    return f'''
 mov r0,0x392f04
 mov r1,0x10
 mov r12,0x16f638
 jl_s [r12]
 mov r0,0x392f04
 mov r1,0x10
 mov r12,0x16f66c
 jl_s [r12]
 mov r0,{hex(CB_STUB)}
 mov r1,0x446a08
 st r0,[r1,0]
 mov r0,0
 mov r1,0
 mov r12,0x16f8ec
 jl_s [r12]
'''


def scanner_asm(lo, hi):
    return f'''
 mov r0,{hex(lo)}
 mov r1,{hex(hi)}
 mov r2,1
 mov r12,0x16f86c
 jl_s [r12]
'''


CPU_SPECS = [
    dict(name='install_sync',
         windows=[W_KMACH, W_DESC, W_SHIFT64],
         extra='',
         asserts=[(0x3678E4, 1, 1), (0x3678E8, 4, 0x392F04),
                  (0x3678EC, 2, 0x10), (0x3678EE, 1, 1),
                  (0x3678F0, 4, 0),
                  (0x3678F4, 4, 0), (REC(7) + 1, 1, 0),
                  (REC(8) + 1, 1, 1), (REC(11) + 1, 1, 6),
                  (REC(14) + 1, 1, 7), (REC(67) + 1, 1, 8),
                  (REC(78) + 1, 1, 9), (REC(3) + 1, 1, 5),
                  (REC(98) + 1, 1, 4), (REC(14), 1, 0),
                  (CB_COUNT, 4, 0), (RING_COUNT, 4, 0),
                  (T9028_COUNT, 4, 0), (T905C_COUNT, 4, 0), (T91E8_COUNT, 4, 0), (C150_COUNT, 4, 0)],
         success=0xDEADB001),
    dict(name='press_700_query',
         windows=[W_KMACH, W_DESC, W_SHIFT64],
         extra=scanner_asm(0x80, 0) + f'''
 mov r0,14
 mov r12,0x16f920
 jl_s [r12]
 mov r1,{hex(Q_LOG)}
 st r0,[r1,0]
''',
         asserts=([ (CB_COUNT, 4, 1), (Q_LOG, 4, 1),
                   (REC(14), 1, 1), (0x3678F0, 4, 0x80),
                   (RING_COUNT, 4, 0), (T9028_COUNT, 4, 0), (T905C_COUNT, 4, 0), (T91E8_COUNT, 4, 0),
                   (C150_COUNT, 4, 1)]
                  + cb_entry(0, 14, 1, 0x700)
                  + c150_entry(0, 2, 1, 0x700, 0x701)),
         success=0xDEADB002),
    dict(name='release_701',
         windows=[W_KMACH, W_DESC, W_SHIFT64],
         extra=scanner_asm(0x80, 0) + scanner_asm(0, 0) + f'''
 mov r0,14
 mov r12,0x16f920
 jl_s [r12]
 mov r1,{hex(Q_LOG)}
 st r0,[r1,0]
''',
         asserts=[(CB_COUNT, 4, 2), (Q_LOG, 4, 0),
                  (REC(14), 1, 0), (0x3678F0, 4, 0),
                  (RING_COUNT, 4, 0), (T9028_COUNT, 4, 0), (T905C_COUNT, 4, 0), (T91E8_COUNT, 4, 0),
                  (C150_COUNT, 4, 1)]
                 + cb_entry(0, 14, 1, 0x700)
                 + cb_entry(1, 14, 0, 0x701)
                 + c150_entry(0, 2, 1, 0x700, 0x701),
         success=0xDEADB003),
    dict(name='zoom_pair_380_400',
         windows=[W_KMACH, W_DESC, W_SHIFT64],
         extra=scanner_asm((1 << 20) | (1 << 16), 0),
         asserts=[(CB_COUNT, 4, 2), (REC(7), 1, 1), (REC(8), 1, 1),
                  (0x3678F0, 4, (1 << 20) | (1 << 16)),
                  (RING_COUNT, 4, 0), (T9028_COUNT, 4, 0), (T905C_COUNT, 4, 0), (T91E8_COUNT, 4, 0)]
                 + cb_entry(0, 7, 1, 0x380)
                 + cb_entry(1, 8, 1, 0x400)
                 + c150_entry(0, 2, 1, 0x380, 0x381)
                 + c150_entry(1, 2, 1, 0x400, 0x401),
         success=0xDEADB004),
    dict(name='repeat_98_arm_cancel',
         windows=[W_KMACH, W_DESC, W_SHIFT64],
         extra=scanner_asm(0x80000000, 0) + scanner_asm(0, 0),
         asserts=([ (CB_COUNT, 4, 2), (T9028_COUNT, 4, 0),
                   (T905C_COUNT, 4, 1), (T91E8_COUNT, 4, 1),
                   (T905C_FIELDS + 0, 4, 0x3678F8),
                   (T905C_FIELDS + 4, 4, 4),
                   (T905C_FIELDS + 8, 4, 0x1F4),
                   (T905C_FIELDS + 12, 4, 0x16FA64),
                   (T91E8_FIELDS + 0, 4, 0x3678F8),
                   (T91E8_FIELDS + 4, 4, 4),
                   (0x392F04 + 20 * 4 + 0xA, 2, 0x8000),
                   (RING_COUNT, 4, 0)]
                  + cb_entry(0, 98, 1, 0x3100)
                  + cb_entry(1, 98, 0, 0x3100)),
         success=0xDEADB005),
    dict(name='no_change_negative',
         windows=[W_KMACH, W_DESC, W_SHIFT64],
         extra=scanner_asm(0, 0),
         asserts=[(CB_COUNT, 4, 0), (RING_COUNT, 4, 0),
                  (T9028_COUNT, 4, 0), (T905C_COUNT, 4, 0), (T91E8_COUNT, 4, 0), (C150_COUNT, 4, 0),
                  (REC(14), 1, 0), (0x3678F0, 4, 0)],
         success=0xDEADB006),
    dict(name='ring_gated_press',
         windows=[W_KMACH, W_DESC, W_SHIFT64],
         extra='''
 mov r0,14
 mov r1,1
 mov r12,0x16f950
 jl_s [r12]
 mov r0,1
 mov r12,0x16f964
 jl_s [r12]
''' + scanner_asm(0x80, 0),
         asserts=([ (CB_COUNT, 4, 1), (RING_COUNT, 4, 1),
                   (0x3678F9, 1, 1), (T9028_COUNT, 4, 0), (T905C_COUNT, 4, 0), (T91E8_COUNT, 4, 0),
                   (C150_COUNT, 4, 1)]
                  + cb_entry(0, 14, 1, 0x700)
                  + ring_entry(0, 0x700, 0, 1)
                  + c150_entry(0, 2, 1, 0x700, 0x701)),
         success=0xDEADB007),
    dict(name='ec38_runtime_entry',
         windows=[W_KMACH, W_DESC, W_SHIFT64, W_EC38],
         extra='''
 mov r0,0x80
 mov r1,0
 mov r12,0x16ec38
 jl_s [r12]
''',
         asserts=([ (CB_COUNT, 4, 1), (E6E0_COUNT, 4, 1),
                   (REC(14), 1, 1), (RING_COUNT, 4, 0)]
                  + cb_entry(0, 14, 1, 0x700)
                  + c150_entry(0, 2, 1, 0x700, 0x701)),
         success=0xDEADB008),
    dict(name='slot_map_all_four',
         windows=[W_KMACH, W_DESC, W_SHIFT64],
         extra=scanner_asm(0x1000 | 0x80 | 0x100 | 0x2000, 0),
         asserts=([ (CB_COUNT, 4, 4),
                   (REC(11), 1, 1), (REC(14), 1, 1),
                   (REC(67), 1, 1), (REC(78), 1, 1),
                   (0x3678F0, 4, 0x1000 | 0x80 | 0x100 | 0x2000),
                   (RING_COUNT, 4, 0), (T9028_COUNT, 4, 0),
                   (T905C_COUNT, 4, 0), (T91E8_COUNT, 4, 0),
                   (C150_COUNT, 4, 4)]
                  + cb_entry(0, 11, 1, 0x580)
                  + cb_entry(1, 14, 1, 0x700)
                  + cb_entry(2, 67, 1, 0x2180)
                  + cb_entry(3, 78, 1, 0x2700)
                  + c150_entry(0, 2, 1, 0x580, 0x581)
                  + c150_entry(1, 2, 1, 0x700, 0x701)
                  + c150_entry(2, 2, 1, 0x2180, 0x2181)
                  + c150_entry(3, 2, 1, 0x2700, 0x2701)),
         success=0xDEADB009),
]


# ------------------------------------------------------------------ asm ----
def harness(setup, extra):
    return ('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            f' mov sp,{hex(STACK)}\n'
            + setup + extra +
            f' mov r12,{hex(PROBE_AT)}\n'
            ' j_s [r12]\n'
            '.section .log,"aw",@progbits\n.align 4\n .space 2048\n'
            '.section .stack,"aw",@nobits\n.align 16\n .space 16384\n')


def stub_cb():
    return ('.section .s_cb,"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            f' mov r3,{hex(LOG + 80)}\n'
            ' ld r4,[r3,0]\n add r5,r4,1\n st r5,[r3,0]\n'
            ' asl r6,r4,3\n asl r7,r4,2\n add r6,r6,r7\n'
            ' add r6,r6,r3\n add r6,r6,16\n'
            ' st r0,[r6,0]\n st r1,[r6,4]\n'
            ' ldh r5,[r2,0]\n st r5,[r6,8]\n'
            ' mov r0,1\n pop_s blink\n j_s [blink]\n')


def stub_ring():
    return ('.section .s_ring,"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            ' mov r5,r3\n'
            f' mov r3,{hex(LOG + 488)}\n'
            ' ld r4,[r3,0]\n add r6,r4,1\n st r6,[r3,0]\n'
            ' asl r6,r4,4\n add r6,r6,r3\n add r6,r6,16\n'
            ' st r0,[r6,0]\n st r1,[r6,4]\n st r2,[r6,8]\n st r5,[r6,12]\n'
            ' mov r0,0\n pop_s blink\n j_s [blink]\n')


def stub_c150():
    return ('.section .s_c150,"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            f' mov r3,{hex(LOG + 640)}\n'
            ' ld r4,[r3,0]\n add r5,r4,1\n st r5,[r3,0]\n'
            ' asl r6,r4,4\n add r6,r6,r3\n add r6,r6,16\n'
            ' st r1,[r6,0]\n st r2,[r6,4]\n'
            ' ldh r5,[r0,0]\n st r5,[r6,8]\n'
            ' ldh r5,[r0,2]\n st r5,[r6,12]\n'
            ' mov r0,0\n pop_s blink\n j_s [blink]\n')


def stub_timer(sec, logaddr):
    """Stub compatto (<= 0x34 byte): contatore + campi fissi, no indice."""
    return (f'.section {sec},"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            f' mov r3,{hex(logaddr)}\n'
            ' mov r5,r4\n'
            ' ld r4,[r3,0]\n add r6,r4,1\n st r6,[r3,0]\n'
            ' st r0,[r3,4]\n st r1,[r3,8]\n'
            ' st r2,[r3,12]\n st r5,[r3,16]\n'
            ' mov r0,0\n pop_s blink\n j_s [blink]\n')


def stub_ret0(sec):
    return (f'.section {sec},"ax",@progbits\n .org 0\n'
            ' push_s blink\n mov r0,0\n pop_s blink\n j_s [blink]\n')


def stub_e6e0():
    return ('.section .s_e6e0,"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            f' mov r3,{hex(LOG + 908)}\n'
            ' ld r4,[r3,0]\n add r5,r4,1\n st r5,[r3,0]\n'
            ' mov r0,1\n pop_s blink\n j_s [blink]\n')


def stub_ad90c():
    lines = [' st r4,[r3,0]\n st r4,[r3,4]\n st r4,[r3,8]\n'
             ' st r4,[r3,12]\n st r4,[r3,16]\n st r4,[r3,20]\n'
             ' st r4,[r3,24]\n st r4,[r3,28]\n st r4,[r3,32]\n'
             ' st r4,[r3,36]\n']
    return ('.section .s_ad90c,"ax",@progbits\n .org 0\n'
            ' push_s blink\n mov r3,r0\n mov r4,0\n'
            + ''.join(lines) +
            ' mov r0,0\n pop_s blink\n j_s [blink]\n')


def probe(asserts, success, case_idx):
    text = []
    n = 0
    for addr, width, expected in asserts:
        text.append(f' mov r4,{hex(addr)}')
        text.append(' ldb r5,[r4,0]' if width == 1
                    else ' ldh r5,[r4,0]' if width == 2
                    else ' ld r5,[r4,0]')
        text.append(f' mov r6,{hex(expected)}')
        text.append(' cmp r5,r6')
        text.append(f' bne bad{n}')
        n += 1
    text.append(f' mov r5,{hex(success)}')
    text.append(' ldb r0,[r5,0]')
    for k in range(n):
        marker = 0xDEAD0000 + case_idx * 0x80 + k
        text.append(f'bad{k}:')
        text.append(f' mov r5,{hex(marker)}')
        text.append(' ldb r0,[r5,0]')
    return ('.section .probe,"ax",@progbits\n .org 0\n'
            + '\n'.join(text) + '\n')


STUB_SECTIONS = [
    ('.s_ad90c', 0xAD90C, stub_ad90c),
    ('.s_lock_ac', 0x1593AC, lambda: stub_ret0('.s_lock_ac')),
    ('.s_lock_a4', 0x1594A4, lambda: stub_ret0('.s_lock_a4')),
    ('.s_e6e0', 0x16E6E0, stub_e6e0),
    ('.s_c150', 0x17C150, stub_c150),
    ('.s_ring', 0x17BC7C, stub_ring),
    ('.s_t9028', 0x149028, lambda: stub_timer('.s_t9028', T9028_COUNT)),
    ('.s_t905c', 0x14905C, lambda: stub_timer('.s_t905c', T905C_COUNT)),
    ('.s_t91e8', 0x1491E8, lambda: stub_timer('.s_t91e8', T91E8_COUNT)),
    ('.s_cb', CB_STUB, stub_cb),
]
RAM_SECTIONS = [
    ('.kmram', 0x446800, 0x240),
    ('.ctxram', 0x3678E0, 0x40),
]


# ------------------------------------------------------------- static ----
INSN_RE = re.compile(r'V([0-9A-F]{6,8}) \| [0-9a-f ]+\| (\S+)\s*(.*)')
CALL_RE = re.compile(r'V([0-9A-F]{6,8}) \| [0-9a-f ]+\| '
                     r'(bl|bl\.d|bl_s|bl_s\.d)\s+?-?\d+\s+'
                     r';0x(16f66c|16f8ec|16f86c|16f72c|16f950|16f988|16f638|'
                     r'16e2f4|16f6a4|16e3a2|16ec38|16f920)\b')


def load_lines():
    return LISTING.read_text(errors='replace').splitlines()


def payload_of(blocks, addr):
    for b in blocks:
        if b['load_address_candidate'] <= addr \
                < b['load_address_candidate'] + b['size']:
            return b['index']
    return None


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'key_machine_static_map_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, block_dir = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp, action='key-machine-map',
                   limits=[
                       'Static decode + 9 CPU cases on ORIGINAL bytes '
                       '(pinned GNU ARC700 engine); no hardware',
                       'Key record RAM 0x446808..0x446A30 and ctx '
                       '0x3678E4 are SYNTHETIC in the CPU cases (runtime '
                       'RAM, gap of the dump); ctx dump content at rest '
                       'is zero (verified in payload 1)',
                       'Callbacks 0x446A08 replaced by a logging stub: '
                       'the real first callback 0x16E588 is NOT run '
                       '(its decode is static only)',
                       '0x17C150/0x17BC7C/0x149028/0x14905C/0x1491E8/'
                       '0x1593AC/0x1594A4/0x16E6E0/0xAD90C are stubs with '
                       'logging: their real behavior is not proven here',
                       'Runtime poll wiring (who calls 0x16EC38 at '
                       'runtime; 0x140634 registration) is STATIC '
                       'evidence only (pool 0x16E390)',
                       'Input polarity (active-low GPIO via 0x14066C = '
                       '~0x22C434) is static decode; physical pin '
                       'identity of the 64-bit word is OPEN',
                       'V1.1 sample; NON_INSTALLARE'])
    try:
        lines = load_lines()
        # --- 1. bl censuses ---------------------------------------------
        got = {}
        for ln in lines:
            m = CALL_RE.search(ln)
            if m:
                got.setdefault(int(m.group(3), 16), []).append(
                    int(m.group(1), 16))
        for api, want in CENSUS.items():
            assert sorted(got.get(api, [])) == sorted(want), (
                hex(api), [hex(x) for x in sorted(got.get(api, []))])
        assert len(got.get(0x16F920, [])) == CENSUS_16F920_COUNT, (
            len(got.get(0x16F920, [])))
        assert got.get(0x16E3A2, None) is None
        assert got.get(0x16EC38, None) is None
        results['bl_census'] = {
            hex(k): [hex(x) for x in sorted(v)] for k, v in CENSUS.items()}
        results['bl_16f920_count'] = CENSUS_16F920_COUNT

        # --- 2. descriptor table bytes ----------------------------------
        pidx = payload_of(blocks, 0x392F04)
        assert pidx == 1, pidx
        raw = payloads[pidx][0x392F04 - base[pidx]: 0x392F04 - base[pidx]
                             + 320]
        results['descriptor_table_sha256'] = hashlib.sha256(raw).hexdigest()
        for i, (m_lo, m_hi, bit, classe, flags, pev) in enumerate(
                DESC_TABLE):
            d = raw[20 * i: 20 * i + 20]
            assert struct.unpack_from('<I', d, 0)[0] == m_lo, i
            assert struct.unpack_from('<I', d, 4)[0] == m_hi, i
            assert d[8] == bit, i
            assert d[9] == classe, i
            assert struct.unpack_from('<I', d, 0xA)[0] == flags, i
            assert struct.unpack_from('<H', d, 0xC)[0] == pev, i
            if bit < 32:
                assert m_lo == (1 << bit) and m_hi == 0, i
            else:
                assert m_hi == (1 << (bit - 32)) and m_lo == 0, i
            kp = KEYMAP[classe]
            assert kp[0] == bit and kp[1] == (classe << 7) \
                and kp[2] == (classe << 7) | 1, (classe, kp)
        results['keymap'] = {
            hex(c): dict(bit=b, press=hex(p), release=hex(r))
            for c, (b, p, r) in sorted(KEYMAP.items())}

        # --- 3. pool words ------------------------------------------------
        for addr, value in POOL_WORDS.items():
            p = payload_of(blocks, addr)
            assert p is not None, hex(addr)
            w = struct.unpack_from('<I', payloads[p], addr - base[p])[0]
            assert w == value, (hex(addr), hex(w), hex(value))
        results['pool_words'] = {hex(a): hex(v) for a, v
                                 in POOL_WORDS.items()}

        # --- 4. installer call site ---------------------------------------
        pat = re.compile(
            r'V0016E302 \| [0-9a-f ]+\| ld_s\t?r0,\[pcl,0x88\]\t;0x16e388')
        assert any(pat.search(ln) for ln in lines), 'installer pool load'
        pat = re.compile(r'V0016E304 \| [0-9a-f ]+\| mov_s\tr1,0x10')
        assert any(pat.search(ln) for ln in lines), 'installer count'
        pat = re.compile(r'V0016E306 \| [0-9a-f ]+\| bl\t4968\t;0x16f66c')
        assert any(pat.search(ln) for ln in lines), 'installer call'
        pat = re.compile(r'V0016E30A \| [0-9a-f ]+\| bl\.d\t5760\t;0x16f988')
        assert any(pat.search(ln) for ln in lines), 'callback register'
        pat = re.compile(r'V0016E30E \| [0-9a-f ]+\| ld_s\tr0,\[pcl,0x80\]'
                        r'\t;0x16e38c')
        assert any(pat.search(ln) for ln in lines), 'callback pool load'
        pat = re.compile(r'V0016E31A \| [0-9a-f ]+\| bl\t-187564\t;0x14066c')
        assert any(pat.search(ln) for ln in lines), 'raw reader call'
        pat = re.compile(r'V0016E336 \| [0-9a-f ]+\| bl\t5560\t;0x16f8ec')
        assert any(pat.search(ln) for ln in lines), 'sync call'

        # --- 5. LE scans ---------------------------------------------------
        def le_scan(val):
            hits = []
            needle = struct.pack('<I', val)
            for b in blocks:
                data = payloads[b['index']]
                start = 0
                while True:
                    i = data.find(needle, start)
                    if i < 0:
                        break
                    hits.append((b['index'], base[b['index']] + i))
                    start = i + 1
            return hits
        for val, want in LE_EXPECT.items():
            assert sorted(le_scan(val)) == sorted(want), (
                hex(val), [hex(h[1]) for h in le_scan(val)])
        results['le_scans'] = {hex(v): [(p, hex(a)) for p, a in e]
                               for v, e in LE_EXPECT.items()}

        # --- 6. ctx static content (documentation) --------------------------
        ctx = payloads[1][0x3678E4 - base[1]: 0x3678E4 - base[1] + 0x14]
        assert ctx[0] == 0 and struct.unpack_from('<I', ctx, 4)[0] == 0 \
            and struct.unpack_from('<I', ctx, 8)[0] == 0, ctx.hex()
        results['ctx_at_rest'] = dict(base=hex(0x3678E4),
                                      bytes14=ctx.hex(),
                                      note='zero nel dump (pre-init)')

        # --- 7. CPU cases ---------------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
                                   output=out, action='key-machine-map'))
        r.prepare()
        r.results.update(static_pass=results)
        cases = []
        for idx, spec in enumerate(CPU_SPECS):
            name = spec['name']
            windows = spec['windows'] + [W_MILI]
            asm = (harness(setup_asm(), spec['extra'])
                   + ''.join(gen() for (_, _, gen) in STUB_SECTIONS)
                   + probe(spec['asserts'], spec['success'], idx))
            s = out / f'{name}.s'
            s.write_text(asm)
            obj = out / f'{name}.o'
            assert r.command(f'{name}_as', [
                TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL',
                '-o', obj, s]).returncode == 0
            bin_objs = []
            for (pidxw, wlo, whi, section) in windows:
                assert payload_of(blocks, wlo) == pidxw, (hex(wlo), pidxw)
                data = payloads[pidxw][wlo - base[pidxw]: whi - base[pidxw]]
                orig = out / f'{name}_{section}.bin'
                orig.write_bytes(data)
                bo = out / f'{name}_{section}_bin.o'
                assert r.command(f'{name}_{section}_oc', [
                    TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary',
                    '-O', 'elf32-littlearc', '-B', 'arc',
                    '--rename-section',
                    f'.data={section},alloc,load,readonly,code,contents',
                    '--change-section-vma', f'.data={hex(wlo)}',
                    '--strip-all', orig, bo]).returncode == 0
                bin_objs.append(bo)
            elf = out / f'{name}.elf'
            ld = out / f'{name}.ld'
            ld.write_text(
                'ENTRY(_start)\nSECTIONS {\n'
                '  .text 0x1000 : { *(.text .text.*) }\n'
                + ''.join(f'  {section} {hex(wlo)} : {{ *({section}) }}\n'
                          for (_, wlo, _, section) in windows)
                + ''.join(f'  {sec} {hex(addr)} : {{ *({sec}) }}\n'
                          for (sec, addr, _) in STUB_SECTIONS)
                + ''.join(f'  {sec} {hex(addr)} : {{ *({sec}) }}\n'
                          for (sec, addr, _) in RAM_SECTIONS)
                + f'  .probe {hex(PROBE_AT)} : {{ *(.probe) }}\n'
                  f'  .log {hex(LOG)} : {{ *(.log) }}\n'
                  '  .stack 0xC8F000 (NOLOAD) : { *(.stack .stack.*) }\n'
                  '} \n')
            cmd = [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-T', ld, '-o', elf,
                   obj] + bin_objs
            assert r.command(f'{name}_ld', cmd).returncode == 0
            ep, segments = elf_loads(elf)
            assert ep == 0x1000, hex(ep)
            for (pidxw, wlo, whi, section) in windows:
                want = payloads[pidxw][wlo - base[pidxw]: whi - base[pidxw]]
                by = [seg for seg in segments
                      if seg['address'] <= wlo
                      and wlo + (whi - wlo) <= seg['address'] + seg['size']]
                assert len(by) == 1, (hex(wlo), segments)
                data = by[0]['data'][wlo - by[0]['address']:]
                assert data[:whi - wlo] == bytes(want), hex(wlo)
            case, sim_text = r.run(name, '/result/' + f'{name}.elf')
            assert case['exit_code'] == 11, (name, case)
            fault = case['fault']
            assert fault is not None and fault['operation'] == 'read', (
                name, fault)
            assert int(fault['address'], 16) == spec['success'], (
                name, fault, hex(spec['success']))
            cases.append(dict(name=name, success=hex(spec['success']),
                              instructions=case['instructions'],
                              fault=fault, original_bytes=True))
            print(f'PASS {name} -> {hex(spec["success"])}', flush=True)
        assert len(cases) == 9, len(cases)
        results['cpu_cases'] = cases
        results['status'] = 'PASS'
        results['verdict'] = 'PASS_KEY_MACHINE_STATIC_MAP_CPU'
        print('PASS_KEY_MACHINE_STATIC_MAP_CPU', stamp)
    except AssertionError as exc:
        results['status'] = 'FAIL'
        results['error'] = repr(exc)
        print('FAIL:', exc, flush=True)
        raise
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')
        if results['status'] == 'PASS':
            latest = ROOT / 'Risultati/GUI_S33/key_machine_static_map_latest.json'
            latest.write_text(json.dumps(results, indent=2, default=str)
                              + '\n')
        print('Evidence:', out / 'verified_evidence.json')


if __name__ == '__main__':
    main()
