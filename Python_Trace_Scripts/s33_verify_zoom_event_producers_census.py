#!/usr/bin/env python3
"""Censimento dei produttori runtime degli eventi zoom 0x380/0x400 (+rilasci
0x381/0x401) verso la finestra AutoSceneLiveView (registro p3 0x783B08,
handler 0x65B3A8), dei CANCELLATORI dell'anello 0x17BF60 e della libreria
di iniettori p4 + 4 casi CPU su byte ORIGINALI. Chiude il punto (a)
dell'iterazione 48; revisione indipendente agente producer-review-45
integrata (correzioni C2/C3/C5/C6/C7).

Fatti qui assunti (congelati):

- API di post/coda: census bl di 0x169EB4 = 304, 0x169F40 = 28,
  0x169F00 = 33, 0x16F6B0 = 7, 0x17BF60 = 188 (i tail-jump b/b.d e le
  chiamate indirette jl_s NON sono nel census, come in it.45).
- 0x16F6B0 (p0) e' il fan-out della macchina tasti: fino a 10 callback
  prese da 0x446808+512+4i (add2 scala 4, provato in it.39; ld.as
  [r1,128] scala 4 -> +512), con (r17=ctx, r18, sp+0x20); poi, se
  byte[pool 0x16FA40 = 0x3678F9] != 0 e r4 != 0 ed esito callback != 0 e
  0x16F6A4(ctx) != 0, inserisce (0, evento_halfword_r2, r3, 1) nell'anello
  0x17BC7C. La tabella callback 0x446A08 e' fuori dai 16 payload
  verificati: contenuto APERTO. NESSUN evento 0x380/0x400/0x381/0x401
  nei suoi 7 chiamanti (eventi dinamici; costanti/pool: 0x581@0x26C5C2,
  0x3B81 pool@0x20F74E).
- 0x17BF60 (p0) NON e' un produttore: cammina l'anello 0x47A848 e AZZERA
  l'evento dei record con desc == r0 (0: qualunque) ed evento in [r1..r2].
  Census dei chiamanti bl con range risolvibile (mov/mov_s, ld pcl pool,
  copia da registro, asl concatenati, def nel delay slot di bl.d, propria
  e altrui): 76 siti coprenti 0x380/0x400 congelati per range:
  [0x1,0x7FFF]x1, [0x80,0x307F]x65, [0x300,0x500]x2, [0x380,0x380]x4,
  [0x400,0x400]x4. NON coprenti dimostrati: 0x16F97E (bl.d con delay slot
  asl_s r1,r1,0xa -> lo = 0x15<<10 = 0x5400: range [0x5400,0x57FF]),
  0x65A898 (mov r1,0xC + bset_s r1,r1,0xe + mov r2,r1 -> [0x400C,
  0x400C]). NON risolvibili staticamente in locale (limiti): 0x65B342
  (r1 dinamico) e gli altri ~110 chiamanti con argomenti calcolati.
  Piu' i CANCELLATORI INDIRETTI jl_s [pool=0x17BF60]: 0x65B640/0x65B64A/
  0x65B6BA/0x65B6C4 (dentro l'handler di rilascio 0x65B5D4), 0x65D2F6/
  0x65D300, 0x9DEFBE/0x9DEFC8, 0x7F7DEE/0x7F7DF8, 0x7FA484/0x7FA48E.
- PRODUTTORI diretti a costante via 0x169EB4 (nearest-def):
  0x380 x8, 0x400 x10, 0x381 x1, 0x401 x1 (liste congelate sotto) + il
  SITO DUALE 0x65B700: raggiunto da DUE rami dell'handler di rilascio
  (0x65B6EA mov r1,1024 = 0x400 con b_s 0x65B6FE; 0x65B6FA mov r1,896 =
  0x380): posta (r13, 0x400/0x380, 0) a seconda del ramo. NESSUN hit
  per questi id via 0x169F40/0x169F00.
- Libreria iniettori p4 (desc=0, finestra corrente): press+release con
  arg 0xFF/0: 0x80BC7C=(0x400,0x401), 0x80BD4C=(0x480,0x481),
  0x80BDE8=(0x500,0x501), 0x80BE84=(0x380,0x381); con arg 0/0:
  0x80BD18=(0x200,0x201), 0x80BC48=(0x780,0x781); e le coppie estese
  (revisione): 0x80BF4A=(0x700,0x701), 0x80BFB2=(0x580,0x581),
  0x80BFF4=(0x600,0x601), 0x80C026=(0x680,0x681). Auto-ripetizione
  (stesso evento, periodo pool 0x186A0 = 100000): 0x80BCB0=0x400,
  0x80BD80=0x480, 0x80BE1C=0x500, 0x80BEB8=0x380. Pool periodo a
  0x80BD08/0x80BDD8/0x80BE74/0x80BF10 = 0x186A0.
- Dispatcher 0x809F78(record r0, cmd_id r1): UNICO chiamante bl
  0x2D77BE (p0, interprete comandi); catena cmp_s r14,id/bne_s byte-
  verificata per i casi 0x24..0x36 e 0x3A (elenco congelato sotto; NB
  la revisione indicava 0x37 per 0x80BE84: il caso reale e' 0x3A, sito
  0x80A3E4), arg r0 = [[r13]] dal record.
- REGISTRO finestra p3 0x783B08..0x783C40: 39 record (id,handler) col
  terminatore (0, 0x20E814). Chiave: 0x380/0x400 -> 0x65B3A8
  (consumatore it.48) e 0x381/0x401 -> 0x65B5D4 (handler di RILASCIO;
  la riga del listato a 0x65B5D2 e' la decodifica spuria della coda
  del pool 0x4111 a 0x65B5D0; l'entry reale e' push_s blink a 0x65B5D4,
  byte congelati). 0x65B5D4 NON ha chiamanti bl e NON ha parole LE:
  raggiunto SOLO tramite il registro p3.
- Handler 0x65B5D4 (rilascio): cancel (0,0x400,0x400) e (0,0x380,0x380)
  via jl_s [r14=pool 0x65B714=0x17BF60] (due volte ciascuno in rami
  diversi); stati [ctx+4] {4,5} letti (0x65B61A-24); alla fine
  0x16F920(8)!=0 -> post (r13,0x400,0) via 0x169EB4@0x65B700, altrimenti
  0x16F920(7)!=0 -> post (r13,0x380,0): RIPUBBLICA l'evento del tasto
  ancora premuto quando l'altro viene rilasciato. Percorsi alternativi
  (revisione, statici): se un flag resta -> bl.d 0x145C3C con delay slot
  ld.as [pcl,-208] -> 0x65B39C = 0x30D40 (attesa 200000) prima del
  ri-controllo; l'uscita 0x65B704 e' b 0x65B1B8 (loop macchina a
  stati, NON un return al dispatcher del registro).
- CPU (byte originali, motore pinnato GNU ARC700): il bl SENZA .d NON ha
  delay slot: in 0x80BEB8 il b_s -32 a 0x80BEF8 e' il loop-back DOPO il
  ritorno di 0x169EB4 (esplorazione 20261101: DUR 250000 -> 3 post/3
  sleep, 50000 -> 1/1, 350000 -> 4/4). Il bl.d 0x145C3C con delay slot
  ld_s r0,[pcl,0x28] -> pool 0x80BF10 = 0x186A0 riceve il periodo. I b
  negativi-large verso gli epiloghi millicode 0x3341A4/0x33418C
  (finestra 0x334100..0x3341E4) sono eseguiti dal motore pinnato.

Read-only: firmware, blocchi, strumenti, listati mai modificati.
Nessun hardware/USB/SD; NON_INSTALLARE invariato.
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
NPOST = LOG + 40
NSLEEP = LOG + 44
POST_ENT = LOG + 64           # 16 bytes per entry: desc, ev, arg
SLEEP_ENT = LOG + 192         # 8 bytes per entry: arg
W_MILI = (0, 0x334100, 0x3341E4, '.mili')

# ---------------------------------------------------------------- frozen ----
API_CALLERS = {0x169EB4: 304, 0x169F40: 28, 0x169F00: 33,
               0x16F6B0: 7, 0x17BF60: 188}
POST_APIS = (0x169EB4, 0x169F40, 0x169F00)
TARGET_EVENTS = (0x380, 0x400, 0x381, 0x401)
PRODUCERS_169EB4 = {
    0x380: [0x654322, 0x65B700, 0x7CBC72, 0x802036, 0x80BE9A,
            0x80BED4, 0x80BEF4, 0x9E223A],
    0x400: [0x2101F2, 0x654B04, 0x654B9C, 0x7CBC8A, 0x80204E,
            0x8020BA, 0x80BC92, 0x80BCCC, 0x80BCEC, 0x9E2250],
    0x381: [0x80BEA6],
    0x401: [0x80BC9E],
}
DUAL_POST = (0x65B700, 0x380, 0x400)   # both r1=896 and r1=1024 reach it
DESC_KINDS = {
    0x654322: 'zero', 0x65B700: 'r13', 0x7CBC72: 'r13', 0x802036: 'r13',
    0x80BE9A: 'zero', 0x80BED4: 'r14', 0x80BEF4: 'r16', 0x9E223A: 'r13',
    0x2101F2: 'ret1453f4', 0x654B04: 'r13', 0x654B9C: 'r13',
    0x7CBC8A: 'r13', 0x80204E: 'r13', 0x8020BA: 'r14', 0x80BC92: 'zero',
    0x80BCCC: 'r14', 0x80BCEC: 'r16', 0x9E2250: 'r13',
    0x80BEA6: 'zero', 0x80BC9E: 'zero',
}
FANOUT_CONSTS = {0x26C5C2: 0x581}      # bl to 0x16F6B0 with const r2
FANOUT_POOLS = {0x20F74E: 0x3B81}
POOL_WORDS = {
    0x65B5D0: 0x4111, 0x65B708: 0x681F83, 0x65B70C: 0xBB8,
    0x65B710: 0x681F5C, 0x65B714: 0x17BF60, 0x65B718: 0x16F920,
    0x65B39C: 0x30D40,
    0x16FA3C: 0x446808, 0x16FA40: 0x3678F9,
    0x16FA54: 0x307F, 0x16FA58: 0x57FF,
    0x80BD08: 0x186A0, 0x80BDD8: 0x186A0,
    0x80BE74: 0x186A0, 0x80BF10: 0x186A0,
    0x652E54: 0x307F, 0x6591EC: 0x307F,
    0x7D48B0: 0x307F, 0x7FAB84: 0x7C60,
}
RELEASE_ENTRY = (0x65B5D4, 14, 'f1c0520b4e6cfc1cc8b60a230037')
REGISTRY_P3 = [
    (0x4401, 0x659554), (0x4405, 0x65959C), (0x4406, 0x659EF0),
    (0x4409, 0x65A4A4), (0x440E, 0x659FA0), (0x400C, 0x65A708),
    (0x7D40, 0x65AB5C), (0x80, 0x65AC58), (0x81, 0x65B060),
    (0x100, 0x65B1CC), (0x380, 0x65B3A8), (0x381, 0x65B5D4),
    (0x400, 0x65B3A8), (0x401, 0x65B5D4), (0x480, 0x65BEA4),
    (0x500, 0x65BEA4), (0x600, 0x65BF00), (0x180, 0x65C2CC),
    (0x181, 0x65C404), (0x3101, 0x65C418), (0x580, 0x65C46C),
    (0x700, 0x65C46C), (0x2180, 0x65C46C), (0x2700, 0x65C46C),
    (0x581, 0x65C6B4), (0x2701, 0x65C6B4), (0x3181, 0x65C228),
    (0x3281, 0x65BFDC), (0x3B81, 0x65C08C), (0x3301, 0x65C178),
    (0x4001, 0x65C928), (0x4006, 0x65CA60), (0x4005, 0x65CA04),
    (0x4110, 0x65CC40), (0x4111, 0x65CCC8), (0x4002, 0x65CD54),
    (0x4008, 0x65CD98), (0x7CEA, 0x65B9E4), (0x4104, 0x65BA40),
]
REGISTRY_TERM = (0, 0x20E814)
LE_EXPECT = {
    0x65B3A8: [(3, 0x783B5C), (3, 0x783B6C)],
    0x65B5D4: [(3, 0x783B64), (3, 0x783B74)],
    0x65BEA4: [(3, 0x783B7C), (3, 0x783B84)],
    0x65C46C: [(3, 0x783BAC), (3, 0x783BB4), (3, 0x783BBC),
               (3, 0x783BC4)],
    0x809F78: [], 0x65B5D6: [],
}
CANCELLERS_FROZEN = {
    (0x1, 0x7FFF): [0x16A102],
    (0x80, 0x307F): [0x144D9A, 0x16ECE4, 0x16F972, 0x175828, 0x20F3FC,
                     0x2B425E, 0x2D0A18, 0x2FE688, 0x2FE8B2, 0x64D4A4,
                     0x64E084, 0x64E866, 0x64F358, 0x64FEC2, 0x652958,
                     0x652A8E, 0x652C1A, 0x652D0C, 0x65328C, 0x65408E,
                     0x65437E, 0x65439C, 0x654B6C, 0x655B20, 0x6591CA,
                     0x659828, 0x6599CE, 0x659A66, 0x65A88A, 0x65A9DA,
                     0x65B334, 0x65BF98, 0x65C57C, 0x65CC04, 0x661F56,
                     0x662118, 0x662164, 0x6621A2, 0x6621E2, 0x6621FC,
                     0x6635AE, 0x663A98, 0x7D4886, 0x7D5130, 0x7D6322,
                     0x7DB2AA, 0x7E3F0E, 0x7F6EE8, 0x7F7068, 0x7F7D2A,
                     0x7FA3A0, 0x7FAA8A, 0x7FDA2E, 0x7FDC6A, 0x7FDE7E,
                     0x7FEBBC, 0x7FEF8C, 0x7FF69C, 0x801858, 0x801ED2,
                     0x8025DC, 0x9D817A, 0x9D8A2C, 0x9DBE10, 0x9DC3CE],
    (0x300, 0x500): [0x7DCFA8, 0x9D6EB2],
    (0x380, 0x380): [0x654760, 0x801FFA, 0x802160, 0x9DEDD6],
    (0x400, 0x400): [0x65476C, 0x802006, 0x80216C, 0x9DEDE2],
}
NON_COVERING = [
    (0x16F97E, 0x5400, 0x57FF, 'bl.d delay slot asl_s r1,r1,0xa'),
    (0x65A898, 0x400C, 0x400C, 'mov r1,0xC + bset_s r1,r1,0xe + mov r2,r1'),
]
INDIRECT_CANCELLERS = [
    (0x65B640, 0, 0x400, 0x400), (0x65B64A, 0, 0x380, 0x380),
    (0x65B6BA, 0, 0x400, 0x400), (0x65B6C4, 0, 0x380, 0x380),
    (0x65D2F6, 0, 0x380, 0x380), (0x65D300, 0, 0x400, 0x400),
    (0x9DEFBE, 0, 0x380, 0x380), (0x9DEFC8, 0, 0x400, 0x400),
    (0x7F7DEE, 0, 0x380, 0x381), (0x7F7DF8, 0, 0x400, 0x401),
    (0x7FA484, 0, 0x380, 0x381), (0x7FA48E, 0, 0x400, 0x401),
]
DISPATCHER_CALLERS = [0x2D77BE]
DISPATCH_CASES = [
    (0x24, 0x80BC28, 0x80A294), (0x25, 0x80BC48, 0x80A2A8),
    (0x26, 0x80BC7C, 0x80A2B8), (0x27, 0x80BD18, 0x80A2C8),
    (0x28, 0x80BCB0, 0x80A2D8), (0x29, 0x80BD80, 0x80A2E8),
    (0x2A, 0x80BE1C, 0x80A2F8), (0x2B, 0x80BEB8, 0x80A308),
    (0x2C, 0x80BF20, 0x80A318), (0x2D, 0x80BD4C, 0x80A328),
    (0x2E, 0x80BF34, 0x80A338), (0x2F, 0x80BF68, 0x80A348),
    (0x30, 0x80BF9C, 0x80A358), (0x31, 0x80BD0C, 0x80A364),
    (0x32, 0x80BDDC, 0x80A370), (0x33, 0x80BE78, 0x80A37C),
    (0x34, 0x80BF14, 0x80A388), (0x35, 0x80BFD0, 0x80A398),
    (0x36, 0x80BDE8, 0x80A3A8), (0x3A, 0x80BE84, 0x80A3E4),
]
INJECTOR_PAIRS = [
    (0x80BC7C, 0x400, 0x401, 0xFF), (0x80BD4C, 0x480, 0x481, 0xFF),
    (0x80BDE8, 0x500, 0x501, 0xFF), (0x80BE84, 0x380, 0x381, 0xFF),
    (0x80BD18, 0x200, 0x201, 0), (0x80BC48, 0x780, 0x781, 0),
]
EXTENDED_PAIRS = [
    (0x80BF4A, 0x700, 0x701), (0x80BFB2, 0x580, 0x581),
    (0x80BFF4, 0x600, 0x601), (0x80C026, 0x680, 0x681),
]
REPEATERS = [(0x80BCB0, 0x400), (0x80BD80, 0x480),
             (0x80BE1C, 0x500), (0x80BEB8, 0x380)]


def post_entry(k, desc, ev, arg):
    return [(POST_ENT + 16 * k + 0, 4, desc),
            (POST_ENT + 16 * k + 4, 4, ev),
            (POST_ENT + 16 * k + 8, 4, arg)]


def sleep_entry(k, arg):
    return [(SLEEP_ENT + 8 * k, 4, arg)]


CPU_SPECS = [
    dict(name='press380', entry=0x80BE84, arg=0x55AA,
         windows=[(4, 0x80BE84, 0x80BEB6, '.origpr')],
         asserts=([(NPOST, 4, 2), (NSLEEP, 4, 0)]
                  + post_entry(0, 0, 0x380, 0xFF)
                  + post_entry(1, 0, 0x381, 0)),
         success=0xDEADB101),
    dict(name='repeat380_d250', entry=0x80BEB8, arg=250000,
         windows=[(4, 0x80BEB8, 0x80BF0E, '.origrp'),
                  (4, 0x80BF10, 0x80BF14, '.poolf10')],
         asserts=([(NPOST, 4, 3), (NSLEEP, 4, 3)]
                  + post_entry(0, 0, 0x380, 0xFF)
                  + post_entry(1, 0, 0x380, 0xFF)
                  + post_entry(2, 0, 0x380, 0xFF)
                  + sleep_entry(0, 100000) + sleep_entry(1, 100000)
                  + sleep_entry(2, 50000)),
         success=0xDEADB201),
    dict(name='repeat380_d50', entry=0x80BEB8, arg=50000,
         windows=[(4, 0x80BEB8, 0x80BF0E, '.origrp'),
                  (4, 0x80BF10, 0x80BF14, '.poolf10')],
         asserts=([(NPOST, 4, 1), (NSLEEP, 4, 1)]
                  + post_entry(0, 0, 0x380, 0xFF)
                  + sleep_entry(0, 50000)),
         success=0xDEADB301),
    dict(name='repeat380_d350', entry=0x80BEB8, arg=350000,
         windows=[(4, 0x80BEB8, 0x80BF0E, '.origrp'),
                  (4, 0x80BF10, 0x80BF14, '.poolf10')],
         asserts=([(NPOST, 4, 4), (NSLEEP, 4, 4)]
                  + post_entry(0, 0, 0x380, 0xFF)
                  + post_entry(1, 0, 0x380, 0xFF)
                  + post_entry(2, 0, 0x380, 0xFF)
                  + post_entry(3, 0, 0x380, 0xFF)
                  + sleep_entry(0, 100000) + sleep_entry(1, 100000)
                  + sleep_entry(2, 100000) + sleep_entry(3, 50000)),
         success=0xDEADB401),
]

# ------------------------------------------------------------- classifier ----
INSN_RE = re.compile(r'V([0-9A-F]{6,8}) \| [0-9a-f ]+\| (\S+)\s*(.*)')
CALL_API_RE = re.compile(r'V([0-9A-F]{6,8}) \| [0-9a-f ]+\| '
                         r'(bl|bl\.d|bl_s|bl_s\.d)\s+?-?\d+\s+'
                         r';0x(169eb4|169f40|169f00|16f6b0|17bf60)\b')


def load_lines():
    return LISTING.read_text(errors='replace').splitlines()


def census(lines):
    callers = {api: [] for api in API_CALLERS}
    for i, ln in enumerate(lines):
        m = CALL_API_RE.search(ln)
        if m:
            callers[int(m.group(3), 16)].append((i, int(m.group(1), 16)))
    return callers


def payload_of(blocks, addr):
    for b in blocks:
        if b['load_address_candidate'] <= addr < b['load_address_candidate'] + b['size']:
            return b['index']
    return None


def insn_at(lines, j):
    m = INSN_RE.search(lines[j])
    return (m.group(2), m.group(3).strip()) if m else (None, None)


def def_at(lines, blocks, payloads, base, j, reg):
    """const/pool def of reg at line j; ('reg',rX) for register copies."""
    op, args = insn_at(lines, j)
    if op in ('mov_s', 'mov') and args.startswith(reg + ','):
        rest = args[len(reg) + 1:].strip()
        if re.fullmatch(r'(0x[0-9a-f]+|\d+)', rest):
            return ('const', int(rest, 0))
        rm = re.fullmatch(r'r(\d+)', rest)
        if rm:
            return ('reg', 'r' + rm.group(1))
        return ('unknown', None)
    if op in ('ld_s', 'ld', 'ldw_s') and args.startswith(reg + ',') \
            and 'pcl' in args:
        pm = re.search(r';0x([0-9a-f]+)', args)
        if pm:
            paddr = int(pm.group(1), 16)
            pidx = payload_of(blocks, paddr)
            if pidx is not None:
                return ('pool', (pidx, paddr, struct.unpack_from(
                    '<I', payloads[pidx], paddr - base[pidx])[0]))
        return ('unknown', None)
    if op in ('bset_s', 'bset') and args.startswith(reg + ','):
        pm = re.fullmatch(reg + r',' + reg + r',(0x[0-9a-f]+|\d+)',
                          args.strip())
        if pm:
            return ('bset', int(pm.group(1), 0))
    return None


def asl_at(lines, j, reg):
    op, args = insn_at(lines, j)
    if op not in ('asl_s', 'asl'):
        return None
    m = re.fullmatch(reg + r',' + reg + r',(0x[0-9a-f]+|\d+)', args)
    return int(m.group(1), 0) if m else None


def resolve_reg(lines, blocks, payloads, base, i, reg, depth=0):
    """Nearest def of reg walking back from line i; handles asl chains,
    register copies (depth 1), delay slots of preceding bl.d."""
    scale = 1
    for j in range(i - 1, max(0, i - 40), -1):
        op, args = insn_at(lines, j)
        if op is None:
            continue
        k = asl_at(lines, j, reg)
        if k is not None:
            scale *= 2 ** k
            continue
        d = def_at(lines, blocks, payloads, base, j, reg)
        if d is not None:
            if d[0] == 'const':
                return (d[0], d[1], d[1] * scale if scale > 1 else d[1],
                        scale)
            if d[0] == 'pool':
                w = d[1][2]
                return (d[0], d[1], w * scale if scale > 1 else w, scale)
            if d[0] == 'reg' and depth < 1:
                sub = resolve_reg(lines, blocks, payloads, base, j,
                                  d[1], depth + 1)
                if sub and sub[0] in ('const', 'pool'):
                    return (sub[0], sub[1], sub[2] * scale, scale)
            return ('unknown', None, None, 1)
        if op in ('bl', 'bl_s', 'jl', 'jl_s', 'jl_s.d', 'j', 'j_s'):
            return ('unknown', None, None, 1)
        if op in ('bl.d', 'bl_s.d'):
            d2 = def_at(lines, blocks, payloads, base, j + 1, reg)
            if d2 is not None and d2[0] in ('const', 'pool'):
                w = d2[1] if d2[0] == 'const' else d2[1][2]
                return (d2[0], d2[1], w * scale, scale)
            k2 = asl_at(lines, j + 1, reg)
            if k2 is not None:
                scale *= 2 ** k2
                continue
            return ('unknown', None, None, 1)
    return ('unknown', None, None, 1)


def classify_events(lines, blocks, payloads, base, callers):
    out = {api: {} for api in API_CALLERS}
    for api in API_CALLERS:
        reg = 'r2' if api == 0x16F6B0 else 'r1'
        for i, site in callers[api]:
            kind, val, scaled, _ = resolve_reg(lines, blocks, payloads,
                                               base, i, reg)
            if kind in ('const', 'pool'):
                out[api].setdefault(scaled, []).append(
                    site if kind == 'const' else (site, val[0], val[1]))
    return out


def classify_cancellers(lines, blocks, payloads, base, callers):
    hits = {}
    for i, site in callers[0x17BF60]:
        m = CALL_API_RE.search(lines[i])
        op = m.group(2)
        lo = hi = None
        if op in ('bl.d', 'bl_s.d'):
            d = def_at(lines, blocks, payloads, base, i + 1, 'r1')
            k = asl_at(lines, i + 1, 'r1')
            if d is not None and d[0] in ('const', 'pool'):
                lo = d[1] if d[0] == 'const' else d[1][2]
            elif k is not None:
                pv = resolve_reg(lines, blocks, payloads, base, i, 'r1')
                lo = pv[2] << k if pv[0] in ('const', 'pool') else None
            d = def_at(lines, blocks, payloads, base, i + 1, 'r2')
            if d is not None and d[0] in ('const', 'pool'):
                hi = d[1] if d[0] == 'const' else d[1][2]
        if lo is None:
            r = resolve_reg(lines, blocks, payloads, base, i, 'r1')
            lo = r[2] if r[0] in ('const', 'pool') else None
        if hi is None:
            r = resolve_reg(lines, blocks, payloads, base, i, 'r2')
            hi = r[2] if r[0] in ('const', 'pool') else None
        if lo is not None and hi is not None and \
                (lo <= 0x380 <= hi or lo <= 0x400 <= hi):
            hits.setdefault((lo, hi), []).append(site)
    return hits


def check_dual(lines):
    site, eva, evb = DUAL_POST
    pat_a = re.compile(r'V0*65B6EA \| [0-9a-f ]+\| mov\tr1,1024')
    pat_b = re.compile(r'V0*65B6FA \| [0-9a-f ]+\| mov\tr1,896')
    pat_j = re.compile(r'V0*65B6EE \| [0-9a-f ]+\| b_s\s+18\t;0x65b6fe')
    assert any(pat_a.search(ln) for ln in lines), 'dual mov r1,1024'
    assert any(pat_b.search(ln) for ln in lines), 'dual mov r1,896'
    assert any(pat_j.search(ln) for ln in lines), 'dual b_s join'


def check_dispatch(lines):
    got = []
    for case_id, target, expect_site in DISPATCH_CASES:
        bpat = re.compile(rf'V([0-9A-F]{{6,8}}) \| [0-9a-f ]+\| bl\s+?\d+\s'
                          rf';0x{target:x}\b')
        cpat = re.compile(rf'cmp_s\tr14,0x{case_id:x}\b')
        found = None
        for i, ln in enumerate(lines):
            m = bpat.search(ln)
            if not m:
                continue
            if any(cpat.search(lines[j]) for j in
                   range(i - 1, max(0, i - 7), -1)):
                found = int(m.group(1), 16)
                break
        assert found == expect_site, (case_id, hex(found or 0))
        got.append((case_id, target, found))
    return got


def check_pairs(lines):
    for entry, evp, evr, argp in INJECTOR_PAIRS:
        seg = []
        for ln in lines:
            m = re.search(rf'V0*{entry:X} ', ln)
            if m:
                seg = [ln]
                continue
            if seg and re.search(r'V[0-9A-F]{6,8} ', ln):
                seg.append(ln)
                if len(seg) >= 20:
                    break
        assert seg, hex(entry)
        text = '\n'.join(seg)
        assert re.search(rf'mov\s+r1,{evp}\b', text), (hex(entry), evp)
        assert re.search(rf'mov\s+r1,{evr}\b', text), (hex(entry), evr)
        if not re.search(rf'mov_s\tr2,0x{argp:x}\b', text):
            assert argp == 0 and re.search(r'mov_s\tr2,r0\b', text) and \
                re.search(r'mov_s\tr0,0\b', text), (hex(entry), argp)
        assert ';0x169eb4' in text, hex(entry)
    for site, evp, evr in EXTENDED_PAIRS:
        i = next((i for i, ln in enumerate(lines)
                  if re.search(rf'V0*{site:X} \| [0-9a-f ]+\| bl\s'
                               r'+?-?\d+\s+;0x169eb4\b', ln)), None)
        assert i is not None, hex(site)
        before = '\n'.join(lines[max(0, i - 5):i])
        after = '\n'.join(lines[i + 1:i + 7])
        assert re.search(rf'mov\tr1,{evp}\b', before), (hex(site), evp)
        assert re.search(rf'mov\tr1,{evr}\b', after), (hex(site), evr)
    for entry, ev in REPEATERS:
        seg = []
        for ln in lines:
            m = re.search(rf'V0*{entry:X} ', ln)
            if m:
                seg = [ln]
                continue
            if seg and re.search(r'V[0-9A-F]{6,8} ', ln):
                seg.append(ln)
                if len(seg) >= 34:
                    break
        assert seg, hex(entry)
        text = '\n'.join(seg)
        assert len(re.findall(rf'mov\s+r1,{ev}\b', text)) >= 2, hex(entry)
        assert re.search(r'add\tr13,r14,0x186a0', text), hex(entry)
        assert ';0x145c3c' in text, hex(entry)


def check_non_covering(lines):
    # 0x16F97E: bl.d with delay slot asl_s r1,r1,0xa -> lo = 0x15<<10
    i97e = next(i for i, ln in enumerate(lines)
                if re.search(r'V0016F97E \| [0-9a-f ]+\| bl\.d', ln))
    op, args = insn_at(lines, i97e + 1)
    assert op == 'asl_s' and args == 'r1,r1,0xa', (op, args)
    # 0x65A898: mov r1,0xC + bset_s r1,r1,0xe + mov r2,r1
    i898 = next(i for i, ln in enumerate(lines)
                if re.search(r'V0065A898 \| [0-9a-f ]+\| bl', ln))
    op, args = insn_at(lines, i898 - 1)
    assert op == 'mov_s' and args == 'r2,r1', (op, args)
    op, args = insn_at(lines, i898 - 2)
    assert op == 'bset_s' and args == 'r1,r1,0xe', (op, args)
    op, args = insn_at(lines, i898 - 3)
    assert op == 'mov_s' and args == 'r1,0xc', (op, args)


def check_indirect_cancellers(lines):
    for site, desc, lo, hi in INDIRECT_CANCELLERS:
        i = next((i for i, ln in enumerate(lines)
                  if re.search(rf'V0*{site:X} \| [0-9a-f ]+\| jl_s', ln)), None)
        assert i is not None, hex(site)
        window = '\n'.join(lines[max(0, i - 8):i])
        assert re.search(rf'(?:mov|mov_s)\s+r0,{desc}\b', window), (
            hex(site), desc)
        assert re.search(rf'(?:mov|mov_s)\s+r1,{lo}\b', window), (
            hex(site), lo)
        if not re.search(rf'(?:mov|mov_s)\s+r2,{hi}\b', window):
            ok_copy = hi == lo and re.search(r'(?:mov|mov_s)\s+r2,r1\b',
                                             window)
            ok_add = hi == lo + 1 and re.search(
                r'add_s\tr2,r1,0x1\b', window)
            assert ok_copy or ok_add, (hex(site), hi)


def classify_descs(lines, blocks, payloads, base, sites):
    lines_idx = {}
    for i, ln in enumerate(lines):
        m = INSN_RE.search(ln)
        if m:
            lines_idx.setdefault(int(m.group(1), 16), i)
    out = {}
    for site in sites:
        i = lines_idx.get(site)
        assert i is not None, hex(site)
        for j in range(i - 1, max(0, i - 40), -1):
            op, args = insn_at(lines, j)
            if op in ('bl', 'bl.d', 'bl_s', 'bl_s.d', 'jl', 'jl_s',
                      'jl_s.d', 'j', 'j_s') and j < i:
                tm = re.search(r';0x([0-9a-f]+)', args)
                got = 'ret1453f4' if tm and int(tm.group(1), 16) \
                    == 0x1453F4 else f'ret:{args}'
                out[site] = got
                break
            if op in ('mov_s', 'mov') and args.startswith('r0,'):
                rest = args[3:].strip()
                if rest == '0':
                    out[site] = 'zero'
                elif re.fullmatch(r'r\d+', rest):
                    out[site] = rest
                else:
                    out[site] = f'mov:{rest}'
                break
        else:
            out[site] = 'unknown'
    return out


# -------------------------------------------------------------------- CPU ----
def stub_post():
    return ('.section .stub_post,"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            f' mov r3,{hex(LOG)}\n'
            ' ld r4,[r3,40]\n add r5,r4,1\n st r5,[r3,40]\n'
            ' asl r6,r4,4\n add r6,r6,r3\n'
            ' st r0,[r6,64]\n st r1,[r6,68]\n st r2,[r6,72]\n'
            ' mov r0,1\n pop_s blink\n j_s [blink]\n')


def stub_sleep():
    return ('.section .stub_sleep,"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            f' mov r3,{hex(LOG)}\n'
            ' ld r4,[r3,44]\n add r5,r4,1\n st r5,[r3,44]\n'
            ' asl r6,r4,3\n add r6,r6,r3\n'
            ' st r0,[r6,192]\n'
            ' mov r0,0\n pop_s blink\n j_s [blink]\n')


def probe(asserts, success, case_idx):
    text = []
    n = 0
    for addr, width, expected in asserts:
        text.append(f' mov r4,{hex(addr)}')
        text.append(' ldb r5,[r4,0]' if width == 1 else ' ld r5,[r4,0]')
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


def harness(entry, arg):
    return ('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            f' mov sp,{hex(STACK)}\n'
            f' mov r0,{hex(arg)}\n'
            f' mov r12,{hex(entry)}\n'
            ' jl_s [r12]\n'
            f' mov r12,{hex(PROBE_AT)}\n'
            ' j_s [r12]\n'
            '.section .log,"aw",@progbits\n.align 4\n .space 512\n'
            '.section .stack,"aw",@nobits\n.align 16\n .space 16384\n')


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'zoom_event_producers_census_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, block_dir = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp, action='zoom-producers-census',
                   limits=[
                       'Static analysis over the GNU listing + 4 CPU cases '
                       'on ORIGINAL bytes (pinned engine); no hardware',
                       'Canceller/event/desc classification bounded: defs '
                       'clobbered by non-delay-slot calls, computed by '
                       'add/sub/shift chains other than the handled ones, '
                       'or beyond 40 lines are NOT resolved (documented); '
                       'the independent review (~96 sites with its own '
                       'rules) agrees on every site both resolve',
                       'Tail-jumps b/b.d and indirect jl_s calls to the '
                       'post APIs are NOT in the bl census (as in it.45)',
                       '0x16F6B0 (key-machine fan-out) posts DYNAMIC event '
                       'ids: the physical key -> 0x380/0x400 map is OPEN; '
                       'its callback table 0x446A08 is outside the 16 '
                       'verified payloads',
                       '0x65B5D4 flow beyond the final post (200000 wait, '
                       'b 0x65B1B8 loop exit) is STATIC decode; CPU-proven '
                       'here only for the injector windows',
                       'CPU cases stub 0x169EB4/0x145C3C: no ring insert, '
                       'no real sleep; the WindowManager cycle is not run',
                       'V1.1 sample; NON_INSTALLARE'])
    try:
        # --- 1. bl censuses ------------------------------------------------
        lines = load_lines()
        callers = census(lines)
        counts = {api: len(sites) for api, sites in callers.items()}
        assert counts == API_CALLERS, counts
        results['api_caller_counts'] = {hex(k): v for k, v in counts.items()}

        # --- 2. producer classification ------------------------------------
        evmap = classify_events(lines, blocks, payloads, base, callers)
        for api in POST_APIS:
            for ev in TARGET_EVENTS:
                sites = sorted(evmap[api].get(ev, []))
                if api == 0x169EB4:
                    assert sites == PRODUCERS_169EB4[ev], (
                        hex(ev), [hex(s) if isinstance(s, int) else s
                                  for s in sites])
                else:
                    assert sites == [], (hex(api), hex(ev))
        results['producers'] = {
            hex(ev): [hex(s) for s in sites]
            for ev, sites in PRODUCERS_169EB4.items()}
        results['dual_post'] = dict(site=hex(DUAL_POST[0]),
                                    events=[hex(DUAL_POST[1]),
                                            hex(DUAL_POST[2])])
        check_dual(lines)
        fanout = {}
        for i, site in callers[0x16F6B0]:
            kind, val, scaled, _ = resolve_reg(lines, blocks, payloads,
                                               base, i, 'r2')
            if kind == 'const':
                assert scaled not in TARGET_EVENTS or site in FANOUT_CONSTS, \
                    (hex(site), hex(scaled))
            shown = (hex(scaled) if isinstance(scaled, int)
                     else hex(scaled[2]) if scaled else None)
            fanout[hex(site)] = [kind, shown]
        results['fanout_16f6b0_r2'] = fanout

        # --- 3. desc classification ----------------------------------------
        all_sites = [s for sites in PRODUCERS_169EB4.values() for s in sites]
        descs = classify_descs(lines, blocks, payloads, base, all_sites)
        for site in all_sites:
            assert descs[site] == DESC_KINDS[site], (
                hex(site), descs[site], DESC_KINDS[site])
        results['desc_kinds'] = {hex(s): k for s, k in descs.items()}

        # --- 4. canceller classification ------------------------------------
        canc = classify_cancellers(lines, blocks, payloads, base, callers)
        got = {k: sorted(v) for k, v in canc.items()}
        want = {k: sorted(v) for k, v in CANCELLERS_FROZEN.items()}
        assert got == want, (
            {hex(k): [hex(x) for x in v] for k, v in got.items()},
            {hex(k): [hex(x) for x in v] for k, v in want.items()})
        results['cancellers'] = {
            f'{hex(lo)}-{hex(hi)}': [hex(x) for x in sorted(v)]
            for (lo, hi), v in CANCELLERS_FROZEN.items()}
        results['cancellers_total'] = sum(
            len(v) for v in CANCELLERS_FROZEN.values())
        check_non_covering(lines)
        results['non_covering'] = [dict(site=hex(s), lo=hex(lo), hi=hex(hi),
                                        why=w) for s, lo, hi, w
                                   in NON_COVERING]
        check_indirect_cancellers(lines)
        results['indirect_cancellers'] = [
            dict(site=hex(s), desc=d, lo=hex(lo), hi=hex(hi))
            for s, d, lo, hi in INDIRECT_CANCELLERS]

        # --- 5. dispatcher + injector library -------------------------------
        assert check_dispatch(lines) == DISPATCH_CASES
        results['dispatch_cases'] = [
            dict(case_id=hex(c), target=hex(t), site=hex(s))
            for c, t, s in DISPATCH_CASES]
        dpat = re.compile(r'V([0-9A-F]{6,8}) \| [0-9a-f ]+\| '
                         r'(bl|bl\.d|bl_s|bl_s\.d)\s+?-?\d+\s+;0x809f78\b')
        d_callers = [int(m.group(1), 16) for ln in lines
                     for m in [dpat.search(ln)] if m]
        assert d_callers == DISPATCHER_CALLERS, d_callers
        results['dispatcher_callers'] = [hex(a) for a in d_callers]
        check_pairs(lines)
        results['injector_pairs'] = [
            dict(entry=hex(e), press=hex(p), release=hex(r), arg=a)
            for e, p, r, a in INJECTOR_PAIRS]
        results['extended_pairs'] = [
            dict(entry=hex(e), press=hex(p), release=hex(r))
            for e, p, r in EXTENDED_PAIRS]
        results['repeaters'] = [dict(entry=hex(e), event=hex(v))
                                for e, v in REPEATERS]

        # --- 6. pool words --------------------------------------------------
        for addr, value in POOL_WORDS.items():
            pidx = payload_of(blocks, addr)
            assert pidx is not None, hex(addr)
            got = struct.unpack_from('<I', payloads[pidx],
                                     addr - base[pidx])[0]
            assert got == value, (pidx, hex(addr), hex(got))
        results['pool_words'] = {f'{payload_of(blocks, a)}:{hex(a)}': hex(v)
                                 for a, v in POOL_WORDS.items()}

        # --- 7. registry p3 --------------------------------------------------
        a = 0x783B08
        got = []
        for _ in range(len(REGISTRY_P3) + 1):
            got.append((struct.unpack_from('<I', payloads[3],
                                           a - base[3])[0],
                        struct.unpack_from('<I', payloads[3],
                                           a + 4 - base[3])[0]))
            a += 8
        assert got == REGISTRY_P3 + [REGISTRY_TERM], [
            (hex(e), hex(h)) for e, h in got]
        results['registry_p3'] = dict(
            base=0x783B08, records=len(REGISTRY_P3),
            terminator_at=hex(0x783B08 + 8 * len(REGISTRY_P3)),
            map={hex(e): hex(h) for e, h in REGISTRY_P3})

        # --- 8. LE scans -----------------------------------------------------
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
        for val, expect in LE_EXPECT.items():
            assert sorted(le_scan(val)) == sorted(expect), (
                hex(val), [hex(h) for h in le_scan(val)])
        results['le_scans'] = {hex(v): [(i, hex(a)) for i, a in e]
                               for v, e in LE_EXPECT.items()}

        # --- 9. release handler entry bytes ---------------------------------
        lo, size, hexs = RELEASE_ENTRY
        pidx = payload_of(blocks, lo)
        assert pidx == 2, (hex(lo), pidx)
        gotb = payloads[pidx][lo - base[pidx]: lo - base[pidx] + size].hex()
        assert gotb == hexs, (hex(lo), gotb)
        results['release_entry'] = dict(
            addr=hex(lo), size=size,
            sha256=hashlib.sha256(bytes.fromhex(hexs)).hexdigest(), hex=hexs)

        # --- 10. CPU cases ---------------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
                                   output=out, action='zoom-producers-census'))
        r.prepare()
        r.results.update(static_pass=results)
        cases = []
        for idx, spec in enumerate(CPU_SPECS):
            name = spec['name']
            windows = spec['windows'] + [W_MILI]
            asm = (harness(spec['entry'], spec['arg']) + stub_post()
                   + stub_sleep() + probe(spec['asserts'], spec['success'],
                                          idx))
            s = out / f'{name}.s'
            s.write_text(asm)
            obj = out / f'{name}.o'
            assert r.command(f'{name}_as', [
                TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL',
                '-o', obj, s]).returncode == 0
            bin_objs = []
            for (pidx, wlo, whi, section) in windows:
                assert payload_of(blocks, wlo) == pidx, (hex(wlo), pidx)
                data = payloads[pidx][wlo - base[pidx]: whi - base[pidx]]
                orig = out / f'{name}_{section}.bin'
                orig.write_bytes(data)
                bo = out / f'{name}_{section}_bin.o'
                assert r.command(f'{name}_{section}_oc', [
                    TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary',
                    '-O', 'elf32-littlearc', '-B', 'arc', '--rename-section',
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
                + '  .stub_post 0x169EB4 : { *(.stub_post) }\n'
                  '  .stub_sleep 0x145C3C : { *(.stub_sleep) }\n'
                  f'  .probe {hex(PROBE_AT)} : {{ *(.probe) }}\n'
                  f'  .log {hex(LOG)} : {{ *(.log) }}\n'
                  '  .stack 0xC8F000 (NOLOAD) : { *(.stack .stack.*) }\n'
                  '} \n')
            cmd = [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-T', ld, '-o', elf,
                   obj] + bin_objs
            assert r.command(f'{name}_ld', cmd).returncode == 0
            ep, segments = elf_loads(elf)
            assert ep == 0x1000, hex(ep)
            for (pidx, wlo, whi, section) in windows:
                want = payloads[pidx][wlo - base[pidx]: whi - base[pidx]]
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
            cases.append(dict(name=name, entry=hex(spec['entry']),
                              arg=hex(spec['arg']),
                              success=hex(spec['success']),
                              instructions=case['instructions'],
                              fault=fault, original_bytes=True))
            print(f'PASS {name} -> {hex(spec["success"])}', flush=True)
        assert len(cases) == 4, len(cases)
        results['cpu_cases'] = cases
        results['status'] = 'PASS'
        results['verdict'] = 'PASS_ZOOM_EVENT_PRODUCERS_CENSUS'
        print('PASS_ZOOM_EVENT_PRODUCERS_CENSUS', stamp)
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
            latest = ROOT / 'Risultati/GUI_S33/zoom_event_producers_latest.json'
            latest.write_text(json.dumps(results, indent=2, default=str) + '\n')
        print('Evidence:', out / 'verified_evidence.json')


if __name__ == '__main__':
    main()
