#!/usr/bin/env python3
"""Static + CPU verification of the desired-mode cell producer (V1.1).

Closes the open point (a) of iteration 41 (checkpoint 2026-11-01): the runtime
producer of the "desired mode" cell 0x3657C8 (struct 0x365750 + 0x78, the same
struct that holds the guard byte at +1 and the saved-guard flag at +188).
Iteration 41 excluded direct [rN,120] stores inside bounded windows but left
the producer OPEN, with the documented lesson that writer censuses must also
cover NEARBY pool bases with small offsets - not only the exact cell pool.

Facts asserted here (byte-exact aligned windows + frozen call censuses over
the GNU listing + LE pool scans over all 16 payloads + 4 CPU cases on the GNU
ARC700 simulator executing ORIGINAL firmware bytes):

- The producer is the save function 0xD0478 (payload0): prologue helper
  0x334130, then in sequence 0xDE6D0 -> word 0x3657CA, 0xDE398 -> byte
  0x3657D0, 0x14A1F8 -> word 0x3657D4 clamped to <= 400, guard getter 0xCA310
  -> byte 0x3657CC (saved guard), 0x17E238 -> 0x3657CD, 0x17E460 -> 0x3657CE,
  0xDEBE8 -> 0x3657CF, and finally the mode cell 0xC8E80C (pool 0xD04D8 read
  by ld_s at 0xD04BE, EA=(PC&~3)+0x1c=0xD04D8) copied into 0x3657C8 by
  stb_s r0,[r13,0x8] at 0xD04C2 with r13 = pool 0xD04D0 = 0x3657C0; tail
  branch to the common epilogue 0xCA2CA -> 0x33419C.  The cell is therefore a
  SNAPSHOT OF THE CURRENT MODE taken when the shooting context is saved.
- Census: EXACTLY 5 bl callers of 0xD0478: 0x20ED7A (p0), 0x65602C, 0x65C3D4,
  0x66361A (p2), 0x8021FE (p4).  Three of them (0x65602C, 0x65C3D4, 0x8021FE)
  immediately transition to mode 3 (mov r0,3 + bl 0xCA404) after the save;
  0x66361A follows with the leave-shooting chain 0xCB5E4/0x145C3C/0xCBDF8/
  0x177030; 0x20ED7A notifies 0x7E via 0x1453E4.  The save therefore happens
  when LEAVING the shooting mode (4 of 5 sites leave it explicitly).
- Writer uniqueness (listing-wide, register-invalidated tracking of every base
  loaded from a pool whose value lies in [0x365740..0x365860], reset at
  function prologues, register invalidated on any other write, age limit 24):
  the ONLY store whose effective address is 0x3657C8 is V0D04C2.  Documented
  limits: writers via pointers passed in registers across calls, or via
  computed pointer arithmetic not involving a struct-window pool load, are
  NOT excluded by this scan.
- Block accessors: the saved-context block 0x3657C8..0x3657D4 has EXACTLY the
  pools listed in BLOCK_POOLS (LE scan, all in payload0); getters 0xD04DC
  (0x3657CC), 0xD04E8 (0x3657D0), 0xD04F4 (0x3657CD), 0xD0500 (0x3657CE),
  0xD050C (0x3657CF), 0xD0518 (WORD 0x3657D4 via the 32-bit pcl load
  ld r0,[pcl,-76], pool 0xD04CC), 0xD0520 (word 0x3657CA), 0xD0528
  (byte 0x3657C8); census: each block getter except
  0xD0528 has EXACTLY ONE bl caller (the restore function 0x7F9F7C reads
  word/bytes and feeds 0xCE1EC/0x17C5E4/0x14A900(0x64)/0x163D6C/0x17E124/
  0x17E36C/0xDEBCC; the saved guard 0x3657CC is read by 0xD04DC at 0x7F6AE6
  and copied to [pool 0x7F6E20]+0x18); 0xD0528 keeps the 21 callers frozen in
  iteration 41 (15 feeders of 0xCA404 + 6 context consumers comparing the
  saved mode against 0x6A/0x1F/0xA/0x37).
- CPU case (original bytes 0xD04BE..0xD04DB, including the pool 0xD04D8):
  with a fixture mode cell 0xC8E80C and r13 = 0x3657C0, the ORIGINAL ld_s/
  ldb_s/stb_s sequence copies the mode byte into 0x3657C8 and leaves the
  neighbours (+-1) untouched; with r13 redirected to a scratch block the
  desired cell keeps its sentinel (the store EA is r13+8, not a fixed
  address).  CPU probe of the 0xD0518 getter: executing the original bytes
  b4 17 00 f0 00 80 (ld r0,[pcl,-76] + ld_s r0,[r0,0]) resolves the 32-bit
  pcl load to the pool 0xD04CC = 0x3657D4 and loads the WORD saved there -
  NOT the byte 0x3657CF guessed by the interrupted session (that byte is
  read by the getter 0xD050C via pool 0xD0514); this extends the it.40
  ld.as EA lesson to the 32-bit ld encoding (EA = PC + imm for the
  4-aligned 32-bit form).

Read-only: firmware, blocks, tools and listings are never modified.
No hardware, no USB/SD access; NON_INSTALLARE state unchanged.
"""
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_capture_transition_caller_census import (
    window_lines, DESIRED_GETTER_CENSUS, DESIRED_FEEDERS)
from s33_verify_capture_guard_setter_census import LISTING, CENSUS_PATTERN
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, elf_loads

SAVE_FUNC = 0xD0478
DESIRED_CELL = 0x3657C8
MODE_CELL = 0xC8E80C
STRUCT = 0x365750
WINDOW_LO, WINDOW_HI = 0x365740, 0x365860

BLOCK_POOLS = {
    0x3657C8: [0xD0530],
    0x3657CA: [0xD04C8],
    0x3657CC: [0xD04D4, 0xD04E4],
    0x3657CD: [0xD04FC],
    0x3657CE: [0xD0508],
    0x3657CF: [0xD0514],
    0x3657D0: [0xD04F0],
    0x3657D4: [0xD04CC],
}
SAVE_POOLS = {
    0xD04C8: 0x3657CA, 0xD04CC: 0x3657D4, 0xD04D0: 0x3657C0,
    0xD04D4: 0x3657CC, 0xD04D8: MODE_CELL, 0xD0530: DESIRED_CELL,
    0xD04E4: 0x3657CC, 0xD04F0: 0x3657D0, 0xD04FC: 0x3657CD,
    0xD0508: 0x3657CE, 0xD0514: 0x3657CF,
}

SAVE_CALLERS = [0x20ED7A, 0x65602C, 0x65C3D4, 0x66361A, 0x8021FE]

# byte-exact window of the whole save function (payload0)
SAVE_LINES = [
    (0x0D0478, 'push_s\tblink'),
    (0x0D047A, 'bl\t2505912\t;0x334130'),
    (0x0D047E, 'bl\t57940\t;0xde6d0'),
    (0x0D0482, 'ld_s\tr1,[pcl,0x48]\t;0xd04c8'),
    (0x0D0484, 'ld_s\tr14,[pcl,0x48]\t;0xd04cc'),
    (0x0D0486, 'stw_s\tr0,[r1,0]'),
    (0x0D0488, 'bl\t57104\t;0xde398'),
    (0x0D048C, 'ld_s\tr13,[pcl,0x44]\t;0xd04d0'),
    (0x0D048E, 'stb_s\tr0,[r13,0x10]'),
    (0x0D0490, 'bl\t499048\t;0x14a1f8'),
    (0x0D0494, 'ld_s\tr1,[pcl,0x40]\t;0xd04d4'),
    (0x0D0496, 'st_s\tr0,[r1,0x8]'),
    (0x0D0498, 'ld_s\tr0,[r14,0]'),
    (0x0D049A, 'cmp\tr0,400'),
    (0x0D049E, 'bls_s\t10\t;0xd04a6'),
    (0x0D04A0, 'mov\tr0,400'),
    (0x0D04A4, 'st_s\tr0,[r1,0x8]'),
    (0x0D04A6, 'bl\t-24980\t;0xca310'),
    (0x0D04AA, 'stb_s\tr0,[r13,0xc]'),
    (0x0D04AC, 'bl\t712076\t;0x17e238'),
    (0x0D04B0, 'stb_s\tr0,[r13,0xd]'),
    (0x0D04B2, 'bl\t712624\t;0x17e460'),
    (0x0D04B6, 'stb_s\tr0,[r13,0xe]'),
    (0x0D04B8, 'bl\t59184\t;0xdebe8'),
    (0x0D04BC, 'stb_s\tr0,[r13,0xf]'),
    (0x0D04BE, 'ld_s\tr0,[pcl,0x1c]\t;0xd04d8'),
    (0x0D04C0, 'ldb_s\tr0,[r0,0]'),
    (0x0D04C2, 'stb_s\tr0,[r13,0x8]'),
    (0x0D04C4, 'b\t-25082\t;0xca2ca'),
]

CALLER_WINDOWS = {
    0x20ED7A: (0, 0x20ED72, [
        (0x20ED76, 'bl\t-1324944\t;0xcb5e4'),
        (0x20ED7A, 'bl\t-1304832\t;0xd0478'),
        (0x20ED7E, 'mov_s\tr0,0x7e'),
        (0x20ED80, 'mov_s\tr1,0'),
        (0x20ED82, 'bl\t-825756\t;0x1453e4'),
    ], 'save_then_notify_7e'),
    0x65602C: (2, 0x656024, [
        (0x65602C, 'bl\t-5790644\t;0xd0478'),
        (0x656030, 'mov_s\tr0,0x3'),
        (0x656032, 'bl\t-5815340\t;0xca404'),
    ], 'save_then_mode3'),
    0x65C3D4: (2, 0x65C3D0, [
        (0x65C3D0, 'bl\t-5836268\t;0xcb5e4'),
        (0x65C3D4, 'bl\t-5816156\t;0xd0478'),
        (0x65C3D8, 'mov_s\tr0,0x3'),
        (0x65C3DA, 'bl\t-5840852\t;0xca404'),
        (0x65C3DE, 'bl\t-5834212\t;0xcbdf8'),
    ], 'save_then_mode3_then_cbdf8'),
    0x66361A: (2, 0x663604, [
        (0x66361A, 'bl\t-5845408\t;0xd0478'),
        (0x66361E, 'bl\t-5865528\t;0xcb5e4'),
        (0x663622, 'bl.d\t-5364196\t;0x145c3c'),
        (0x663626, 'ld_s\tr0,[pcl,0x24]\t;0x663648'),
        (0x663628, 'bl\t-5863472\t;0xcbdf8'),
        (0x66362C, 'bl\t-5162492\t;0x177030'),
    ], 'save_then_leave_shooting_chain'),
    0x8021FE: (4, 0x8021E4, [
        (0x8021F6, 'mov_s\tr0,0x9'),
        (0x8021F8, 'bl\t-6861256\t;0x177030'),
        (0x8021FC, 'b_s\t88\t;0x802254'),
        (0x8021FE, 'bl\t-7544196\t;0xd0478'),
        (0x802202, 'mov_s\tr0,0x3'),
        (0x802204, 'bl\t-7568896\t;0xca404'),
    ], 'save_then_mode3'),
}

GETTER_CENSUS = {
    0xD04DC: [0x7F6AE6], 0xD04E8: [0x7F9F86], 0xD04F4: [0x7F9FA2],
    0xD0500: [0x7F9FAA], 0xD050C: [0x7F9FB2], 0xD0518: [0x7F9F9A],
    0xD0520: [0x7F9F7E],
}

RESTORE_LINES = [
    (0x7F9F7C, 'push_s\tblink'),
    (0x7F9F7E, 'bl\t-7510620\t;0xd0520'),
    (0x7F9F82, 'bl\t-7519636\t;0xce1ec'),
    (0x7F9F86, 'bl\t-7510684\t;0xd04e8'),
    (0x7F9F8A, 'mov\tr1,-1'),
    (0x7F9F8E, 'mov_s\tr2,r1'),
    (0x7F9F90, 'bl\t-6805932\t;0x17c5e4'),
    (0x7F9F94, 'mov_s\tr0,0x64'),
    (0x7F9F96, 'bl\t-7009940\t;0x14a900'),
    (0x7F9F9A, 'bl\t-7510656\t;0xd0518'),
    (0x7F9F9E, 'bl\t-6906416\t;0x163d6c'),
    (0x7F9FA2, 'bl\t-7510700\t;0xd04f4'),
    (0x7F9FA6, 'bl\t-6798976\t;0x17e124'),
    (0x7F9FAA, 'bl\t-7510696\t;0xd0500'),
    (0x7F9FAE, 'bl\t-6798400\t;0x17e36c'),
    (0x7F9FB2, 'bl\t-7510692\t;0xd050c'),
    (0x7F9FB6, 'bl\t-7451624\t;0xdebcc'),
    (0x7F9FBA, 'pop_s\tblink'),
]

SAVEDGUARD_CONSUMER_LINES = [
    (0x7F6ADE, 'ld_s\tr1,[pcl,0x344]\t;0x7f6e20'),
    (0x7F6AE0, 'mov_s\tr0,0'),
    (0x7F6AE2, 'stb_s\tr0,[r1,0x18]'),
    (0x7F6AE6, 'bl\t-7497224\t;0xd04dc'),
    (0x7F6AEA, 'ld_s\tr1,[pcl,0x338]\t;0x7f6e20'),
    (0x7F6AEC, 'stb_s\tr0,[r1,0x18]'),
]

NON_FEEDERS = {
    0x252C0E: (0, 0x252C0E, [
        (0x252C0E, 'bl\t-1582820\t;0xd0528'),
        (0x252C12, 'cmp_s\tr0,0x6a'),
        (0x252C14, 'bne_s\t230\t;0x252cfa'),
    ], 'cmp_0x6a'),
    0x25327A: (0, 0x253272, [
        (0x253272, 'bl\t-979900\t;0x163eb4'),
        (0x253276, 'cmp_s\tr0,0x5'),
        (0x253278, 'beq_s\t246\t;0x25336e'),
        (0x25327A, 'bl\t-1584464\t;0xd0528'),
        (0x25327E, 'cmp_s\tr0,0x6a'),
        (0x253280, 'bne_s\t238\t;0x25336e'),
    ], 'cmp_0x6a_gated_163eb4'),
    0x7F6AF4: (4, 0x7F6AF4, [
        (0x7F6AF4, 'bl\t-7497164\t;0xd0528'),
        (0x7F6AF8, 'cmp_s\tr0,0x1f'),
        (0x7F6AFA, 'bne_s\t10\t;0x7f6b02'),
        (0x7F6AFC, 'mov_s\tr0,0xff'),
        (0x7F6AFE, 'bl\t-7099832\t;0x131544'),
    ], 'cmp_0x1f_then_131544_ff'),
    0x7F8ACC: (4, 0x7F8ACC, [
        (0x7F8ACC, 'bl\t-7505316\t;0xd0528'),
        (0x7F8AD0, 'cmp_s\tr0,0xa'),
        (0x7F8AD2, 'bne_s\t12\t;0x7f8adc'),
        (0x7F8AD8, 'mov_s\tr2,0x1'),
        (0x7F8ADE, 'ld_s\tr1,[pcl,0x2f0]\t;0x7f8dcc'),
        (0x7F8AE0, 'mov_s\tr2,0'),
        (0x7F8AE2, 'jl_s\t[r13]'),
    ], 'cmp_0xa_select_resource'),
    0x7FBE3A: (4, 0x7FBE3A, [
        (0x7FBE3A, 'bl\t-7518480\t;0xd0528'),
        (0x7FBE3E, 'cmp_s\tr0,0xa'),
        (0x7FBE40, 'bne_s\t10\t;0x7fbe4a'),
        (0x7FBE46, 'mov_s\tr2,0x1'),
        (0x7FBE4C, 'ld_s\tr1,[pcl,0x60]\t;0x7fbeac'),
        (0x7FBE4E, 'mov_s\tr2,0'),
        (0x7FBE50, 'jl_s\t[r13]'),
    ], 'cmp_0xa_select_resource'),
    0x7FAA50: (4, 0x7FAA50, [
        (0x7FAA50, 'bl\t-7513384\t;0xd0528'),
        (0x7FAA54, 'cmp_s\tr0,0x37'),
        (0x7FAA56, 'beq_s\t20\t;0x7faa68'),
        (0x7FAA58, 'ldb\tr0,[r14,55]'),
        (0x7FAA5E, 'bne_s\t12\t;0x7faa68'),
        (0x7FAA60, 'bl\t-7531624\t;0xcbdf8'),
        (0x7FAA64, 'bl\t-6830644\t;0x177030'),
    ], 'cmp_0x37_then_return_pair'),
}

# frozen raw bytes (payload0, base 0x0AD800)
# window 0xD04BE..0xD04DC (30 bytes): ld_s/ldb_s/stb_s, b 0xCA2CA, then the
# pools 0xD04C8/0xD04CC/0xD04D0/0xD04D4/0xD04D8 in LITTLE-ENDIAN byte order
# (the first transcription of the interrupted session had the pool words
# byte-swapped; fixed against the payload bytes, see failing evidence dir
# capture_desired_cell_producer_cpu_20261101T121918208030Z).
CPU_WINDOW_HEX = ('07 d0 00 88 08 ad 07 06 cf fc '
                  'ca 57 36 00 d4 57 36 00 c0 57 36 00 '
                  'cc 57 36 00 0c e8 c8 00')
GETTER_CLUSTER_HEX = ('02 d0 00 88 e0 7e e0 78 cc 57 36 00 '
                      '02 d0 00 88 e0 7e e0 78 d0 57 36 00 '
                      '02 d0 00 88 e0 7e e0 78 cd 57 36 00 '
                      '02 d0 00 88 e0 7e e0 78 ce 57 36 00 '
                      '02 d0 00 88 e0 7e e0 78 cf 57 36 00 '
                      'b4 17 00 f0 00 80 e0 7e a8 17 00 f0 '
                      '00 98 e0 7e 02 d0 00 88 e0 7e e0 78')

LINE_RE = re.compile(r'^F[0-9A-F]+ V([0-9A-F]{6,8}) \|[0-9a-f ]+\| ([a-z0-9_.]+)\s*(.*)$')


def payload_of(blocks, addr):
    for b in blocks:
        if b['load_address_candidate'] <= addr < b['load_address_candidate'] + b['size']:
            return b['index']
    raise ValueError(hex(addr))


def census(targets):
    hits = {t: [] for t in targets}
    with LISTING.open('r', errors='replace') as fh:
        for line in fh:
            m = CENSUS_PATTERN.search(line)
            if m and int(m.group(3), 16) in hits:
                hits[int(m.group(3), 16)].append(int(m.group(1), 16))
    return hits


def listing_store_writers(payload_base_values):
    """Register-invalidated listing scan: for every store whose base register
    was loaded from a pool with a struct-window value, yield (addr, mnem,
    ops, pool_value, disp, ea). Prologues reset the tracked registers."""
    val, age = {}, {}
    out = []
    with LISTING.open('r', errors='replace') as fh:
        for line in fh:
            m = LINE_RE.match(line.rstrip())
            if not m:
                continue
            addr = int(m.group(1), 16)
            mnem, ops = m.group(2), m.group(3).strip()
            if mnem in ('st.aw', 'push_s') or (mnem == 'sub' and 'sp,sp' in ops):
                val.clear(); age.clear()
                continue
            parts = ops.split(',')
            if mnem.startswith('st'):
                inner = ops.split('[')[-1].split(']')[0]
                if ',' in inner:
                    base_reg, disp = inner.split(',', 1)
                    try:
                        d = int(disp, 0)
                    except ValueError:
                        d = None
                else:
                    base_reg, d = inner, 0
                base_reg = base_reg.strip()
                if base_reg in val and d is not None:
                    ea = val[base_reg] + d
                    if WINDOW_LO <= ea <= WINDOW_HI:
                        out.append((addr, mnem, ops, val[base_reg], d, ea))
            if not mnem.startswith('st') and parts:
                dst = parts[0].strip()
                if re.match(r'^(r\d+b?|fp|sp|gp|pcl)$', dst):
                    pm = re.search(r';0x([0-9a-f]+)\b', ops)
                    if mnem.startswith('ld') and '[pcl' in ops and pm:
                        pa = int(pm.group(1), 16)
                        if pa in payload_base_values:
                            val[dst] = payload_base_values[pa]
                            age[dst] = 0
                            continue
                    if dst in val:
                        del val[dst], age[dst]
            for r in list(age):
                age[r] += 1
                if age[r] > 24:
                    del age[r], val[r]
    return out


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'capture_desired_cell_producer_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, block_dir = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                   action='capture-desired-cell-producer',
                   firmware_blocks=16,
                   limits=['Static analysis + 4 synthetic CPU cases; no hardware',
                           'Writer scan covers bases loaded from struct-window pools '
                           'with register invalidation and age 24; writers via pointers '
                           'passed in registers across calls or computed without a '
                           'struct-window pool load are NOT excluded',
                           'The 5 save callers fire at runtime when leaving the '
                           'shooting mode - scheduling/reachability NOT proven',
                           'Restore consumers 0xCE1EC/0x17C5E4/0x14A900/0x163D6C/'
                           '0x17E124/0x17E36C/0xDEBCC not decoded',
                           'V1.1 sample vs V1.0 machine; NON_INSTALLARE'])
    try:
        # --- 1. frozen pool words -----------------------------------------
        for addr, value in SAVE_POOLS.items():
            idx = payload_of(blocks, addr)
            got = struct.unpack_from('<I', payloads[idx], addr - base[idx])[0]
            assert got == value, (hex(addr), hex(got), hex(value))
        results['save_pool_words'] = {hex(a): hex(v) for a, v in SAVE_POOLS.items()}

        # --- 2. LE scans of the saved-context block cells ------------------
        for cell, pools in BLOCK_POOLS.items():
            pat = struct.pack('<I', cell)
            hits = []
            for i, data in payloads.items():
                k = data.find(pat)
                while k != -1:
                    hits.append((i, base[i] + k))
                    k = data.find(pat, k + 1)
            assert sorted(hits) == sorted((0, p) for p in pools), (hex(cell), hits)
        static_byte = payloads[1][DESIRED_CELL - base[1]]
        assert static_byte == 0x2C, hex(static_byte)
        results['block_pools'] = {hex(c): [hex(p) for p in v]
                                  for c, v in BLOCK_POOLS.items()}
        results['desired_cell_static_byte'] = hex(static_byte)

        # --- 3. save function window, byte-exact ---------------------------
        lines = window_lines(payloads[0], base[0], 0xD0478, 0xD04C8)
        for pc, text in SAVE_LINES:
            assert lines.get(pc) == text, (hex(pc), lines.get(pc), text)
        raw = payloads[0][0xD04BE - base[0]:0xD04DC - base[0]]
        assert raw.hex(' ') == CPU_WINDOW_HEX, raw.hex(' ')
        assert len(raw) == 30
        cluster = payloads[0][0xD04DC - base[0]:0xD0530 - base[0]]
        assert cluster.hex(' ') == GETTER_CLUSTER_HEX, cluster.hex(' ')
        results['save_window'] = {
            'function': hex(SAVE_FUNC), 'store_site': '0xD04C2',
            'store': 'stb_s r0,[r13,0x8] with r13=pool 0xD04D0=0x3657C0',
            'mode_source': 'pool 0xD04D8=0xC8E80C via ld_s r0,[pcl,0x1c] at 0xD04BE',
            'saved_fields': {
                '0x3657CA': 'word <- 0xDE6D0',
                '0x3657D0': 'byte <- 0xDE398',
                '0x3657D4': 'word <- 0x14A1F8, clamped <= 400',
                '0x3657CC': 'byte <- guard getter 0xCA310',
                '0x3657CD': 'byte <- 0x17E238',
                '0x3657CE': 'byte <- 0x17E460',
                '0x3657CF': 'byte <- 0xDEBE8',
                '0x3657C8': 'byte <- mode cell 0xC8E80C',
            },
            'tail': 'b 0xCA2CA -> common epilogue 0x33419C'}

        # --- 4. census of the 5 save callers -------------------------------
        got = census([SAVE_FUNC] + list(GETTER_CENSUS) + [0xD0528])
        assert sorted(got[SAVE_FUNC]) == sorted(SAVE_CALLERS)
        assert len(got[SAVE_FUNC]) == 5
        for getter, callers in GETTER_CENSUS.items():
            assert sorted(got[getter]) == sorted(callers), (hex(getter), got[getter])
        assert sorted(got[0xD0528]) == sorted(DESIRED_GETTER_CENSUS)
        assert len(got[0xD0528]) == 21
        non_feeder_sites = sorted(set(got[0xD0528]) - set(DESIRED_FEEDERS))
        assert non_feeder_sites == sorted(NON_FEEDERS), non_feeder_sites
        results['census'] = {
            'save_callers': [hex(x) for x in sorted(got[SAVE_FUNC])],
            'block_getter_callers': {hex(g): [hex(c) for c in v]
                                     for g, v in GETTER_CENSUS.items()},
            'desired_getter_callers': len(got[0xD0528]),
            'desired_non_feeders': [hex(x) for x in sorted(NON_FEEDERS)]}

        # --- 5. caller contexts -------------------------------------------
        classes = {}
        for site, (idx, start, patterns, cls) in CALLER_WINDOWS.items():
            assert payload_of(blocks, site) == idx
            wend = max(pc for pc, _ in patterns) + 8
            lines = window_lines(payloads[idx], base[idx], start, wend)
            for pc, text in patterns:
                assert pc in lines, (hex(site), hex(pc))
                assert lines[pc] == text, (hex(pc), lines[pc], text)
            classes[hex(site)] = cls
        assert len(classes) == 5
        assert sum(1 for c in classes.values() if 'mode3' in c) == 3
        results['caller_classes'] = classes

        # --- 6. restore function + saved-guard consumer --------------------
        lines = window_lines(payloads[4], base[4], 0x7F9F7C, 0x7F9FBC)
        for pc, text in RESTORE_LINES:
            assert lines.get(pc) == text, (hex(pc), lines.get(pc), text)
        lines = window_lines(payloads[4], base[4], 0x7F6ADE, 0x7F6AF0)
        for pc, text in SAVEDGUARD_CONSUMER_LINES:
            assert lines.get(pc) == text, (hex(pc), lines.get(pc), text)
        results['restore_chain'] = {
            'restore_func': '0x7F9F7C',
            'chain': ['0xD0520(0x3657CA)->0xCE1EC',
                      '0xD04E8(0x3657D0)->0x17C5E4(r1=r2=-1)',
                      '0x14A900(0x64)',
                      '0xD0518(word 0x3657D4)->0x163D6C',
                      '0xD04F4(0x3657CD)->0x17E124',
                      '0xD0500(0x3657CE)->0x17E36C',
                      '0xD050C(0x3657CF)->0xDEBCC'],
            'saved_guard_consumer': '0x7F6AE6 -> [pool 0x7F6E20]+0x18'}

        # --- 7. non-feeder consumers of the desired cell -------------------
        nf_classes = {}
        for site, (idx, start, patterns, cls) in NON_FEEDERS.items():
            assert payload_of(blocks, site) == idx, (hex(site), idx)
            wend = max(pc for pc, _ in patterns) + 8
            lines = window_lines(payloads[idx], base[idx], start, wend)
            for pc, text in patterns:
                assert pc in lines, (hex(site), hex(pc))
                assert lines[pc] == text, (hex(pc), lines[pc], text)
            nf_classes[hex(site)] = cls
        assert len(nf_classes) == 6
        results['non_feeder_consumers'] = nf_classes

        # --- 8. writer uniqueness, listing-wide ----------------------------
        pool_addr_val = {}
        for addr, value in SAVE_POOLS.items():
            pool_addr_val[addr] = value
        # extend with every struct-window pool found in the payloads
        for b in blocks:
            data = payloads[b['index']]
            bbase = b['load_address_candidate']
            for off in range(0, len(data) - 3, 2):
                w = struct.unpack_from('<I', data, off)[0]
                if WINDOW_LO <= w <= WINDOW_HI:
                    pool_addr_val[bbase + off] = w
        writers = listing_store_writers(pool_addr_val)
        on_desired = [w for w in writers if w[5] == DESIRED_CELL]
        assert len(on_desired) == 1, [(hex(w[0]), hex(w[3]), w[4]) for w in on_desired]
        w = on_desired[0]
        assert w[0] == 0xD04C2 and w[1] == 'stb_s' and w[3] == 0x3657C0 and w[4] == 8
        results['writer_scan'] = {
            'pools_tracked': len(pool_addr_val),
            'stores_into_struct_window': len(writers),
            'stores_on_desired_cell': [[hex(x[0]), x[1], x[2], hex(x[3]),
                                        x[4], hex(x[5])] for x in on_desired],
            'note': ('unique store reaching 0x3657C8 from a struct-window pool '
                     'base is V0D04C2; scan does not exclude writers via '
                     'register-passed pointers or non-pool pointer arithmetic')}

        # --- 9. CPU cases: ORIGINAL save-tail bytes ------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
                                   output=out, action='capture-desired-cell-producer'))
        r.prepare()
        r.results.update(static_pass=results)

        def case_common(as_text, ld_extra, objs, name):
            orig_bin = out / f'{name}_orig.bin'
            orig_bin.write_bytes(raw)
            s = out / f'{name}.s'
            s.write_text(as_text)
            ld = out / f'{name}.ld'
            ld.write_text(
                'ENTRY(_start)\n'
                + ld_extra +
                'SECTIONS {\n'
                '  .text 0x1000 : { *(.text .text.*) }\n'
                '  .origtext 0xD04BE : { *(.origtext) }\n'
                '  .stub 0xCA2CA : { *(.stub) }\n'
                '  .saved 0x3657C0 : { *(.saved) }\n'
                '  .scratch 0x366000 : { *(.scratch) }\n'
                '  .modecell 0xC8E808 : { *(.modecell) }\n'
                '  .stack 0xC8F000 (NOLOAD) : { *(.stack .stack.*) }\n'
                '}\n')
            cmds = [
                ('as', [TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL',
                        '-o', out / f'{name}.o', s]),
                ('orig', [TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary',
                          '-O', 'elf32-littlearc', '-B', 'arc',
                          '--rename-section',
                          '.data=.origtext,alloc,load,data,contents',
                          '--change-section-vma', '.origtext=0xD04BE',
                          '--strip-all', orig_bin, out / f'{name}_orig.o']),
                ('ld', [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-T', ld, '-o',
                        out / f'{name}.elf', out / f'{name}.o',
                        out / f'{name}_orig.o'] + objs),
                ('disasm', [TOOLCHAIN / 'arc-elf32-objdump', '-d',
                            '-m', 'arc:ARC700', '-EL', out / f'{name}.elf'])]
            for tag, cmd in cmds:
                assert r.command(f'{name}_{tag}', cmd).returncode == 0
            ep, segments = elf_loads(out / f'{name}.elf')
            assert ep == 0x1000, hex(ep)
            by = {seg['address']: seg for seg in segments}
            assert by[0xD04BE]['data'] == raw
            case, sim_text = r.run(name, '/result/' + f'{name}.elf')
            assert case['exit_code'] == 11, sim_text
            assert case['fault'] is not None
            return case

        def saved_block(mode):
            # sentinels: neighbours 0xA5, per-cell markers in the block
            b = bytearray(0xA5 for _ in range(32))   # 0x3657C0..0x3657DF
            b[8] = 0xA5        # 0x3657C8 sentinel before the store
            b[0x10] = 0xAA     # 0x3657D0 marker
            b[0x14] = 0xDD     # 0x3657D4 marker
            return bytes(b)

        def save_case(name, mode_value, r13_value, expect_fault, scratch=False):
            body = (
                '.section .text,"ax",@progbits\n.global _start\n_start:\n'
                ' mov sp,0xC8F000\n'
                f' mov r13,{r13_value}\n'
                # bl requires a 4-byte-aligned target and 0xD04BE is 2 mod 4:
                # jump indirectly; the window never returns (tail b 0xCA2CA).
                ' mov r0,0xD04BE\n'
                ' jl_s [r0]\n'
                '.section .stub,"ax",@progbits\n'
                '.org 0\n')
            if scratch:
                body += (
                    ' ldb r2,[r13,0x8]\n'
                    f' cmp_s r2,{mode_value}\n'
                    ' bne_s bad\n'
                    ' mov r1,0x3657C8\n'
                    ' ldb r2,[r1,0]\n'
                    ' mov r5,0xdead0000\n'
                    ' add r5,r5,r2\n'
                    ' ldb r0,[r5,0]\n'
                    'bad:\n'
                    ' mov r5,0xdeadff00\n'
                    ' ldb r0,[r5,0]\n')
            else:
                body += (
                    ' mov r1,0x3657C8\n'
                    ' ldb r2,[r1,0]\n'
                    ' ldb r3,[r1,-1]\n'
                    ' ldb r4,[r1,1]\n'
                    ' cmp r3,0xa5\n'
                    ' bne_s bad\n'
                    ' cmp r4,0xa5\n'
                    ' bne_s bad\n'
                    ' mov r5,0xdead0000\n'
                    ' add r5,r5,r2\n'
                    ' ldb r0,[r5,0]\n'
                    'bad:\n'
                    ' mov r5,0xdeadff00\n'
                    ' ldb r0,[r5,0]\n')
            body += (
                '.section .saved,"aw",@progbits\n'
                '.align 4\n'
                + ''.join(f' .byte {b}\n' for b in saved_block(mode_value)) +
                '.section .scratch,"aw",@progbits\n'
                '.align 4\n'
                + ''.join(' .byte 0x5c\n' for _ in range(32)) +
                '.section .modecell,"aw",@progbits\n'
                '.align 4\n'
                ' .byte 0xa5\n .byte 0xa5\n .byte 0xa5\n .byte 0xa5\n'
                f' .byte {mode_value}\n'
                ' .byte 0xa5\n .byte 0xa5\n .byte 0xa5\n'
                ' .byte 0xa5\n .byte 0xa5\n .byte 0xa5\n .byte 0xa5\n'
                ' .byte 0xa5\n .byte 0xa5\n .byte 0xa5\n .byte 0xa5\n'
                '.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
            case = case_common(body, '', [], name)
            assert case['fault']['address'] == expect_fault, case['fault']
            case.update(mode_cell=hex(mode_value), r13=hex(r13_value),
                        original_bytes=True)
            return case

        cases = [
            save_case('save_mode_46', 0x46, 0x3657C0, '0xdead0046'),
            save_case('save_mode_2c', 0x2C, 0x3657C0, '0xdead002c'),
            save_case('save_r13_scratch', 0x46, 0x366000, '0xdead00a5',
                      scratch=True),
        ]

        # --- 10. CPU probe: EA of the 32-bit pcl load at 0xD0518 -----------
        # ld r0,[pcl,-76] (bytes b4 17 00 f0) -> EA = 0xD0518-76 = 0xD04CC,
        # the pool holding 0x3657D4; the getter then loads the WORD at
        # 0x3657D4 (ld_s r0,[r0,0], bytes 00 80).  The interrupted session
        # guessed pool 0xD0514 (0x3657CF): WRONG - that pool is read by the
        # getter 0xD050C.  The original window must include 0xD04CC.
        probe_win = payloads[0][0xD04C8 - base[0]:0xD0522 - base[0]]
        name = 'getter_d0518_ea'
        orig_bin = out / f'{name}_orig.bin'
        orig_bin.write_bytes(probe_win)
        # distinct markers in the saved block: word at 0x3657D4 = 0x5DD4
        marker_block = bytearray(0xA5 for _ in range(32))
        marker_block[8] = 0xB8    # 0x3657C8
        marker_block[0xC] = 0xCC  # 0x3657CC
        marker_block[0xD] = 0xCD  # 0x3657CD
        marker_block[0xE] = 0xCE  # 0x3657CE
        marker_block[0xF] = 0xCF  # 0x3657CF
        marker_block[0x10] = 0xD0  # 0x3657D0
        marker_block[0x14] = 0xD4  # 0x3657D4 word = 0x00005DD4
        marker_block[0x15] = 0x5D
        marker_block[0x16] = 0x00
        marker_block[0x17] = 0x00
        s = out / f'{name}.s'
        s.write_text(
            '.section .text,"ax",@progbits\n.global _start\n_start:\n'
            ' mov sp,0xC8F000\n'
            # bl with a numeric literal does not encode an absolute target in
            # this assembler (it.41 used a linker symbol); jump indirectly.
            ' mov r0,0xD0518\n'
            ' jl_s [r0]\n'
            ' mov r5,0xdead0000\n'
            ' and r0,r0,0xffff\n'
            ' add r5,r5,r0\n'
            ' ldb r1,[r5,0]\n'
            '.section .origtext2,"ax"\n'
            '.section .saved,"aw",@progbits\n.align 4\n'
            + ''.join(f' .byte {b}\n' for b in marker_block) +
            '.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
        (out / f'{name}.ld').write_text(
            'ENTRY(_start)\n'
            'SECTIONS {\n'
            '  .text 0x1000 : { *(.text .text.*) }\n'
            '  .origtext 0xD04C8 : { *(.origtext) }\n'
            '  .saved 0x3657C0 : { *(.saved) }\n'
            '  .stack 0xC8F000 (NOLOAD) : { *(.stack .stack.*) }\n'
            '}\n')
        for tag, cmd in [
                ('as', [TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL',
                        '-o', out / f'{name}.o', s]),
                ('orig', [TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary',
                          '-O', 'elf32-littlearc', '-B', 'arc',
                          '--rename-section',
                          '.data=.origtext,alloc,load,data,contents',
                          '--change-section-vma', '.origtext=0xD04C8',
                          '--strip-all', orig_bin, out / f'{name}_orig.o']),
                ('ld', [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-T',
                        out / f'{name}.ld', '-o', out / f'{name}.elf',
                        out / f'{name}.o', out / f'{name}_orig.o']),
                ('disasm', [TOOLCHAIN / 'arc-elf32-objdump', '-d',
                            '-m', 'arc:ARC700', '-EL', out / f'{name}.elf'])]:
            assert r.command(f'{name}_{tag}', cmd).returncode == 0
        ep, segments = elf_loads(out / f'{name}.elf')
        by = {seg['address']: seg for seg in segments}
        assert by[0xD04C8]['data'] == probe_win
        case, sim_text = r.run(name, '/result/' + f'{name}.elf')
        assert case['exit_code'] == 11, sim_text
        assert case['fault'] is not None
        # expected: pool 0xD04CC = 0x3657D4 -> word marker 0x00005DD4;
        # the byte pool 0xD0514 (0x3657CF) belongs to the getter 0xD050C.
        assert case['fault']['address'] == '0xdead5dd4', case['fault']
        case.update(expected_ea='0xD04CC (pool 0x3657D4)', original_bytes=True)
        cases.append(case)

        results['cpu_cases'] = cases
        results['cpu_semantics'] = {
            'mode cell -> 0x3657C8 copy runs on original bytes': True,
            'store EA is r13+8 (scratch redirect leaves the cell untouched)': True,
            'neighbours 0x3657C7/0x3657C9 keep sentinels': True,
            'getter 0xD0518 reads WORD 0x3657D4 via pool 0xD04CC (ld r0,[pcl,-76])': True}

        results['status'] = 'PASS_CAPTURE_DESIRED_CELL_PRODUCER'
        r.results.update(static_pass=results)
        r.results['status'] = 'PASS_CAPTURE_DESIRED_CELL_PRODUCER'
        r.finish()
        r.save()
        print('PASS_CAPTURE_DESIRED_CELL_PRODUCER', stamp, flush=True)
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'static_evidence.json').write_text(json.dumps(results, indent=2) + '\n')
        print('Evidenze statiche:', out / 'static_evidence.json', flush=True)


if __name__ == '__main__':
    main()
