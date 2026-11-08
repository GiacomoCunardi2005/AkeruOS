#!/usr/bin/env python3
"""Static verification of the semantics of the 22-byte record and of the
arguments of the lens command orchestrators (iteration 8).

Answers the open point of iteration 7 (MDs/S33_Obiettivo_Chiamanti_Modulo_
Orchestrazione.md, section 9): decode 0x301EC0 and the 22-byte record that the
state-API caller 0x301E1C builds before calling the orchestrator 0x29E8F0.

Byte-verified results (all windows aligned at the function entries; pool words
read raw little-endian from the payload image, NOT from the objdump byte
column, which prints 32-bit chunks in instruction halfword order):

1. THE 22-BYTE RECORD IS THE ARGUMENT BLOCK ITSELF. 0x301E1C zeroes a
   22-byte buffer on its frame with memcpy(dst=fp-0x18, src=0x354DE4,
   len=0x16; pool 0x301EBC). The 22 bytes at 0x354DE4 are all zero (right
   after the strings "BootNANDBase.bin" 0x354DC1 / "BootNANDBase.dmp"
   0x354DD2). The orchestrator 0x29E8F0 then stores its OWN args r0..r5 at
   [sp+0x28..0x3C] and memcpy-copies EXACTLY 22 bytes of that save area
   ([sp+0x28..0x3D] = r0..r4 full words + the LOW halfword of r5) into its
   local record at [sp+4]. So "record 22 byte" = pack(a0..a4, a5[15:0]):
   the record layout is the packed argument block, not a separate struct.

2. 0x301EC0 IS NOT A RECORD FILLER. It is a 4-write MMIO strobe sequence to
   the peripheral bank 0x0FE400xx (the bank whose identity is open since the
   GNU DSPv5 boot stop at 0x010091F8, write 0x4321 -> 0x0FE40004 in TBIB):
     sth.di 0x4321 -> 0x0FE40004   (pool 0x301EC8/0x301ECC)
     sth.di 0x6641 -> 0x0FE40008   (pool 0x301EDC/0x301EE0)
     sth.di 0xE972 -> 0x0FE4000C   (pool 0x301EF0/0x301EF4)
     sth.di 0xFFFF -> 0x0FE40010   (pool 0x301F04/0x301F08)
   followed by pop_s blink; j_s [blink] (0x301F10/0x301F12). Each write is
   ld_s r1,[pcl,..] (address) + ld_s r0,[pcl,..] (value) + b_s over the pool +
   sth.di r0,[r1]. This is a MAIN-SIDE writer of the same bank the TBIB boot
   writes; the state-API route 0x301E1C -> 0x301EC0 touches it before the
   validators run.

3. 0x29E8F0 SEMANTICS (wrapper of the main orchestrator 0x29E680):
   a) saves r0..r5 at [sp+0x28..0x3C]; resolves ctxA with 0x25CAEC(0)
      ([sp,0] receives the ctxA pointer, iteration-2 anchor: ctxA=0x50F52C);
   b) copies the 22-byte arg block into the local record at [sp+4];
   c) if ctxA[+2] bit0xA is SET (btst_s r0,0xa), transforms the 5 parameter
      halfwords of the record at offsets 6..14 (source save area sp+0x2E,
      sp+0x30, sp+0x32, sp+0x34, sp+0x36 = r1_hi, r2_lo, r2_hi, r3_lo,
      r3_hi) with h <- ceil(h/8): the block is
      `ldh r0,[sp,SRC] / bmsk.f 0,r0,0x2 / asr_s r0,r0,0x3 / beq_s +4 /
       add_s r0,r0,0x1 / sth r0,[sp,DST]`. `bmsk.f 0,...` is the ARC
      flags-only idiom (dummy destination, 72 `sub.f 0,` occurrences in the
      integral listing): flags = (h & 7) != 0, and asr_s (no flags) computes
      h>>3 from the ORIGINAL h, so the result is (h>>3) + ((h&7)?1:0) =
      ceil(h/8), verified below for all 65536 halfword values;
   d) checks 0x1593AC(0x1B00001, 0) (pool 0x29EB84 = 0x1B00001, the error id
      of iteration 5); nonzero return -> error exit via 0x1594A4;
   e) reloads the 6 record words r0=[sp+4], r1=[sp+8], r2=[sp+0xC],
      r3=[sp+0x10], r4=[sp+0x14], r5=[sp+0x18] and calls 0x29E680 with them.
      r6 (the caller arg1) is NOT saved and NOT reloaded by this wrapper:
      its forwarding is ABI-dependent and remains open.

4. THE STATE-API ROUTE PASSES A ZERO RECORD. The caller 0x301E1C reads its 6
   words back from the ZEROED frame ([fp-24]..[fp-4]) after the validators
   0x3013A0 / 0x30183C / (arg0==1 ? 0x30026C : 0x30144C) / 0x300D94, so the
   orchestrator receives a0..a4 = 0 and a5 = 16 bits of stack residue
   ([fp-2],[fp-1] are NOT covered by the 22-byte memcpy of the 24-byte
   frame; the same 2-byte residue exists inside 0x29E8F0 at [sp+0x1A],
   [sp+0x1B] of the forwarded word). The only non-zero input of the route
   is r6 = arg1 (the selector, values 1/r16 in the payload4 tuning sites).

5. 0x29E680 INTAKE: saves its 6 args at [sp+0x1C..0x30], resolves ctxA with
   0x25CAEC(sp+4), then calls 0x25C038(r0=ctxA, r1=sp+0x1C) — the candidate
   intake of the 6-word block into the ctxA command fields (0xC4..0xDE of
   the iteration-2 dispatch, still to be byte-verified inside 0x25C038).
   Then: 0x25BFB0, 0x25CADC, 0x25CAF4, attention 0x25F28C, ctxB fill
   0x25C020, the stride check (add2 r0,r1,0x3b / sub / cmp 236 -> error id
   0x1B00105, pool 0x29E758), the status check 0x25D3AC, and the template
   memcpys 0x3F6698 -> 0x50F210 (528 bytes) and -> 0x50F310 (244 bytes),
   confirming the iteration-5 anchors.

pcl notes: ld_s pool words resolve at (PC & ~3) + offset (unscaled); the
GNU byte column prints 32-bit chunks in ARC instruction halfword order, so
pool VALUES are always read raw from the payload image here. Read-only:
firmware, blocks and tools are never modified.
"""
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads
from s33_run_gnu_arc700 import ROOT, sha
from s33_verify_sensor_mmio_dialog import aligned_window

FIRMWARE = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Orchestrator_Args'

BASE0, END0 = 0x0AD800, 0x35BC00

ZERO_AREA = 0x354DE4
CALLER = 0x301E1C
MMIO_FN = 0x301EC0
ORCH2 = 0x29E8F0
MAIN_ORCH = 0x29E680

# (pool address, expected LE word) for every pcl pool touched by the route.
POOL_WORDS = {
    0x301EBC: 0x354DE4,   # memcpy source of the zeroed record
    0x301EC8: 0x0FE40004, 0x301ECC: 0x00004321,
    0x301EDC: 0x0FE40008, 0x301EE0: 0x00006641,
    0x301EF0: 0x0FE4000C, 0x301EF4: 0x0000E972,
    0x301F04: 0x0FE40010, 0x301F08: 0x0000FFFF,
    0x29EB84: 0x1B00001,   # error id (iteration 5)
    0x29E758: 0x1B00105,   # stride-check error id
    0x29E75C: 0x3F6698,    # template source
    0x29E760: 0x50F210,    # template dst 528 B
    0x29E764: 0x50F21A,
    0x29E768: 0x50F310,    # template dst 244 B
    0x29E76C: 0x50F31A,
}

MMIO_STROBES = [
    (0x0FE40004, 0x4321), (0x0FE40008, 0x6641),
    (0x0FE4000C, 0xE972), (0x0FE40010, 0xFFFF),
]

# (ldh source offset, sth destination offset) of the 5 ceil(h/8) blocks.
TRANSFORM_SITES = [(46, 10), (48, 12), (50, 14), (52, 16), (54, 18)]

WINDOWS = [
    ('caller_301e1c', 0x301E1C, 0x301EC0),
    ('mmio_strobes_301ec0', 0x301EC0, 0x301F14),
    ('orchestrator_29e8f0', 0x29E8F0, 0x29E9C4),
    ('main_orchestrator_29e680', 0x29E680, 0x29E738),
]


def ceil8(h: int) -> int:
    return (h >> 3) + (1 if h & 7 else 0)


def main() -> None:
    out = EVIDENCE / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())
    assert sha(FIRMWARE) == ('1d34e990a8f99019ffa53ca5de785399df863e9427'
                              '39a667ceb314ec6ce62a39')
    blocks, payloads, block_dir = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    p0 = bytes(payloads[0])
    assert info[0]['load_address_candidate'] == BASE0

    def word(va: int) -> int:
        return struct.unpack_from('<I', p0, va - BASE0)[0]

    windows = {}
    for name, lo, hi in WINDOWS:
        w = aligned_window(p0, BASE0, lo, hi)
        assert w.strip(), (name, hex(lo))
        windows[name] = w

    # --- 1. Raw pool words (little-endian from the payload image). ---
    for va, val in POOL_WORDS.items():
        assert word(va) == val, (hex(va), hex(word(va)), hex(val))

    # --- 2. The zero area: 22 zero bytes right after the BootNANDBase strings.
    assert p0[ZERO_AREA - BASE0:ZERO_AREA - BASE0 + 0x16] == b'\x00' * 0x16
    assert p0.find(b'BootNANDBase.bin') == 0x354DC1 - BASE0
    assert p0.find(b'BootNANDBase.dmp') == 0x354DD2 - BASE0

    # --- 3. Caller 0x301E1C: zeroed 22-byte record + MMIO strobes + validators.
    w = windows['caller_301e1c']
    assert re.search(r'\tpush_s\tblink\b', w)
    assert re.search(r'\tbl\t[-0-9]+\t;0x33412c\b', w), 'thunk missing'
    assert re.search(r'\tsub_s\tsp,sp,0x18\b', w)
    assert re.search(r'\tmov_s\tr14,r0\b', w) and \
        re.search(r'\tmov_s\tr13,r1\b', w)
    assert re.search(r'\tld_s\tr1,\[pcl,0x8c\]\t;0x301ebc\b', w)
    assert re.search(r'\tsub\tr15,fp,0x18\b', w)
    assert re.search(r'\tmov_s\tr2,0x16\b', w), 'record length 22 missing'
    assert re.search(r'\tbl\t[-0-9]+\t;0x128c20\b', w), 'memcpy missing'
    assert re.search(r'\tbl\t132\t;0x301ec0\b', w), '0x301EC0 call missing'
    for validator in (0x3013A0, 0x30183C, 0x30026C, 0x30144C, 0x300D94):
        assert re.search(rf'\tbl(?:_s)?\t[-0-9]+\t;0x{validator:x}\b', w), \
            (hex(validator), 'validator missing')
    assert re.search(r'\tcmp_s\tr14,0x1\b', w), 'arg0 selector missing'
    # the 6 record words are read back from the ZEROED frame and r6 = arg1
    for reg, off in (('r15', -8), ('r5', -4), ('r0', -24), ('r1', -20),
                     ('r2', -16), ('r3', -12)):
        assert re.search(rf'\tld\t{reg},\[fp,{off}\]', w), (reg, 'frame load')
    assert re.search(r'\tmov_s\tr6,r13\b', w), 'r6 = arg1 missing'
    assert re.search(r'\tbl\t[-0-9]+\t;0x29e8f0\b', w), 'orchestrator call'
    assert re.search(r'\tbl\t[-0-9]+\t;0x16f200\b', w)
    assert re.search(r'\tbl_s\t[-0-9]+\t;0x30188c\b', w)

    # --- 4. 0x301EC0: exactly 4 sth.di MMIO writes + return, nothing else.
    # The linear GNU window hides three of the four sth.di inside the pool
    # words (decoded as garbage), so the function body is verified BYTES-EXACT
    # against its fully regular layout instead:
    #   push_s blink | (ld_s r1,[pcl,8]; ld_s r0,[pcl,8|c]; b_s; [nop];
    #   pool addr, value; sth.di r0,[r1]) x4 | pop_s blink; j_s [blink].
    w = windows['mmio_strobes_301ec0']
    assert re.search(r'\tpush_s\tblink\b', w)
    assert len(re.findall(r'\tsth\.di\tr0,\[r1\]', w)) == 1, 'first sth.di'
    assert MMIO_FN + 0x54 == 0x301F14, 'function size changed'
    body = bytearray()
    body += struct.pack('<HHH', 0xC0F1, 0xD102, 0xD002) + struct.pack('<H', 0xF006)
    body += struct.pack('<II', 0x0FE40004, 0x4321)
    body += struct.pack('<HH', 0x1900, 0x0024)
    for addr, val in MMIO_STROBES[1:]:
        body += struct.pack('<HHHH', 0xD102, 0xD003, 0xF006, 0x78E0)
        body += struct.pack('<II', addr, val)
        body += struct.pack('<HH', 0x1900, 0x0024)
    body += struct.pack('<HH', 0xC0D1, 0x7EE0)
    actual = p0[MMIO_FN - BASE0:0x301F14 - BASE0]
    assert bytes(body) == actual, '0x301EC0 body differs from the expected layout'
    # the pool loads resolve at (PC & ~3) + offset to exactly these pairs
    for i, (addr, val) in enumerate(MMIO_STROBES):
        pool_va = 0x301EC8 + i * 0x14
        assert word(pool_va) == addr and word(pool_va + 4) == val, \
            (hex(pool_va), hex(word(pool_va)), hex(word(pool_va + 4)))
    # the byte-encoded halfwords really are the expected instructions
    assert struct.pack('<HH', 0x1900, 0x0024) in actual  # sth.di r0,[r1]
    assert struct.pack('<H', 0xC0D1) in actual and \
        struct.pack('<H', 0x7EE0) in actual  # pop_s blink; j_s [blink]

    # --- 5. 0x29E8F0: pack, optional ceil(h/8) scaling, dispatch.
    w = windows['orchestrator_29e8f0']
    assert re.search(r'\tsub_s\tsp,sp,0x18\b', w)
    assert re.search(r'\tpush_s\tblink\b', w)
    assert re.search(r'\tbl\t[-0-9]+\t;0x334130\b', w), 'thunk missing'
    # argument save area: r0..r5 at [sp+0x28..0x3C]
    for reg, slot in (('r0', 0x28), ('r1', 0x2c), ('r2', 0x30),
                      ('r3', 0x34)):
        assert re.search(rf'\tst_s\t{reg},\[sp,{slot:#x}\]', w), (reg, 'arg store')
    assert re.search(r'\tst\tr4,\[sp,56\]', w) and \
        re.search(r'\tst\tr5,\[sp,60\]', w)
    assert not re.search(r'\tst\tr6,', w), 'r6 must not be saved here'
    # ctxA resolve with argument 0, pointer returned through [sp,0]
    assert re.search(r'\tmov_s\tr0,0\b', w)
    assert re.search(r'\tst_s\tr0,\[sp,0\]', w)
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x25caec\b', w), 'ctxA fill missing'
    # record copy: memcpy(sp+4 <- sp+0x28, 22)
    assert re.search(r'\tadd_s\tr0,sp,0x4\b', w)
    assert re.search(r'\tadd_s\tr1,sp,0x28\b', w)
    assert re.search(r'\tmov_s\tr2,0x16\b', w)
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x128c20\b', w), 'record copy'
    # ctxA[+2] bit 0xA gate
    assert re.search(r'\tld_s\tr0,\[sp,0\]', w)
    assert re.search(r'\tldw_s\tr0,\[r0,0x2\]', w)
    assert re.search(r'\tbtst_s\tr0,0xa\b', w), 'bit0xA test missing'
    # the 5 ceil(h/8) transform blocks
    for src, dst in TRANSFORM_SITES:
        assert re.search(rf'\tldh\tr0,\[sp,{src}\]', w), (src, 'ldh')
        assert re.search(r'\tbmsk\.f\t0,r0,0x2\b', w), 'flags-only bmsk'
        assert re.search(r'\tasr_s\tr0,r0,0x3\b', w), 'asr_s missing'
        assert re.search(r'\tadd_s\tr0,r0,0x1\b', w), 'round-up add'
        assert re.search(rf'\tsth\tr0,\[sp,{dst}\]', w), (dst, 'sth')
    # error-id check 0x1593AC(0x1B00001, 0) and the error exit 0x1594A4
    assert re.search(r'\tld_s\tr0,\[pcl,0x204\]\t;0x29eb84\b', w)
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x1593ac\b', w)
    assert re.search(r'\tmov_s\tr1,0\b', w)
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x1594a4\b', w)
    # dispatch of the 6 record words to the main orchestrator
    for reg, slot in (('r14', 0x14), ('r0', 0x4), ('r1', 0x8),
                      ('r2', 0xc), ('r3', 0x10), ('r13', 0x18)):
        assert re.search(rf'\tld_s\t{reg},\[sp,{slot:#x}\]', w), (reg, 'reload')
    assert re.search(r'\tmov_s\tr4,r14\b', w) and \
        re.search(r'\tmov_s\tr5,r13\b', w)
    assert re.search(r'\tbl_s\t[-0-9]+\t;0x29e680\b', w), 'main orchestrator'
    # in-place semantics: record offset of the i-th store == source-0x28 offset
    for i, (src, dst) in enumerate(TRANSFORM_SITES):
        assert src == 0x28 + 6 + 2 * i and dst == 4 + 6 + 2 * i, (i, src, dst)

    # --- 6. 0x29E680: intake of the 6-word block through 0x25C038.
    w = windows['main_orchestrator_29e680']
    assert re.search(r'\tsub_s\tsp,sp,0x18\b', w)
    assert re.search(r'\tpush_s\tblink\b', w)
    for reg, slot in (('r0', 0x1c), ('r1', 0x20), ('r2', 0x24),
                      ('r3', 0x28)):
        assert re.search(rf'\tst_s\t{reg},\[sp,{slot:#x}\]', w), (reg, 'arg store')
    assert re.search(r'\tst\tr4,\[sp,44\]', w) and \
        re.search(r'\tst\tr5,\[sp,48\]', w)
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x25caec\b', w), 'ctxA fill missing'
    assert re.search(r'\tadd_s\tr0,sp,0x4\b', w), 'ctxA slot missing'
    for call in (0x25BFB0, 0x25CADC, 0x25CAF4, 0x25F28C, 0x25C020,
                 0x25D3AC, 0x25C038, 0xAD90C, 0xAD920, 0x13A954, 0x1ED9CC):
        assert re.search(rf'\tbl(?:\.d|_s)?\t[-0-9]+\t;0x{call:x}\b', w), \
            (hex(call), 'call missing')
    # the candidate intake passes the ctxA pointer and the arg-block address
    assert re.search(r'\tadd_s\tr1,sp,0x1c\b', w), 'arg-block address missing'
    # stride check 236 and error id 0x1B00105
    assert re.search(r'\tadd2\tr0,r1,0x3b\b', w)
    assert re.search(r'\tcmp\tr0,236\b', w), 'stride 236 check missing'
    assert re.search(r'\tld_s\tr0,\[pcl,0x88\]\t;0x29e758\b', w)
    # template memcpys (iteration-5 anchors)
    assert re.search(r'\tmov\tr2,528\b', w), 'template 528 missing'
    assert re.search(r'\tmov_s\tr2,0xf4\b', w), 'template 244 missing'
    assert len(re.findall(r'\tbl\.d\t[-0-9]+\t;0x128c20\b', w)) == 2

    # --- 7. ceil model: the decoded transform equals ceil(h/8) everywhere.
    for h in range(0x10000):
        assert ceil8(h) == (h + 7) // 8, h
    # the record/forwarding quirk: 22-byte copy inside a 24-byte frame leaves
    # the top half of the last word undefined at BOTH layers.
    assert 0x16 < 0x18 and 0x28 + 0x16 == 0x3E and 0x3C + 2 == 0x3E

    result = {
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'firmware_sha256': sha(FIRMWARE),
        'question': 'semantics of the 22-byte record, of 0x301EC0 and of the '
                    '7 arguments on the route 0x301E1C -> 0x29E8F0 '
                    '(open point of iteration 7)',
        'findings': {
            'record_is_arg_block': 'the 22-byte record is the packed argument '
                                   'block {a0..a4 words, a5[15:0]}; the caller '
                                   '0x301E1C zeroes it with memcpy from '
                                   '0x354DE4 (22 zero bytes) and the wrapper '
                                   '0x29E8F0 re-copies the same layout from '
                                   'its own save area [sp+0x28..0x3D]',
            'caller_zero_record': 'on the state-API route a0..a4 = 0 and a5 '
                                  'carries 16 bits of stack residue ([fp-2],'
                                  '[fp-1] and [sp+0x1A],[sp+0x1B] are not '
                                  'covered by the 22-byte copies); the only '
                                  'non-zero input is r6 = arg1 (selector)',
            'mmio_301ec0': '0x301EC0 is a 4-write sth.di strobe sequence to '
                           'the 0x0FE400xx bank (0x4321/0x6641/0xE972/'
                           '0xFFFF -> 0x0FE40004/08/0C/10), the same bank '
                           'written by the TBIB boot at 0x010091F8 '
                           '(GNU DSPv5 checkpoint); NOT a record filler',
            'orchestrator_29e8f0': 'ctxA resolve 0x25CAEC(0) -> record copy '
                                   '-> optional ceil(h/8) scaling of the 5 '
                                   'parameter halfwords at record offsets '
                                   '6..14 when ctxA[+2] bit0xA is set -> '
                                   'check 0x1593AC(0x1B00001,0) -> dispatch '
                                   'of the 6 record words to 0x29E680',
            'ceil_transform': 'h <- (h>>3) + ((h&7)?1:0) = ceil(h/8); '
                               'bmsk.f 0,r0,0x2 is the ARC flags-only '
                               'dummy-destination idiom, asr_s has no flags',
            'main_orchestrator_intake': '0x29E680 saves r0..r5 at '
                                        '[sp+0x1C..0x30] and calls '
                                        '0x25C038(ctxA, sp+0x1C): candidate '
                                        'intake of the 6-word block into the '
                                        'ctxA command fields (0xC4..0xDE)',
        },
        'pool_words': {hex(k): hex(v) for k, v in sorted(POOL_WORDS.items())},
        'mmio_strobes': [[hex(a), hex(v)] for a, v in MMIO_STROBES],
        'transform_sites': TRANSFORM_SITES,
        'windows_verified': [w[0] for w in WINDOWS],
        'limits': [
            'static only: no MMIO, lens MCU or camera hardware accessed; no '
            'firmware executed',
            'the ceil(h/8) semantics are derived from the instruction listing '
            '(flags-only bmsk.f idiom, 72 sub.f 0, occurrences in the '
            'integral listing) and modeled in Python over all 65536 values; '
            'they are not proven on the physical CPU',
            'r6 (caller arg1) is neither saved nor reloaded by 0x29E8F0: its '
            'forwarding to 0x29E680 depends on the callee-saved ABI of '
            '0x25CAEC/0x128C20/0x1593AC and remains open',
            'the 2 stack-residue bytes of the last record word are not '
            'resolved: their runtime value is unknown',
            '0x25C038 must still be byte-verified to close the link between '
            'the 6-word block and the ctxA fields 0xC4..0xDE of the '
            'iteration-2 dispatch',
            'the identity of the 0x0FE400xx peripheral bank remains open; the '
            'TBIB cross-reference comes from the GNU DSPv5 report (write '
            '0x4321 -> 0x0FE40004 at 0x010091F8), not re-verified here',
            'V1.1 analysed vs V1.0 camera; NON_INSTALLARE',
        ],
        'sources': {str(p): sha(p) for p in [Path(__file__), FIRMWARE,
                     ROOT / 'S33-sections/TBM_blocks/manifest.json',
                     ROOT / 'work/build-arc/binutils/objcopy',
                     ROOT / 'work/build-arc/binutils/objdump']},
    }
    (out / 'verified_evidence.json').write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    (EVIDENCE / 'latest.json').write_text(
        json.dumps({'evidence': str((out / 'verified_evidence.json')
                                    .relative_to(ROOT))}) + '\n')
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))
    print('PASS', out)
    print('record = packed arg block {a0..a4, a5_lo}; 0x301EC0 = 4 sth.di '
          'strobes to 0x0FE400xx')
    print('0x29E8F0: ctxA -> copy -> ceil(h/8) scaling on bit0xA -> '
          '0x1593AC(0x1B00001,0) -> 0x29E680(record[0..20])')


if __name__ == '__main__':
    main()
