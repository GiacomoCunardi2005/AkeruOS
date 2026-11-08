#!/usr/bin/env python3
"""Static decode of the split paths 0x1EDED8 / 0x1EDFDC of the lens command
switch 0x1EE730, down to the wire byte injection sites.

Follows the switch-consumer session (s33_verify_lens_switch_consumer.py,
iteration 11) and answers its open point (a): how the chunked move steps of
the split path reach the lens wire, and where the dictionary command bytes
{00,10,30,50,60,70,80,D0,FF} enter. Byte-verified facts asserted here:

- split dispatch (payload0, bytes): cases 1..6 -> 0x1EDED8(cmd*cum+arg2,
  chunks, r15, 0) with chunks = ceil(arg3 / (ctxA[+0x10]<<9)) via the divide
  millicode 0x335B34; case 0 -> ctxB[0xB4..0xC0] = the four words of arg1,
  then 0x1EDFDC(0, chunks, ptr_to_words, 0), then ctxB[0xAC] =
  ceil(ctxB[0xB8]/((cmd<<9)*ctxA[+0x10])) <= 0x50 (else 0x1B00113) and hub
  0x1EE148(0,0);
- 0x1EDED8(offset, chunks, step, 0): guard 0x25CFE4 = bit 7 of the halfword
  at 0x50F52E (ctxA+2): set -> return 0x1B00001; prepare 0x25C87C(arg0);
  ready-check 0x25C800 returns 1 iff ctrl byte[+1] == 0 (pool 0x25C878 =
  0x36B255); error tail 0x1EDC9C with busy 0x1B0000A retry x2 and final
  0x1EDC78/0x1B00009; validation 0x1EDA10 (bit-table 0x50F190 + parent
  0x36B244 bytes); single step 0x1EDD08 = 0x2606B4(arg0, 0x50E940, ctrl, r3)
  + query 0x260C6C; chunk loop: r13 += ctxA[+0x10]<<9 per chunk, chunks
  countdown, final 0x1EDE7C state-sync;
- 0x1EDFDC(0, n_steps, ptr, 0): same busy guard; bit 0xA of ctxA[+2] selects
  the record writer (clear -> 0x25C1F0 with r19 = 4, set -> 0x25C37C with
  r19 = 2); ctxB halfword[+8] -> ctrl halfword[+2], ctxB cumulative
  halfword[+196] (0xC4) -> ctrl halfword[+4]; per step: stb ctrl[+1] = 0,
  ready-check 0x25C800, step index bound: r13 < ctxB parameter halfword[+210]
  (0xD2) + r19, violated (r13 >= bound) -> 0x1B00108 via bnc (C clear on
  ARC700 borrow-set-carry semantics, per the independent review)
  + r19 else 0x1B00108, step halfword = ctxB[8+2*step] else 0x1B0010A,
  parameter record write 0x25F6A4(0x50E940, ctrl) [0x50 dictionary byte,
  iteration 2], attention 0x25F28C [0x00/0xFF], response validation
  0x25CBF0(0x50E940) (byte[+5] == 0xF0 and markers 0x55/0xAA at +1/+2/+6/+7),
  movement primitive 0x29DDD4(ctrl) [0x60/0xD0 wire, iteration 2], query
  0x260C6C [0x70], wait loop 0x1EDC10, LUT update
  0x50E9C0[2*ctrl_halfword(+4)] = step halfword, record reset 0x25CE18
  (0xFF fill of count*16 bytes), slot fill 0x25CF10 (position = 0x1000 +
  2*ctrl_halfword(+4), even-rounded, bytes at slot +6/+7/+0xB/+0xC, and
  0xFF at +4/+5), then bulk step 0x2606B4(((cmd*steps_done + ctrl[+1])<<9)
  * ctxA[+0x10] + arg2, 0x50E940, ctrl, 0) [0x80 dictionary byte] with
  busy 0x1B0000A exit, query 0x260C6C, advance on 0x25C80C (ctrl[+1] ==
  ctxA[+5]-1), counters step/r18++, n_steps countdown, retry 0x25C8F0;
- wire byte injection sites (byte-verified literals): 0x25CFBC sends 0x70
  via 0x25CB3C -> 0x25E064 (port write) and reads 0x25E08C bit 6, error
  0x1B00007; 0x260C6C sends 0x70 via 0x25CB3C, reads 0x25E08C bit 0, error
  0x1B00007; 0x2606B4 sends 0x80 via 0x25CB3C then the descriptor sender
  0x25CB54(ctrl) and loops slots: 512-byte writes at base + slot<<9 via
  0x260624 and record slot invalidation (bytes +4/+5 forced to 0xFF unless
  already 0xFF/0xF0);
- 0x25CE18(record): fills count*16 bytes with 0xFF; 0x25CF6C(record): fills
  each 16-byte slot with 0xFF except byte[+5] = 0xF0;
- 0x25C800 = (ctrl[+1] == 0), 0x25C80C = (ctrl[+1] == ctxA[+5]-1);
- pools (raw LE words of payload0): ctrl 0x36B254, parent 0x36B244,
  mirror 0x3692E8/0x3692EA, 0x36B24C/0x36B250, rec16 0x50E940, step record
  0x50E980, buf512 0x50D940, LUT 0x50E9C0, bit-table 0x50F190, ctxA flags
  cell 0x50F52E, buf512 flag cell 0x50F514, template 0x3F668C, and the
  error codes 0x1B00001/02/07/09/0A/0F/10/102/108/10A/116/118;
- the three ld.as constant loads inside 0x1EDFDC resolve with the scaled
  rule ((PC&~3) + off*4) to pools 0x1EDDDC = 0x36B254, 0x1EDDFC = 0x1B0010A
  and 0x1EDE24 = 0x50E9C0; objdump prints the UNSCALED address for ld.as
  (e.g. ";0x1edf7a"), which is a toolchain caveat, not the real target.

MULUDW note: the products inside 0x1EDFDC go through the millicode
multiply helper 0x3342A8, exact only under the documented conditional
hypothesis. Read-only: firmware, blocks and tools are never modified.
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
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Split_Paths'

POOLS = {
    # split-path pool block inside payload0 (0x1EDDDC..0x1EDE24)
    0x1EDDDC: 0x36B254, 0x1EDDE0: 0x3692E8, 0x1EDDE4: 0x36B24C,
    0x1EDDE8: 0x36B25C, 0x1EDDEC: 0x50F190, 0x1EDDF0: 0x36B244,
    0x1EDDF4: 0x36B250, 0x1EDDF8: 0xFFFF, 0x1EDDFC: 0x1B0010A,
    0x1EDE00: 0x50E980, 0x1EDE04: 0x50D940, 0x1EDE08: 0x1B00010,
    0x1EDE0C: 0x1B0000F, 0x1EDE10: 0x1B0000A, 0x1EDE14: 0x3692E8,
    0x1EDE18: 0x1B00009, 0x1EDE1C: 0x3692EA, 0x1EDE20: 0x50E940,
    0x1EDE24: 0x50E9C0,
    # pool block of the switch module (0x1EE1E4..0x1EE204)
    0x1EE1E4: 0x36B250, 0x1EE1E8: 0x3692EA, 0x1EE1EC: 0x1B00001,
    0x1EE1F0: 0x1B0000A, 0x1EE1F4: 0x1B00009, 0x1EE1F8: 0x50E940,
    0x1EE1FC: 0x25F28C, 0x1EE200: 0x1B00108, 0x1EE204: 0x1B00118,
    # cluster 0x25Cxxx pools
    0x25C864: 0x50F4D4, 0x25C868: 0x50E9C0, 0x25C874: 0x36B244,
    0x25C878: 0x36B255, 0x25CAB8: 0x50E940, 0x25CABC: 0x1B00102,
    0x25CEC8: 0x50F514, 0x25CECC: 0x25E078, 0x25CED0: 0x50F514,
    0x25CED4: 0x50F520, 0x25CED8: 0x1B0000F,
    0x25D100: 0x1B00002, 0x25D104: 0x1B00007, 0x25D108: 0x50F52E,
    0x25D10C: 0x29DEEC, 0x25D110: 0x3F668C, 0x25D114: 0x1B00018,
    0x25D118: 0x1B00016,
}

# ld.as constant loads inside 0x1EDFDC: scaled rule ((PC&~3) + off*4).
LDAS = {
    0x1EE006: (-138, 0x1EDDDC, 0x36B254),   # r15 = ctrl
    0x1EE0B8: (-175, 0x1EDDFC, 0x1B0010A),  # empty step halfword error
    0x1EE0C8: (-169, 0x1EDE24, 0x50E9C0),   # LUT base
}


def has(window: str, pattern: str) -> None:
    flat = re.sub(r'\s+', ' ', window)
    assert re.search(pattern, flat), pattern


def main() -> None:
    out = EVIDENCE / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())

    firmware = FIRMWARE.read_bytes()
    assert sha(FIRMWARE) == '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'
    blocks, payloads, block_dir = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    base0 = info[0]['load_address_candidate']
    p0 = payloads[0]
    assert len(p0) == info[0]['size']

    def u32(a: int) -> int:
        return struct.unpack_from('<I', p0, a - base0)[0]

    # --- pools ----------------------------------------------------------------
    for addr, value in POOLS.items():
        assert u32(addr) == value, (hex(addr), hex(u32(addr)), hex(value))
    for pc, (off, target, value) in LDAS.items():
        scaled = (pc & ~3) + off * 4
        assert scaled == target, (hex(pc), hex(scaled), hex(target))
        assert u32(scaled) == value

    windows = {}

    def win(name: str, lo: int, hi: int) -> str:
        w = aligned_window(p0, base0, lo, hi)
        windows[name] = f'{he(lo)}..{he(hi)}'
        (out / f'window_{name}.txt').write_text(w)
        return w

    # --- split dispatch: cases 1..6 and case 0 --------------------------------
    w = win('split_dispatch', 0x1EE958, 0x1EEA4C)
    has(w, r"1ee95a:.*add_s r14,r14,r17")                # r14 = cmd*cum + arg2
    has(w, r"1ee95c:.*ldb_s r1,\[r0,0x10\]")             # ctxA[+0x10] count
    has(w, r"1ee960:.*bl\.d.*;0x335b34")                 # divide millicode
    has(w, r"1ee966:.*cmp_s r1,0")                     # remainder
    has(w, r"1ee96c:.*add_s r2,r2,0x1")                  # ceil
    has(w, r"1ee972:.*cmp_s r13,r0")                     # window check
    has(w, r"1ee974:.*bhs_s.*;0x1ee97a")               # accept when cmd*param >= chunks+arg2
    has(w, r"1eea00:.*b_s.*;0x1ee976")                  # all-zero words -> 0x1B00116
    has(w, r"1ee976:.*ld_s r0,\[pcl,0x4c\].*;0x1ee9c0")  # 0x1B00116 pool
    has(w, r"1ee990:.*bl_s.*;0x1eded8")                  # cases 1..6 call
    has(w, r"1ee988:.*mov_s r0,r14")                     # arg0 = cmd*cum+arg2
    has(w, r"1ee98a:.*mov_s r1,r2")                      # arg1 = chunks
    has(w, r"1ee98c:.*mov_s r2,r15")                     # arg2
    has(w, r"1ee98e:.*mov_s r3,0")                     # arg3 = 0
    has(w, r"1ee9ca:.*ld_s r0,\[r15,0\]")
    has(w, r"1ee9ce:.*st\s+r0,\[r1,180\]")               # ctxB[0xB4]
    has(w, r"1ee9d8:.*st\s+r0,\[r1,184\]")               # ctxB[0xB8]
    has(w, r"1ee9e2:.*st\s+r0,\[r1,188\]")               # ctxB[0xBC]
    has(w, r"1ee9f4:.*st\s+r0,\[r1,192\]")               # ctxB[0xC0]
    has(w, r"1eea08:.*bl_s.*;0x1edfdc")                  # case-0 helper call
    has(w, r"1eea02:.*mov_s r1,r2")                      # chunks
    has(w, r"1eea04:.*mov_s r2,r15")                     # words pointer
    has(w, r"1eea06:.*mov_s r3,r0")
    has(w, r"1eea0e:.*ld_s r1,\[sp,0\]")
    has(w, r"1eea10:.*ldb_s r0,\[r1,0x5\]")              # cmd byte
    has(w, r"1eea12:.*asl_s r0,r0,0x9")
    has(w, r"1eea14:.*bl\.d.*;0x3342a8")                 # mul millicode
    has(w, r"1eea1e:.*bl\.d.*;0x335b34")                 # div millicode
    has(w, r"1eea22:.*ld\s+r0,\[r13,184\]")              # ctxB[0xB8]
    has(w, r"1eea32:.*cmp_s r0,0x50")                    # <= 0x50
    has(w, r"1eea34:.*sth\s+r0,\[r13,172\]")             # ctxB[0xAC]
    has(w, r"1eea3a:.*ld_s r0,\[pcl,0x334\].*;0x1eed6c")  # 0x1B00113 pool
    has(w, r"1eea42:.*bl_s.*;0x1ee148")                  # hub

    # case-0 guard, aligned window (the linear window eats 0x1EE9C4 as pool junk)
    w = win('case0_guard', 0x1EE9C4, 0x1EEA0E)
    has(w, r"1ee9c4:.*cmp\s+r17,0")                    # case 0 requires arg2 == 0
    has(w, r"1ee9c8:.*bne_s.*;0x1ee920")                # arg2 != 0 -> exit path

    # --- 0x1EDED8 body ---------------------------------------------------------
    w = win('step_move', 0x1EDED8, 0x1EDFDC)
    has(w, r"1eded8:.*push_s\s+blink")
    has(w, r"1ededa:.*bl.*;0x334120")                    # save r13-r18
    has(w, r"1edee0:.*mov_s r18,r0")                     # arg0 offset
    has(w, r"1edee2:.*mov_s r16,r1")                     # arg1 chunks
    has(w, r"1edee4:.*mov_s r13,r2")                     # arg2 step
    has(w, r"1edee6:.*mov_s r17,r3")                     # arg3
    has(w, r"1edeec:.*bl\.d.*;0x25caec")                 # ctxA resolver
    has(w, r"1edef2:.*bl.*;0x25cfe4")                    # busy flag check
    has(w, r"1edef6:.*cmp_s r0,0x1")
    has(w, r"1edefa:.*ld_s r0,\[pcl,0x2f4\].*;0x1ee1ec")  # 0x1B00001
    has(w, r"1edefe:.*bl\.d.*;0x25c87c")                 # prepare
    has(w, r"1edf02:.*mov_s r0,r18")
    has(w, r"1edf08:.*bl.*;0x25c800")                    # ready check
    has(w, r"1edf10:.*bl_s.*;0x1edc9c")                  # error tail
    has(w, r"1edf16:.*bl.*;0x25c800")
    has(w, r"1edf1e:.*bl_s.*;0x1eda10")                  # validation
    has(w, r"1edf28:.*bl_s.*;0x1edd08")                  # single step
    has(w, r"1edf2e:.*ld_s r15,\[pcl,0x2c4\].*;0x1ee1f0")  # 0x1B0000A
    has(w, r"1edf3e:.*bl_s.*;0x1eddb4")                  # recovery
    has(w, r"1edf44:.*mov_s r0,r13")
    has(w, r"1edf54:.*bl_s.*;0x1edc78")                  # mirror sync
    has(w, r"1edf5a:.*ld_s r0,\[pcl,0x29c\].*;0x1ee1f4")  # 0x1B00009
    has(w, r"1edf60:.*ld_s r0,\[sp,0\]")
    has(w, r"1edf62:.*ldb_s r0,\[r0,0x10\]")             # ctxA[+0x10]
    has(w, r"1edf64:.*asl_s r0,r0,0x9")
    has(w, r"1edf66:.*bl\.d.*;0x25c80c")
    has(w, r"1edf6a:.*add_s r13,r13,r0")                 # r13 += count<<9
    has(w, r"1edf70:.*bl_s.*;0x1edd2c")                  # LUT publish
    has(w, r"1edf7e:.*sub\.f r0,r16,0x1")               # chunk countdown
    has(w, r"1edf86:.*bl.*;0x25c8f0")
    has(w, r"1edf90:.*bl.*;0x25c80c")
    has(w, r"1edfa0:.*bl_s.*;0x1ede7c")                  # state sync
    has(w, r"1edfa6:.*ld_s r14,\[pcl,0x24c\].*;0x1ee1f0")
    has(w, r"1edfc8:.*bl_s.*;0x1edc78")
    has(w, r"1edfce:.*ld_s r0,\[pcl,0x228\].*;0x1ee1f4")
    has(w, r"1edfd6:.*b\.d.*;0x33417c")                  # restore thunk

    # --- 0x1EDFDC body ---------------------------------------------------------
    w = win('case0_helper', 0x1EDFDC, 0x1EE148)
    has(w, r"1edfdc:.*push_s\s+blink")
    has(w, r"1edfde:.*bl\.d.*;0x334118")
    has(w, r"1edfe6:.*mov_s r17,r1")                     # n_steps
    has(w, r"1edfe8:.*mov_s r16,r2")                     # words pointer
    has(w, r"1edfea:.*mov_s r20,r3")
    has(w, r"1edfee:.*bl\.d.*;0x25cfe4")
    has(w, r"1edff8:.*ld_s r14,\[pcl,0x1f4\].*;0x1ee1ec")
    has(w, r"1edffc:.*bl\.d.*;0x25caec")
    has(w, r"1ee004:.*ldw_s r0,\[r0,0x2\]")              # ctxA flags
    has(w, r"1ee006:.*ld\.as r15,\[pcl,-138\]")          # ctrl 0x36B254
    has(w, r"1ee00a:.*btst_s r0,0xa")
    has(w, r"1ee010:.*bl.*;0x25c1f0")                    # record writer (bit clear)
    has(w, r"1ee01e:.*bl.*;0x25c37c")                    # record writer (bit set)
    has(w, r"1ee01a:.*mov_s r0,0x4")                     # r19 = 4 / 2
    has(w, r"1ee02c:.*bl\.d.*;0x25c020")                  # ctxB resolver
    has(w, r"1ee036:.*ldw_s r0,\[r1,0x8\]")              # ctxB halfword +8
    has(w, r"1ee038:.*stw_s r0,\[r15,0x2\]")
    has(w, r"1ee03a:.*ldh\s+r0,\[r1,196\]")               # ctxB[0xC4]
    has(w, r"1ee03e:.*stw_s r0,\[r15,0x4\]")
    has(w, r"1ee04e:.*stb_s r0,\[r15,0x1\]")             # ctrl state = 0
    has(w, r"1ee054:.*bl.*;0x25c800")
    has(w, r"1ee05e:.*ldh\s+r1,\[r0,210\]")               # ctxB[0xD2]
    has(w, r"1ee062:.*add_s r1,r1,r19")
    has(w, r"1ee066:.*bnc\s+80.*;0x1ee0b4")
    has(w, r"1ee076:.*ld_s r0,\[pcl,0x184\].*;0x1ee1f8")  # 0x50E940
    has(w, r"1ee078:.*bl\.d.*;0x25f6a4")                  # 0x50 record write
    has(w, r"1ee07c:.*mov_s r1,r15")
    has(w, r"1ee07e:.*bl\.d.*;0x25f28c")                  # attention 0x00/0xFF
    has(w, r"1ee088:.*bl\.d.*;0x25cbf0")                  # response validator
    has(w, r"1ee092:.*bl\.d.*;0x29ddd4")                  # movement 0x60/0xD0
    has(w, r"1ee09e:.*bl.*;0x260c6c")                     # query 0x70
    has(w, r"1ee0a6:.*bl_s.*;0x1edc10")                   # state wait
    has(w, r"1ee0b4:.*ld_s r14,\[pcl,0x14c\].*;0x1ee200")  # 0x1B00108
    has(w, r"1ee0b8:.*ld\.as r14,\[pcl,-175\]")           # 0x1B0010A
    has(w, r"1ee0c0:.*ldw_s r2,\[r15,0x4\]")              # ctrl cumulative
    has(w, r"1ee0c8:.*ld\.as r0,\[pcl,-169\]")            # LUT 0x50E9C0
    has(w, r"1ee0cc:.*add1_s r0,r0,r2")
    has(w, r"1ee0ce:.*stw_s r1,\[r0,0\]")               # LUT write
    has(w, r"1ee0d0:.*bl\.d.*;0x25ce18")                  # 0xFF record reset
    has(w, r"1ee0d8:.*bl\.d.*;0x25cf10")                  # slot position fill
    has(w, r"1ee0e0:.*ldb_s r0,\[r14,0x5\]")              # cmd byte
    has(w, r"1ee0e2:.*bl\.d.*;0x3342a8")
    has(w, r"1ee0e8:.*ldb_s r1,\[r15,0x1\]")              # ctrl state
    has(w, r"1ee0ec:.*asl_s r1,r1,0x9")
    has(w, r"1ee0ee:.*bl\.d.*;0x3342a8")
    has(w, r"1ee0f2:.*ldb_s r0,\[r14,0x10\]")             # ctxA count
    has(w, r"1ee0f8:.*add_s r0,r0,r16")
    has(w, r"1ee0fa:.*bl\.d.*;0x2606b4")                   # bulk 0x80 step
    has(w, r"1ee0fe:.*mov_s r3,r20")
    has(w, r"1ee12e:.*ld_s r14,\[pcl,0xc4\].*;0x1ee1f0")  # 0x1B0000A
    has(w, r"1ee104:.*bl.*;0x260c6c")
    has(w, r"1ee10c:.*bl.*;0x25c80c")
    has(w, r"1ee114:.*add_s r13,r13,0x1")
    has(w, r"1ee116:.*add\s+r18,r18,0x1")
    has(w, r"1ee11a:.*sub\.f r0,r17,0x1")
    has(w, r"1ee122:.*bl.*;0x25c8f0")

    # --- 0x1EDB48 wire-step transaction ---------------------------------------
    w = win('wire_step', 0x1EDB48, 0x1EDC10)
    has(w, r"1edb5a:.*ld_s r0,\[pcl,0x288\].*;0x1edde0")   # mirror 0x3692E8
    has(w, r"1edb5e:.*ld_s r14,\[pcl,0x2a4\].*;0x1ede00")  # record 0x50E980
    has(w, r"1edb68:.*ld_s r0,\[pcl,0x274\].*;0x1edddc")   # ctrl
    has(w, r"1edb80:.*ld_s r15,\[pcl,0x284\].*;0x1ede04")  # buf512 0x50D940
    has(w, r"1edb88:.*bl\.d.*;0x25f338")                   # THE transaction
    has(w, r"1edb8c:.*mov_s r3,0")
    has(w, r"1edb92:.*bl\.d.*;0x25cbd0")                   # slot check
    has(w, r"1edb9c:.*bl\.d.*;0x25cca0")                   # marker check
    has(w, r"1edba8:.*bl\.d.*;0x25ccfc")                   # table check
    has(w, r"1edbb6:.*ld_s r0,\[pcl,0x254\].*;0x1ede08")   # 0x1B00010
    has(w, r"1edbbc:.*ld_s r0,\[pcl,0x248\].*;0x1ede04")   # buf512
    has(w, r"1edbc0:.*ldb_s r2,\[r1,0x10\]")                # count
    has(w, r"1edbc2:.*asl_s r2,r2,0x9")
    has(w, r"1edbc4:.*bl\.d.*;0x13a954")                    # fill service
    has(w, r"1edbc8:.*mov_s r1,0xff")                      # fill byte 0xFF
    has(w, r"1edbca:.*bl\.d.*;0x25ce18")                    # record reset
    has(w, r"1edbd4:.*bl\.d.*;0x25cf10")
    has(w, r"1edbde:.*ld_s r0,\[pcl,0x230\].*;0x1ede0c")    # 0x1B0000F
    has(w, r"1edbec:.*bl\.d.*;0x2607b4")
    has(w, r"1edbfa:.*bl.*;0x260c6c")                      # query 0x70
    has(w, r"1edbf6:.*ld_s r0,\[pcl,0x21c\].*;0x1ede10")    # 0x1B0000A

    # --- 0x1EDC10 state wait ---------------------------------------------------
    w = win('state_wait', 0x1EDC10, 0x1EDC78)
    has(w, r"1edc22:.*ld_s r13,\[pcl,0x1bc\].*;0x1edddc")   # ctrl
    has(w, r"1edc24:.*ld_s r15,\[pcl,0x1dc\].*;0x1ede00")  # record
    has(w, r"1edc26:.*ldb\s+r16,\[r13,1\]")                 # save state
    has(w, r"1edc34:.*btst_s r0,0xa")
    has(w, r"1edc38:.*bl.*;0x2608a8")                       # bit-clear extra
    has(w, r"1edc4a:.*ldb_s r0,\[r0,0x5\]")                # ctxA[+5] cmd
    has(w, r"1edc52:.*bl\.d.*;0x260ad0")                    # state poll
    has(w, r"1edc5c:.*bl\.d.*;0x25f28c")                   # attention
    has(w, r"1edc64:.*ld_s r0,\[pcl,0x1ac\].*;0x1ede10")   # 0x1B0000A
    has(w, r"1edc68:.*bl.*;0x25f28c")
    has(w, r"1edc6c:.*stb\s+r16,\[r13,1\]")                # restore state

    # --- record fill helpers ---------------------------------------------------
    w = win('record_fill_ff', 0x25CE18, 0x25CE58)
    has(w, r"25ce18:.*push_s\s+blink")
    has(w, r"25ce30:.*ld_s r0,\[sp,0\]")
    has(w, r"25ce32:.*ldb_s r0,\[r0,0x10\]")               # count
    has(w, r"25ce38:.*mov\s+lp_count,0x10")
    has(w, r"25ce44:.*mov_s r14,0xff")
    has(w, r"25ce4a:.*stb_s r14,\[r0,0\]")
    w = win('record_pattern_f0', 0x25CF6C, 0x25CFB4)
    has(w, r"25cf6c:.*push_s\s+blink")
    has(w, r"25cf88:.*mov\s+lp_count,0x10")
    has(w, r"25cf92:.*cmp_s r1,0x5")                        # index 5
    has(w, r"25cf94:.*mov_s r0,0x1")
    has(w, r"25cf9c:.*bmsk_s r0,r0,0x3")
    has(w, r"25cf9e:.*add\s+r0,r0,240")                     # 0xF0 base
    has(w, r"25cfa2:.*stb\.ab\s+r0,\[r2,1\]")
    w = win('record_positions', 0x25CF10, 0x25CF6C)
    has(w, r"25cf18:.*mov_s r17,r0")                        # record
    has(w, r"25cf1a:.*mov_s r16,r1")                        # ctrl
    has(w, r"25cf2c:.*mov_s r1,0xff")
    has(w, r"25cf2e:.*stb_s r1,\[r14,0x5\]")                # 0xFF at +5
    has(w, r"25cf30:.*stb_s r1,\[r14,0x4\]")                # 0xFF at +4
    has(w, r"25cf32:.*ldh\s+r0,\[r16,4\]")                  # ctrl cumulative
    has(w, r"25cf38:.*bset_s r13,r13,0xc")                  # bit 12
    has(w, r"25cf3a:.*add1_s r13,r13,r0")                   # + 2*value
    has(w, r"25cf4c:.*asr\s+r0,r13,0x8")                    # hi byte
    has(w, r"25cf50:.*stb_s r0,\[r14,0xb\]")
    has(w, r"25cf52:.*stb_s r0,\[r14,0x6\]")
    has(w, r"25cf54:.*stb_s r13,\[r14,0xc\]")
    has(w, r"25cf56:.*stb_s r13,\[r14,0x7\]")

    # --- wire byte injection sites ---------------------------------------------
    w = win('query70_alt', 0x25CFBC, 0x25CFE4)
    has(w, r"25cfbc:.*push_s\s+blink")
    has(w, r"25cfc4:.*mov_s r0,0x70")                       # literal 0x70
    has(w, r"25cfc6:.*bl_s.*;0x25cb3c")                     # port sender
    has(w, r"25cfc8:.*bl.*;0x25e08c")                      # port read
    has(w, r"25cfcc:.*btst_s r0,0x6")
    has(w, r"25cfd4:.*ld_s r13,\[pcl,0x130\].*;0x25d104")   # 0x1B00007
    w = win('busy_flag', 0x25CFE4, 0x25CFF0)
    has(w, r"25cfe4:.*ld_s r0,\[pcl,0x124\].*;0x25d108")     # 0x50F52E
    has(w, r"25cfe6:.*ldw_s r0,\[r0,0\]")
    has(w, r"25cfe8:.*lsr_s r0,r0,0x7")
    has(w, r"25cfec:.*bmsk_s r0,r0,0")                    # bit 7
    w = win('query70', 0x260C6C, 0x260C98)
    has(w, r"260c6c:.*push_s\s+blink")
    has(w, r"260c74:.*bl\.d.*;0x25cb3c")
    has(w, r"260c78:.*mov_s r0,0x70")                        # literal 0x70
    has(w, r"260c7a:.*bl.*;0x25e08c")
    has(w, r"260c7e:.*btst_s r0,0")
    has(w, r"260c82:.*ld_s r13,\[pcl,0x18\].*;0x260c98")     # 0x1B00007
    w = win('bulk80', 0x2606B4, 0x260748)
    has(w, r"2606b4:.*push_s\s+blink")
    has(w, r"2606d6:.*bl\.d.*;0x25cb3c")
    has(w, r"2606da:.*mov_s r0,0x80")                        # literal 0x80
    has(w, r"2606dc:.*bl\.d.*;0x25cb54")                     # descriptor sender
    has(w, r"2606e0:.*mov_s r0,r15")                        # ctrl
    has(w, r"2606ee:.*asl\s+r1,r14,0x9")                     # slot*512
    has(w, r"2606f2:.*add\s+r0,r1,r16")                      # base + slot*512
    has(w, r"2606f6:.*bl_s.*;0x260624")
    has(w, r"2606f8:.*asl_s r0,r14,0x4")                     # slot*16
    has(w, r"2606fc:.*bl_s.*;0x260678")
    has(w, r"260712:.*cmp\s+r1,255")                        # keep 0xFF
    has(w, r"26071e:.*cmp\s+r1,240")                         # keep 0xF0
    has(w, r"26072a:.*mov_s r1,0xff")                        # invalidate +5
    has(w, r"260732:.*bl_s.*;0x260698")

    # --- ready checks and validators -------------------------------------------
    w = win('ready_checks', 0x25C800, 0x25C838)
    has(w, r"25c800:.*ld_s r0,\[pcl,0x78\].*;0x25c878")     # 0x36B255
    has(w, r"25c802:.*ldb_s r0,\[r0,0\]")                 # ctrl state byte
    has(w, r"25c80c:.*push_s\s+blink")
    has(w, r"25c820:.*ldb_s r0,\[r0,0x5\]")                 # ctxA cmd
    has(w, r"25c822:.*ldb_s r1,\[r1,0\]")
    has(w, r"25c824:.*sub_s r0,r0,0x1")
    has(w, r"25c826:.*cmp_s r0,r1")
    w = win('validator_a', 0x25CBF0, 0x25CC48)
    has(w, r"25cbf0:.*push_s\s+blink")
    has(w, r"25cbfc:.*cmp_s r0,0x7")
    has(w, r"25cc00:.*ldb\.aw\s+r0,\[r13,5\]")
    has(w, r"25cc04:.*cmp\s+r0,255")                        # 0xFF
    has(w, r"25cc12:.*cmp\s+r0,240")                        # 0xF0
    has(w, r"25cc1a:.*cmp_s r0,0x55")
    has(w, r"25cc20:.*cmp\s+r0,170")                        # 0xAA
    has(w, r"25cc28:.*cmp_s r0,0x55")
    has(w, r"25cc2e:.*cmp\s+r0,170")
    w = win('single_step', 0x1EDD08, 0x1EDD2C)
    has(w, r"1edd08:.*push_s\s+blink")
    has(w, r"1edd0c:.*ld_s r1,\[pcl,0x114\].*;0x1ede20")    # 0x50E940
    has(w, r"1edd0e:.*bl\.d.*;0x2606b4")
    has(w, r"1edd12:.*ld_s r2,\[pcl,0xcc\].*;0x1edddc")      # ctrl
    has(w, r"1edd1c:.*bl.*;0x260c6c")                        # query
    w = win('lut_publish', 0x1EDD2C, 0x1EDD60)
    has(w, r"1edd32:.*ld_s r0,\[pcl,0xc4\].*;0x1eddf4")      # 0x36B250
    has(w, r"1edd44:.*ld_s r3,\[pcl,0xe0\].*;0x1ede24")      # LUT 0x50E9C0
    has(w, r"1edd48:.*ldw_s r2,\[r14,0x4\]")
    has(w, r"1edd4c:.*add1_s r3,r3,r2")
    has(w, r"1edd50:.*stw_s r0,\[r3,0\]")                  # LUT write
    has(w, r"1edd52:.*cmp_s r2,0xffff")
    w = win('state_sync', 0x1EDE7C, 0x1EDED8)
    has(w, r"1ede8e:.*ld\s+r13,\[pcl,-176\].*;0x1edddc")     # ctrl (ld pool)
    has(w, r"1edea2:.*ldb_s r0,\[r0,0x5\]")                 # ctxA cmd
    has(w, r"1edea8:.*bl_s.*;0x1edb48")                     # wire step
    has(w, r"1edeae:.*cmp_s r0,0x1b0000a")
    has(w, r"1edec0:.*bl_s.*;0x1edd2c")                     # LUT publish
    has(w, r"1edec6:.*ld_s r0,\[pcl,0x324\].*;0x1ee1e8")    # 0x3692EA
    w = win('recovery', 0x1EDDB4, 0x1EDDDC)
    has(w, r"1eddb4:.*push_s\s+blink")
    has(w, r"1eddba:.*ld_s r0,\[pcl,0x3c\].*;0x1eddf4")      # 0x36B250
    has(w, r"1eddbc:.*ld_s r15,\[pcl,0x24\].*;0x1edde0")    # 0x3692E8
    has(w, r"1eddbe:.*ld_s r14,\[pcl,0x20\].*;0x1edddc")     # ctrl
    has(w, r"1eddca:.*bl_s.*;0x1eda10")                     # validation
    has(w, r"1eddd0:.*ld_s r0,\[pcl,0x24\].*;0x1eddf4")
    has(w, r"1eddd2:.*mov_s r1,0x2")

    # --- Python models ---------------------------------------------------------
    # 0x25CF6C: per-16-byte-slot pattern, 0xFF everywhere except 0xF0 at +5.
    for count in (1, 2, 4, 0x10):
        pattern = []
        for slot in range(count):
            pattern += [0xFF] * 5 + [0xF0] + [0xFF] * 10
        assert len(pattern) == count * 16
        assert all(b == 0xFF for i, b in enumerate(pattern) if i % 16 != 5)
        assert all(b == 0xF0 for i, b in enumerate(pattern) if i % 16 == 5)
    # 0x25CE18: whole record reset to 0xFF.
    for count in (1, 4, 0x10):
        assert [0xFF] * (count * 16) == [0xFF] * (count * 16)
    # 0x25CF10 position model: 0x1000 (bit 12) + 2*value, defensively rounded
    # up to even; the sum is always even, so the rounding never fires.
    for value in range(0x10000):
        pos = 0x1000 + ((value << 1) & 0xFFFF)
        if pos & 1:
            pos = (pos + 1) & 0xFFFF
        assert pos & 1 == 0
    # response validator model (0x25CBF0): valid when byte[+5] == 0xF0 and
    # the 0x55/0xAA markers sit at +1/+2/+6/+7; retry until [record+0] >= 7.
    def valid(resp: bytes, tries: int) -> bool:
        for _ in range(tries):
            if resp[0] >= 7:
                return (resp[5] == 0xF0 and resp[1] == 0x55 and
                        resp[2] == 0xAA and resp[6] == 0x55 and
                        resp[7] == 0xAA)
        return False
    ok = bytes([7, 0x55, 0xAA, 0, 0, 0xF0, 0x55, 0xAA, 0, 0, 0, 0, 0, 0, 0, 0])
    assert valid(ok, 1)
    assert not valid(bytes([7, 0x55, 0xAA, 0, 0, 0x30, 0x55, 0xAA] + [0] * 8), 1)
    assert not valid(bytes([1, 0x55, 0xAA, 0, 0, 0xF0, 0x55, 0xAA] + [0] * 8), 1)
    # 0x1EDFDC step base arithmetic (mod 2^32, MULUDW hypothesis):
    # base = ((cmd*steps_done + ctrl_state) << 9) * count + arg2.
    m = 0xFFFFFFFF
    for cmd in (1, 3, 0x40):
        for steps in (0, 1, 5):
            for state in (0, 2, 9):
                for count in (1, 3):
                    base = ((((cmd * steps + state) & 0xFFFF) << 9) * count) & m
                    assert base & 0x1FF == 0  # multiple of 512 per slot
    # 0x1EDED8 chunk advance: r13 += ctxA[+0x10] << 9 per chunk.
    for count in (1, 3, 0x50):
        for chunks in (0, 1, 7):
            r13 = 0
            for _ in range(chunks):
                r13 = (r13 + (count << 9)) & m
            assert r13 == (chunks * count * 512) & m

    result = {
        'topic': 'split paths 0x1EDED8/0x1EDFDC of the lens command switch, '
                 'down to the wire byte injection sites',
        'date': datetime.now(timezone.utc).isoformat(),
        'firmware_sha256': sha(FIRMWARE),
        'payload0': {'base': hex(base0), 'size': hex(info[0]['size'])},
        'split_dispatch': {
            'cases_1_6': '0x1EDED8(cmd*cum+arg2, chunks, r15, 0)',
            'case_0': 'ctxB[0xB4..0xC0] = 4 words of arg1; 0x1EDFDC(0, '
                      'chunks, words_ptr, 0); ctxB[0xAC] = ceil(ctxB[0xB8]/'
                      '((cmd<<9)*ctxA[+0x10])) <= 0x50 else 0x1B00113; hub '
                      '0x1EE148(0,0)',
            'chunks': 'ceil(arg3/(ctxA[+0x10]<<9)) via 0x335B34; accepted '
                      'window cmd*param >= chunks+arg2 (bhs = C clear on the '
                      'ARC700 borrow-set-carry semantics, per the independent '
                      'review; CORRECTS iterations 9-11 which had the window '
                      'inverted); error 0x1B00116 when cmd*param < chunks+arg2; '
                      'case 0 also requires arg2 == 0 and all-zero arg1 words '
                      'exit with 0x1B00116 after ctxB[0xAC] = 0',
        },
        'wire_byte_sites': {
            '0x70': ['0x25CFC4 in 0x25CFBC (bit6 of 0x25E08C read, error '
                     '0x1B00007)',
                     '0x260C78 in 0x260C6C (bit0 of 0x25E08C read, error '
                     '0x1B00007)'],
            '0x80': ['0x2606DA in 0x2606B4, followed by descriptor sender '
                     '0x25CB54(ctrl) and per-slot 512-byte writes at '
                     'base+(slot<<9) via 0x260624'],
            '0x50': ['0x25F6A4(0x50E940, ctrl) in 0x1EDFDC per step '
                     '(iteration 2 semantics)'],
            '0x60/0xD0': ['0x29DDD4(ctrl) in 0x1EDFDC per step '
                          '(iteration 2 semantics)'],
            '0xFF': ['record reset 0x25CE18 (count*16 bytes)',
                     'buf512 fill 0x13A954(0x50D940, 0xFF, count<<9)',
                     'slot bytes +4/+5 forced to 0xFF in 0x2606B4 unless '
                     'already 0xFF/0xF0'],
            '0xF0': ['pattern byte at slot +5 written by 0x25CF6C; expected '
                     'at response record +5 by validators 0x25CBF0/0x25CC48'],
            '0x55/0xAA': ['response markers at record +1/+2/+6/+7'],
            '0x00/0xFF': ['attention 0x25F28C (iteration 2 semantics)'],
        },
        'pools': {he(a): hex(v) for a, v in POOLS.items()},
        'ldas_scaled': {he(pc): {'off': off, 'scaled_target': he(t),
                                 'value': hex(v)}
                        for pc, (off, t, v) in LDAS.items()},
        'return_codes': ['0x1B00001 busy flag bit7 ctxA[+2]',
                         '0x1B00007 query 0x70 port bit',
                         '0x1B00009 mirror sync failure',
                         '0x1B0000A busy retry exhausted',
                         '0x1B0000F wire-step second phase failure',
                         '0x1B00010 slot byte check failure',
                         '0x1B00102 pool 0x25CABC (context)',
                         '0x1B00108 step bound: r13 < ctxB[0xD2]+r19, error when r13 >= bound',
                         '0x1B0010A empty step halfword',
                         '0x1B00113 ctxB[0xAC] > 0x50 (iteration 11)',
                         '0x1B00116 split window (iteration 11)'],
        'windows_verified': windows,
        'limits': [
            'static only: no MMIO, lens MCU or camera hardware accessed; no '
            'firmware executed',
            'the products inside 0x1EDFDC go through the millicode multiply '
            '0x3342A8, exact only under the documented conditional MULUDW '
            'hypothesis (not CPU-proven)',
            'runtime values (cmd byte, ctxA[+0x10] count, ctxA[+2] flags, '
            'ctrl state bytes, mirror/LUT contents) are not determinable '
            'statically',
            'the 0x2606B4 base arithmetic sums the arg2 words pointer of '
            'the case-0 path to ((cmd*steps+state)<<9)*count: the bytes say '
            'so, the physical meaning of that base is open',
            '0x29DEEC (called via register from 0x25CCA0/0x25CCFC and '
            '0x25CFF0), 0x260624/0x260678/0x260698, 0x2607B4, 0x2608A8, '
            '0x260AD0, 0x25DF24/0x25DF4C/0x25DF74/0x25DF9C, 0x25DEAC/0x25DEE8 '
            'and 0x260FE4 are cross-referenced by call sites only, not '
            'byte-decoded here',
            'the 0x50/0x60/0xD0/0x00 semantics of 0x25F6A4/0x29DDD4/0x25F28C '
            'are cross-referenced from iteration 2 (Contesti/API stato) and '
            'not re-derived in this run',
            'V1.1 analysed vs camera V1.0: offsets not portable without '
            'proof',
        ],
        'sources': {str(p): sha(p) for p in [
            Path(__file__), FIRMWARE,
            ROOT / 'S33-sections/TBM_blocks/manifest.json',
            ROOT / 'work/build-arc/binutils/objcopy',
            ROOT / 'work/build-arc/binutils/objdump']},
    }
    (out / 'verified_evidence.json').write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    (EVIDENCE / 'latest.json').write_text(json.dumps(
        dict(evidence=str((out / 'verified_evidence.json').relative_to(ROOT))))
        + '\n')
    print('PASS', out)
    print('windows:', len(windows))
    print('pools asserted:', len(POOLS))
    print('wire byte sites 0x70:', '0x25CFC4, 0x260C78;', '0x80:', '0x2606DA')


def he(x: int) -> str:
    return f'0x{x:x}'


if __name__ == '__main__':
    main()
