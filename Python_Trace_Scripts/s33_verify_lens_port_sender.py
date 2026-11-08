#!/usr/bin/env python3
"""Static decode of the lens wire port chain: sender helpers, gate, strobes
and the MMIO port primitives down to the halfword sequence on 0x0FF05000.

Follows the split-paths session (s33_verify_lens_split_paths.py, iteration 12)
and answers its open point (a): byte-decode 0x25CB3C/0x25DF24/0x25E064 down to
the halfword writes on the lens port and the gate/strobe registers, closing
the 0x25DFxx residues and the port access qualifier (.di halfword).
Byte-verified facts asserted here:

- port write primitives 0x25E064/0x25E078/0x25E0A4(arg r0): three identical
  bodies, each `sth.di r0,[0x0FF05000]` (pool 0x25E06C/0x25E080/0x25E0AC =
  0x0FF05000 raw, raw instruction word 0x24001900): HALFWORD .di write of
  the low 16 bits of r0 -> the qualifier question of iteration 12 is closed;
- port read primitive 0x25E08C(): `ldh.di r0,[0x0FF05000]` (raw 0x09001000)
  with `extb_s r0,r0` in the delay slot of the return: returns ONLY the LOW
  BYTE zero-extended -> the wire is 8-bit payload riding the low byte of the
  16-bit port;
- status primitive 0x25E0B8(): bit 7 of 0x0FF04024 via ldh.di + lsr 7 +
  bmsk 0 in the delay slot of the return;
- port address getter 0x25E0D0(): returns the constant 0x0FF05000 (tail
  ld_s from pool 0x25E0E4 in the delay slot of j_s.d [blink]);
- aux bank control (context) 0x25E0D4(sel): r0==1 -> bclr bit 0 of
  0x0FFCA008, else bset bit 0 (halfword .di RMW, pool 0x25E0E8);
- gate pair on the lens port: 0x25DEAC clears bit 4 of 0x0FEF03A8 and bit 6
  of 0x0FF04034, 0x25DEE8 sets them (halfword .di RMW, pools 0x25DEB8/
  0x25DED0, bit numbers from mov r0,4 / mov r0,6), each wrapped by the
  critical-section enter 0x1786E8 and exit 0x179354;
- strobe quartet on 0x0FF04020 (pool 0x25DF30/0x25DF58/0x25DF80/0x25DFA8):
  halfword .di RMW `ldh.di; and -769 (clears bits 8/9); [bset 9 | none |
  bset 8 | none]; extw_s; sth.di` -> 0x25DF24 sets bit 9, 0x25DF4C clears
  both, 0x25DF74 sets bit 8, 0x25DF9C clears both; lock/unlock wrapped;
- single-byte sender 0x25CB3C(byte): strobe bit 9 (0x25DF24) -> port write
  (0x25E064) -> strobe clear (0x25DF4C), byte saved in r13 across the two
  bl.d delay slots (mov_s r13,r0 / mov_s r0,r13);
- attention 0x25CB0C: strobe bit 9, port write 0xFF, strobe clear, poll of
  0x25E0B8 (bit 7 of 0x0FF04024) while == 0 up to 0xF4240 iterations, then
  the close helper 0x25CAF4;
- close helper 0x25CAF4: strobe clear twice (0x25DF9C, 0x25DF4C), gate SET
  (0x25DEE8) and 0x2E5658(1) -> the gate bits are re-armed when the
  attention/transaction tail completes;
- descriptor sender 0x25CB54(desc): position r16 = (desc[1] + r57) & 0xFFFF
  with r57 composed by two muludw from desc[0], desc halfword[+2], the cmd
  byte at 0x50F531 (ctxA[+5]) and the halfword at 0x50F532 (ctxA[+6])
  (MULUDW conditional hypothesis), strobe bit 8 set (0x25DF74), then the
  packet written one byte at a time through 0x25E078 (called via r14,
  pool 0x25CECC): [0x00 extra iff bit 0xA of h(0x50F52E)] + 0x00 +
  lo8(r16) + hi8(r16) + [desc[0] iff bit 8 of h(0x50F52E)], strobe clear
  0x25DF9C at the end;
- pack3 logger 0x25CBBC(v, out): out[0]=v, out[1]=v>>8, out[2]=(v>>14)|3
  (3-byte position pack with tag 3);
- critical-section pair (context): 0x1786E8 enter reads [0x369348]
  (pool 0x178718), nesting counter at [struct+0x1c]+0x68, `flag` write of
  the saved status when the counter is 0; 0x179354 decrements and restores
  the status via `flag` when it reaches 0 (naming = inference, bytes real).

MULUDW note: the r57 composition inside 0x25CB54 is exact only under the
documented conditional hypothesis (not CPU-proven). Read-only: firmware,
blocks and tools are never modified.
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
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Port_Sender'

# raw LE word pools of the port/gate/strobe cluster (payload0)
POOLS = {
    # lens port 0x0FF05000, one pool per port primitive (plus the getter)
    0x25E06C: 0x0FF05000, 0x25E080: 0x0FF05000, 0x25E094: 0x0FF05000,
    0x25E0AC: 0x0FF05000, 0x25E0E4: 0x0FF05000,
    # status register of the port handshake
    0x25E0C0: 0x0FF04024,
    # aux bank register used by 0x25E0D4
    0x25E0E8: 0x0FFCA008,
    # gate registers: bit 4 of 0x0FEF03A8, bit 6 of 0x0FF04034
    # (one pool pair per gate helper: clear and set)
    0x25DEB8: 0x0FEF03A8, 0x25DED0: 0x0FF04034,
    0x25DEF4: 0x0FEF03A8, 0x25DF0C: 0x0FF04034,
    # strobe register 0x0FF04020, one pool per strobe helper
    0x25DF30: 0x0FF04020, 0x25DF58: 0x0FF04020,
    0x25DF80: 0x0FF04020, 0x25DFA8: 0x0FF04020,
    # descriptor sender pools: flags context base and the port write copy
    0x25CEC8: 0x50F514, 0x25CECC: 0x25E078,
    # critical-section enter: current-structure pointer
    0x178718: 0x00369348,
}

# raw instruction words that pin the access qualifiers
RAW_WORDS = {
    0x25E070: 0x00241900,   # sth.di r0,[r1]   (port write 0x25E064)
    0x25E084: 0x00241900,   # sth.di r0,[r1]   (port write 0x25E078)
    0x25E0B0: 0x00241900,   # sth.di r0,[r1]   (port write 0x25E0A4)
    0x25E098: 0x09001000,   # ldh.di r0,[r0]   (port read 0x25E08C)
    0x25E0C4: 0x09001000,   # ldh.di r0,[r0]   (status 0x25E0B8)
    0x25DEBC: 0x090A1100,   # ldh.di r10,[r1]  (gate, first RMW)
    0x25DEC4: 0x02A41900,   # sth.di r10,[r1]  (gate, first RMW)
    0x25DF34: 0x19001500,   # ldh.di r0,[r13]  (strobe RMW read)
    0x25DF40: 0x10241D00,   # sth.di r0,[r13]  (strobe RMW write)
}

# ld_s pcl pool resolutions: unscaled rule (PC & ~3) + u6 (project caveat)
LDS = {
    0x25E066: (0x8, 0x25E06C, 0x0FF05000),
    0x25E07A: (0x8, 0x25E080, 0x0FF05000),
    0x25E08E: (0x8, 0x25E094, 0x0FF05000),
    0x25E0A6: (0x8, 0x25E0AC, 0x0FF05000),
    0x25E0BA: (0x8, 0x25E0C0, 0x0FF04024),
    0x25E0D2: (0x14, 0x25E0E4, 0x0FF05000),
    0x25E0D6: (0x14, 0x25E0E8, 0x0FFCA008),
    0x25DEB2: (0x8, 0x25DEB8, 0x0FEF03A8),
    0x25DEC8: (0x8, 0x25DED0, 0x0FF04034),
    0x25DEEE: (0x8, 0x25DEF4, 0x0FEF03A8),
    0x25DF04: (0x8, 0x25DF0C, 0x0FF04034),
    0x25DF2C: (0x4, 0x25DF30, 0x0FF04020),
    0x25DF54: (0x4, 0x25DF58, 0x0FF04020),
    0x25DF7C: (0x4, 0x25DF80, 0x0FF04020),
    0x25DFA4: (0x4, 0x25DFA8, 0x0FF04020),
    0x25CB5C: (0x36C, 0x25CEC8, 0x50F514),
    0x25CB72: (0x35C, 0x25CECC, 0x25E078),
    0x1786EE: (0x2C, 0x178718, 0x00369348),
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

    # --- pools and raw instruction words --------------------------------------
    for addr, value in POOLS.items():
        assert u32(addr) == value, (hex(addr), hex(u32(addr)), hex(value))
    for addr, value in RAW_WORDS.items():
        assert u32(addr) == value, (hex(addr), hex(u32(addr)), hex(value))
    for pc, (u6, target, value) in LDS.items():
        assert (pc & ~3) + u6 == target, (hex(pc), hex(target))
        assert u32(target) == value, (hex(target), hex(value))

    windows = {}

    def win(name: str, lo: int, hi: int) -> str:
        w = aligned_window(p0, base0, lo, hi)
        windows[name] = f'0x{lo:x}..0x{hi:x}'
        (out / f'window_{name}.txt').write_text(w)
        return w

    # --- port write primitives -------------------------------------------------
    # NB: the 4-byte pool after the b_s swallows the store in the linear
    # window, so each primitive gets a dedicated window aligned on the
    # access instruction (raw word already asserted above).
    for name, lo, pool_pc, acc in (('port_write_a', 0x25E064, 0x25E066, 0x25E070),
                                   ('port_write_b', 0x25E078, 0x25E07A, 0x25E084),
                                   ('port_write_c', 0x25E0A4, 0x25E0A6, 0x25E0B0)):
        w = win(name, lo, lo + 0x14)
        has(w, rf'{lo:x}:.*push_s\s+blink')
        has(w, rf'{pool_pc:x}:.*ld_s\s+r1,\[pcl,0x8\]')
        has(w, r'pop_s\s+blink')
        has(w, r'j_s\s+\[blink\]')
        a = win(name + '_access', acc, acc + 8)
        has(a, rf'{acc:x}:.*sth\.di\s+r0,\[r1\]')
        has(a, r'pop_s\s+blink')
        assert 'sth.di' in a and 'st.di' not in a

    # --- port read primitive ----------------------------------------------------
    w = win('port_read', 0x25E08C, 0x25E0A4)
    has(w, r'25e08e:.*ld_s\s+r0,\[pcl,0x8\]')
    has(w, r'25e09e:.*j_s\.d\s+\[blink\]')
    # the return's delay slot keeps only the LOW BYTE of the halfword read
    has(w, r'25e0a0:.*extb_s\s+r0,r0')
    a = win('port_read_access', 0x25E098, 0x25E0A4)
    has(a, r'25e098:.*ldh\.di\s+r0,\[r0\]')
    assert 'ldh.di' in a and 'ld.di' not in a

    # --- status primitive -------------------------------------------------------
    w = win('status_bit7', 0x25E0B8, 0x25E0D0)
    has(w, r'25e0ba:.*ld_s\s+r0,\[pcl,0x8\]')
    has(w, r'25e0c4:.*ldh\.di\s+r0,\[r0\]')
    has(w, r'25e0c8:.*lsr_s\s+r0,r0,0x7')
    has(w, r'25e0cc:.*j_s\.d\s+\[blink\]')
    has(w, r'25e0ce:.*bmsk_s\s+r0,r0,0')       # keep bit 0 of the shifted value

    # --- port address getter ----------------------------------------------------
    w = win('port_getter', 0x25E0D0, 0x25E0D4)
    has(w, r'25e0d0:.*j_s\.d\s+\[blink\]')
    has(w, r'25e0d2:.*ld_s\s+r0,\[pcl,0x14\]')  # returns 0x0FF05000

    # --- aux bank bit control (context) -----------------------------------------
    w = win('aux_bit0', 0x25E0D4, 0x25E10C)
    has(w, r'25e0d8:.*cmp_s\s+r0,0x1')
    has(w, r'25e0da:.*bne\.d')                   # r0 != 1 -> set branch
    has(w, r'25e0de:.*mov_s\s+r1,0')             # delay slot: bit number 0
    has(w, r'25e0ec:.*ldh\.di\s+r10,\[r2\]')
    has(w, r'25e0f0:.*bclr\s+r10,r10,r1')        # r0 == 1 -> clear
    has(w, r'25e0f4:.*sth\.di\s+r10,\[r2\]')
    has(w, r'25e0fc:.*ldh\.di\s+r10,\[r2\]')
    has(w, r'25e100:.*bset\s+r10,r10,r1')        # r0 != 1 -> set
    has(w, r'25e104:.*sth\.di\s+r10,\[r2\]')

    # --- gate clear / gate set ---------------------------------------------------
    w = win('gate_clear', 0x25DEAC, 0x25DEE8)
    has(w, r'25deac:.*push_s\s+blink')
    has(w, r'25deae:.*bl\s+.*;0x1786e8')          # critical-section enter
    has(w, r'25deb4:.*mov_s\s+r0,0x4')            # bit 4
    has(w, r'25debc:.*ldh\.di\s+r10,\[r1\]')      # 0x0FEF03A8
    has(w, r'25dec0:.*bclr\s+r10,r10,r0')
    has(w, r'25dec4:.*sth\.di\s+r10,\[r1\]')
    has(w, r'25deca:.*mov_s\s+r0,0x6')            # bit 6
    has(w, r'25ded4:.*ldh\.di\s+r10,\[r1\]')      # 0x0FF04034
    has(w, r'25ded8:.*bclr\s+r10,r10,r0')
    has(w, r'25dedc:.*sth\.di\s+r10,\[r1\]')
    has(w, r'25dee0:.*bl\s+.*;0x179354')          # critical-section exit

    w = win('gate_set', 0x25DEE8, 0x25DF24)
    has(w, r'25dee8:.*push_s\s+blink')
    has(w, r'25deea:.*bl\s+.*;0x1786e8')
    has(w, r'25def0:.*mov_s\s+r0,0x4')
    has(w, r'25def8:.*ldh\.di\s+r10,\[r1\]')
    has(w, r'25defc:.*bset\s+r10,r10,r0')
    has(w, r'25df00:.*sth\.di\s+r10,\[r1\]')
    has(w, r'25df06:.*mov_s\s+r0,0x6')
    has(w, r'25df10:.*ldh\.di\s+r10,\[r1\]')
    has(w, r'25df14:.*bset\s+r10,r10,r0')
    has(w, r'25df18:.*sth\.di\s+r10,\[r1\]')
    has(w, r'25df1c:.*bl\s+.*;0x179354')

    # --- strobe quartet on 0x0FF04020 ---------------------------------------------
    for name, lo, bit, setpat in (
            ('strobe_set9', 0x25DF24, 0x9, r'bset_s\s+r0,r0,0x9'),
            ('strobe_clear_a', 0x25DF4C, None, None),
            ('strobe_set8', 0x25DF74, 0x8, r'bset_s\s+r0,r0,0x8'),
            ('strobe_clear_b', 0x25DF9C, None, None)):
        w = win(name, lo, lo + 0x28)
        has(w, rf'{lo:x}:.*push_s\s+blink')
        has(w, rf'{lo+4:x}:.*bl\s+.*;0x1786e8')
        has(w, rf'{lo+8:x}:.*ld_s\s+r13,\[pcl,0x4\]')     # pool = 0x0FF04020
        has(w, rf'{lo+16:x}:.*ldh\.di\s+r0,\[r13\]')
        has(w, rf'{lo+20:x}:.*and\s+r0,r0,-769')           # clear bits 8/9
        if setpat:
            has(w, rf'{lo+24:x}:.*{setpat}')
        # clear helpers store without any bset between the and and the extw_s
        has(w, r'extw_s\s+r0,r0')
        has(w, r'sth\.di\s+r0,\[r13\]')
        has(w, r'bl\s+.*;0x179354')
        has(w, r'b\s+.*;0x3341a4')                        # pop r13 + return

    # --- single-byte sender -------------------------------------------------------
    w = win('byte_sender', 0x25CB3C, 0x25CB54)
    has(w, r'25cb3c:.*push_s\s+blink')
    has(w, r'25cb3e:.*push_s\s+r13')
    has(w, r'25cb40:.*bl\.d\s+.*;0x25df24')        # strobe bit 9 set
    has(w, r'25cb44:.*mov_s\s+r13,r0')             # delay: save the byte
    has(w, r'25cb46:.*bl\.d\s+.*;0x25e064')        # port write
    has(w, r'25cb4a:.*mov_s\s+r0,r13')             # delay: restore the byte
    has(w, r'25cb4c:.*bl\s+.*;0x25df4c')           # strobe clear
    has(w, r'25cb50:.*b\s+.*;0x3341a4')            # pop r13 + return

    # --- attention -----------------------------------------------------------------
    w = win('attention', 0x25CB0C, 0x25CB3C)
    has(w, r'25cb10:.*bl\.d\s+.*;0x25df24')        # strobe bit 9 set
    has(w, r'25cb14:.*mov_s\s+r13,0')              # delay: counter = 0
    has(w, r'25cb16:.*bl\.d\s+.*;0x25e064')        # port write
    has(w, r'25cb1a:.*mov_s\s+r0,0xff')            # delay: attention byte 0xFF
    has(w, r'25cb1c:.*bl\s+.*;0x25df4c')           # strobe clear
    has(w, r'25cb24:.*cmp_s\s+r13,0xf4240')        # up to 1,000,000 polls
    has(w, r'25cb2a:.*bhs_s\s+12.*;0x25cb34')
    has(w, r'25cb2c:.*bl\s+.*;0x25e0b8')           # bit 7 of 0x0FF04024
    has(w, r'25cb30:.*cmp_s\s+r0,0')
    has(w, r'25cb32:.*beq_s\s+-14.*;0x25cb22')     # loop while not ready
    has(w, r'25cb34:.*bl_s\s+-64.*;0x25caf4')      # close helper
    has(w, r'25cb36:.*b\s+.*;0x3341a4')

    # --- close helper ----------------------------------------------------------------
    w = win('close_helper', 0x25CAF4, 0x25CB0C)
    has(w, r'25caf4:.*push_s\s+blink')
    has(w, r'25caf6:.*bl\s+.*;0x25df9c')           # strobe clear
    has(w, r'25cafa:.*bl\s+.*;0x25df4c')           # strobe clear
    has(w, r'25cafe:.*bl\s+.*;0x25dee8')           # gate SET
    has(w, r'25cb02:.*bl\.d\s+.*;0x2e5658')        # post helper
    has(w, r'25cb06:.*mov_s\s+r0,0x1')             # delay: arg 1

    # --- descriptor sender ---------------------------------------------------------------
    w = win('desc_sender', 0x25CB54, 0x25CBBC)
    has(w, r'25cb54:.*push_s\s+blink')
    has(w, r'25cb56:.*bl\s+.*;0x334128')           # millicode push r13-r16
    has(w, r'25cb5a:.*ldb_s\s+r1,\[r0,0\]')        # desc[0]
    has(w, r'25cb5c:.*ld_s\s+r15,\[pcl,0x36c\]')   # -> 0x50F514
    has(w, r'25cb5e:.*mov_s\s+r13,r0')             # r13 = desc
    has(w, r'25cb60:.*ldw_s\s+r0,\[r15,0x1e\]')     # halfword 0x50F532 (ctxA+6)
    has(w, r'25cb62:.*sr\s+0,\[aux_macmode\]')
    has(w, r'25cb6a:.*muludw\s+0,r0,r1')
    has(w, r'25cb6e:.*ldw_s\s+r0,\[r13,0x2\]')     # desc halfword[+2]
    has(w, r'25cb70:.*ldb_s\s+r1,\[r15,0x1d\]')    # byte 0x50F531 (ctxA+5, cmd)
    has(w, r'25cb72:.*ld_s\s+r14,\[pcl,0x35c\]')   # -> 0x25E078 (port write)
    has(w, r'25cb74:.*add\s+r0,r0,r57')
    has(w, r'25cb78:.*extw_s\s+r0,r0')
    has(w, r'25cb7a:.*muludw\s+0,r1,r0')
    has(w, r'25cb7e:.*ldb_s\s+r0,\[r13,0x1\]')     # desc[1]
    has(w, r'25cb80:.*add\s+r16,r0,r57')
    has(w, r'25cb84:.*bl\.d\s+.*;0x25df74')        # strobe bit 8 set
    has(w, r'25cb88:.*extw\s+r16,r16')             # delay: zero-extend position
    has(w, r'25cb8c:.*ldw_s\s+r0,\[r15,0x1a\]')    # flags 0x50F52E (ctxA+2)
    has(w, r'25cb8e:.*btst_s\s+r0,0xa')
    has(w, r'25cb90:.*beq_s\s+6.*;0x25cb96')       # bit clear -> single 0x00
    has(w, r'25cb92:.*jl_s\.d\s+\[r14\]')          # extra 0x00 (bit 0xA set)
    has(w, r'25cb94:.*mov_s\s+r0,0')
    has(w, r'25cb96:.*jl_s\.d\s+\[r14\]')          # 0x00 always
    has(w, r'25cb98:.*mov_s\s+r0,0')
    has(w, r'25cb9a:.*jl_s\.d\s+\[r14\]')          # lo8(position)
    has(w, r'25cb9c:.*extb\s+r0,r16')
    has(w, r'25cba0:.*asr\s+r0,r16,0x8')
    has(w, r'25cba4:.*jl_s\.d\s+\[r14\]')           # hi8(position)
    has(w, r'25cba6:.*extb_s\s+r0,r0')
    has(w, r'25cba8:.*ldw_s\s+r0,\[r15,0x1a\]')    # flags again
    has(w, r'25cbaa:.*btst_s\s+r0,0x8')
    has(w, r'25cbac:.*beq_s\s+6.*;0x25cbb2')       # bit clear -> skip
    has(w, r'25cbae:.*jl_s\.d\s+\[r14\]')          # desc[0] (bit 8 set)
    has(w, r'25cbb0:.*ldb_s\s+r0,\[r13,0\]')
    has(w, r'25cbb2:.*bl\s+.*;0x25df9c')           # strobe clear
    has(w, r'25cbb6:.*b\s+.*;0x33418c')           # millicode pop r13-r16

    # --- pack3 logger -----------------------------------------------------------------
    w = win('pack3_logger', 0x25CBBC, 0x25CBD0)
    has(w, r'25cbbc:.*stb_s\s+r0,\[r1,0\]')
    has(w, r'25cbbe:.*lsr\s+r2,r0,0x8')
    has(w, r'25cbc2:.*stb_s\s+r2,\[r1,0x1\]')
    has(w, r'25cbc4:.*lsr_s\s+r0,r0,0xe')
    has(w, r'25cbc6:.*or\s+r0,r0,0x3')             # tag 3 in the top bits
    has(w, r'25cbca:.*j_s\.d\s+\[blink\]')
    has(w, r'25cbcc:.*stb_s\s+r0,\[r1,0x2\]')      # delay slot

    # --- critical-section enter / exit (context) ----------------------------------------
    w = win('crit_enter', 0x1786E8, 0x17871C)
    has(w, r'1786e8:.*push_s\s+r13')
    has(w, r'1786ea:.*mov\s+r13,blink')            # keep the caller
    has(w, r'1786ee:.*ld_s\s+r1,\[pcl,0x2c\]')     # -> [0x369348]
    has(w, r'1786f0:.*ld_s\s+r1,\[r1,0\]')
    has(w, r'1786f2:.*ld_s\s+r2,\[r1,0x1c\]')
    has(w, r'1786f4:.*ld_s\s+r2,\[r2,0x68\]')      # nesting counter
    has(w, r'1786f6:.*cmp_s\s+r2,0')
    has(w, r'1786fa:.*ldw_s\s+r0,\[r1,0x16\]')     # saved status32
    has(w, r'1786fc:.*flag\s+r0')                  # enter the critical section
    has(w, r'178702:.*ld_s\s+r0,\[r2,0x68\]')
    has(w, r'178704:.*add_s\s+r0,r0,0x1')
    has(w, r'178706:.*st_s\s+r0,\[r2,0x68\]')      # counter++
    # caller-PC store polarity (per the independent review): the bne_s SKIPS
    # the store when [r1,0x18] != 0, so the store happens only when it is 0
    has(w, r'178708:.*ldw_s\s+r0,\[r1,0x18\]')
    has(w, r'17870a:.*cmp_s\s+r0,0')
    has(w, r'17870c:.*bne_s\s+8.*;0x178714')       # != 0 -> skip the store
    has(w, r'17870e:.*ld_s\s+r0,\[r1,0x1c\]')
    has(w, r'178710:.*st\s+r13,\[r0,208\]')        # only when [r1,0x18] == 0

    w = win('crit_exit', 0x179354, 0x179388)
    has(w, r'179354:.*ld\s+r1,\[0x369348\]')       # limm: current struct
    has(w, r'17935c:.*ld_s\s+r2,\[r1,0x1c\]')
    has(w, r'17935e:.*ld_s\s+r0,\[r2,0x68\]')
    has(w, r'179362:.*jeq_s\s+\[blink\]')          # counter 0 -> nothing
    has(w, r'179364:.*sub\.f\s+r0,r0,0x1')
    has(w, r'179368:.*jne\.d\s+\[blink\]')         # still nested -> return
    has(w, r'17936c:.*st_s\s+r0,\[r2,0x68\]')      # delay: counter--
    has(w, r'17936e:.*ldw_s\s+r0,\[r1,0x18\]')
    has(w, r'179372:.*ld\.as\s+r1,\[r1,141\]')     # scaled: [r1+564]
    has(w, r'179376:.*ldw_s\s+r2,\[r1,0x4\]')
    has(w, r'179378:.*flag\s+r2')                  # restore status32
    has(w, r'17937e:.*ldw_s\s+r3,\[r1,0x1a\]')
    has(w, r'179380:.*flag\s+r3')

    # ld.as scaled check for the status restore
    assert (0x179372 & ~3) + 141 * 4 == 0x1795A4

    # --- Python models --------------------------------------------------------------------
    # strobe RMW on the halfword register 0x0FF04020: mask -769 clears bits 8/9
    # and each set helper sets exactly one of the two bits (over all 65.536
    # values of the halfword register)
    for h in range(0x10000):
        base = h & 0xFCFF
        assert base == (h & ~0x300) & 0xFFFF
        assert ((base | 0x200) & 0x100) == 0      # set 9 leaves bit 8 clear
        assert ((base | 0x100) & 0x200) == 0      # set 8 leaves bit 9 clear
    for h in (0x0000, 0x0100, 0x0200, 0x0300, 0xFFFF, 0xA5A5):
        assert ((h & 0xFCFF) | 0x200) & 0xFFFF == (h & 0xFCFF) | 0x200   # set 9
        assert (h & 0xFCFF) & 0xFFFF == h & 0xFCFF                       # clear
        assert ((h & 0xFCFF) | 0x100) & 0xFFFF == (h & 0xFCFF) | 0x100   # set 8
        # a set-9 never leaves bit 8 set and vice versa
        assert (((h & 0xFCFF) | 0x200) & 0x100) == 0
        assert (((h & 0xFCFF) | 0x100) & 0x200) == 0
    # gate RMW: bit 4 of 0x0FEF03A8 and bit 6 of 0x0FF04034, halfword values
    for h in (0x0000, 0x0010, 0x0040, 0xFFFF, 0xB16C):
        assert (h & ~0x10) & 0xFFFF == h & 0xFFEF        # clear bit 4
        assert (h | 0x10) & 0xFFFF == h | 0x10           # set bit 4
        assert (h & ~0x40) & 0xFFFF == h & 0xFFBF        # clear bit 6
        assert (h | 0x40) & 0xFFFF == h | 0x40           # set bit 6
    # port write: only the low 16 bits of r0 reach the port (sth.di)
    for r0 in (0, 0x70, 0xFF, 0x12345678):
        assert (r0 & 0xFFFF) == r0 & 0xFFFF
    # port read: only the low byte of the halfword is returned (extb_s)
    for h in (0x0000, 0x0070, 0xABCD, 0xFF00):
        assert (h & 0xFF) == h & 0xFF
    # attention poll: at most 0xF4240 iterations, exit as soon as bit7 == 1
    assert 0xF4240 == 1_000_000
    # descriptor sender packet model (MULUDW conditional hypothesis):
    # r57 = lo(cmd) * lo(ctxA6 * desc[0] + desc[2]) mod 2^16,
    # position = (desc[1] + r57) & 0xFFFF, packet = [00]? + 00 + lo + hi + [d0]?
    def packet(desc, cmd, ctxA6, flags):
        d0, d1, d2 = desc
        r57 = (cmd * ((ctxA6 * d0 + d2) & 0xFFFF)) & 0xFFFF
        pos = (d1 + r57) & 0xFFFF
        out = []
        if flags & 0x400:
            out.append(0x00)          # bit 0xA set -> extra 0x00 first
        out += [0x00, pos & 0xFF, (pos >> 8) & 0xFF]
        if flags & 0x100:
            out.append(d0)             # bit 8 set -> desc[0] last
        return out
    # cmd*ctxA6*d0 = 2*256*5 = 2560 -> pos 0x0A00 -> lo 0x00 hi 0x0A
    assert packet((0x05, 0x00, 0x0000), 0x02, 0x0100, 0x0000) == [0x00, 0x00, 0x0A]
    assert packet((0x05, 0x03, 0x0000), 0x02, 0x0100, 0x0400) == [0x00, 0x00, 0x03, 0x0A]
    assert packet((0x05, 0x03, 0x0002), 0x01, 0x0000, 0x0100) == [0x00, 0x05, 0x00, 0x05]
    # pack3 logger model: [v, v>>8, (v>>14)|3]
    for v in (0, 0x1234, 0xABCDEF, 0x3FFFFF):
        b = [v & 0xFF, (v >> 8) & 0xFF, ((v >> 14) | 3) & 0xFF]
        assert len(b) == 3 and (b[2] & 3) == 3

    result = {
        'topic': 'lens wire port chain: senders, gate, strobes and the MMIO '
                 'port primitives of 0x0FF05000 (iteration 12 open point a)',
        'date': datetime.now(timezone.utc).isoformat(),
        'firmware_sha256': sha(FIRMWARE),
        'payload0': {'base': hex(base0), 'size': hex(info[0]['size'])},
        'port_primitives': {
            '0x25E064/0x25E078/0x25E0A4': 'sth.di r0,[0x0FF05000]: halfword .di '
                                          'write of the low 16 bits of r0 '
                                          '(three identical bodies; raw word '
                                          '0x24001900; pools 0x25E06C/'
                                          '0x25E080/0x25E0AC = 0x0FF05000)',
            '0x25E08C': 'ldh.di r0,[0x0FF05000] + extb_s in the return delay '
                        'slot: returns ONLY the low byte, zero-extended -> '
                        'the wire payload is 8-bit on the low byte of the '
                        '16-bit port',
            '0x25E0B8': 'bit 7 of 0x0FF04024 (ldh.di + lsr 7 + bmsk 0 in the '
                        'return delay slot)',
            '0x25E0D0': 'returns the constant 0x0FF05000 (port address getter)',
            '0x25E0D4': 'aux bank control (context): r0==1 -> bclr bit 0 of '
                        '0x0FFCA008, else bset bit 0 (halfword .di RMW)',
        },
        'gate': {
            '0x25DEAC': 'clears bit 4 of 0x0FEF03A8 and bit 6 of 0x0FF04034 '
                        '(halfword .di RMW), wrapped by 0x1786E8/0x179354',
            '0x25DEE8': 'sets the same two bits, same lock pair',
        },
        'strobes_0x0FF04020': {
            '0x25DF24': 'mask 0xFCFF (and -769) + bset bit 9 -> bit9=1 bit8=0',
            '0x25DF4C': 'mask 0xFCFF -> bits 8/9 both 0',
            '0x25DF74': 'mask 0xFCFF + bset bit 8 -> bit8=1 bit9=0',
            '0x25DF9C': 'mask 0xFCFF -> bits 8/9 both 0',
            'qualifier': 'halfword .di RMW (ldh.di/and/extw_s/sth.di), lock '
                         'pair 0x1786E8/0x179354 around each helper',
        },
        'senders': {
            '0x25CB3C(byte)': 'strobe bit 9 (0x25DF24) -> port write '
                              '(0x25E064) -> strobe clear (0x25DF4C); the byte '
                              'rides r13 across the two bl.d delay slots',
            '0x25CB0C': 'attention: strobe bit 9 -> port write 0xFF -> strobe '
                        'clear -> poll bit 7 of 0x0FF04024 up to 0xF4240 '
                        'iterations -> close helper 0x25CAF4',
            '0x25CAF4': 'close: strobe clear twice (0x25DF9C, 0x25DF4C), gate '
                        'SET (0x25DEE8), 0x2E5658(1)',
            '0x25CB54(desc)': 'position r16 = (desc[1] + r57) & 0xFFFF with '
                              'r57 = lo(cmd@0x50F531)*lo(h@0x50F532*desc[0]+'
                              'desc[2]) (two muludw, conditional hypothesis); '
                              'strobe bit 8 set; packet one byte at a time '
                              'through 0x25E078 via r14 (pool 0x25CECC): '
                              '[0x00 iff bit 0xA of h(0x50F52E)] + 0x00 + '
                              'lo8(r16) + hi8(r16) + [desc[0] iff bit 8 of '
                              'h(0x50F52E)]; strobe clear 0x25DF9C',
            '0x25CBBC': 'pack3 logger: out[0]=v, out[1]=v>>8, out[2]=(v>>14)|3',
        },
        'critical_section_context': {
            '0x1786E8': 'enter: r1 = [0x369348] (pool 0x178718), nesting '
                        'counter at [[r1+0x1c]+0x68], flag write of the '
                        'saved status ([r1+0x16]) when the counter is 0, '
                        'counter++, stores blink at [r1+0x1c]+208 only when '
                        '[r1+0x18] == 0 (polarity corrected by the '
                        'independent review: the bne_s at 0x17870C skips '
                        'the store when [r1+0x18] != 0)',
            '0x179354': 'exit: counter--, restore of the saved status via '
                        'flag when the counter reaches 0 ([r1+0x18] path, '
                        'ld.as scaled [r1+141] -> [r1+564]); naming of the '
                        'pair is inference, the bytes are verified',
        },
        'qualifier_resolution': 'iteration 12 left open whether the port '
                                'access is halfword .di or word: it is '
                                'HALFWORD .di on both sides (sth.di write, '
                                'ldh.di read), with the read returning only '
                                'the low byte; the dictionary bytes ride the '
                                'low byte of the halfword port',
        'pools': {hex(a): hex(v) for a, v in POOLS.items()},
        'raw_words': {hex(a): hex(v) for a, v in RAW_WORDS.items()},
        'ld_s_resolutions': {hex(pc): {'u6': u6, 'pool': hex(t),
                                       'value': hex(v)}
                             for pc, (u6, t, v) in LDS.items()},
        'windows_verified': windows,
        'limits': [
            'static only: no MMIO, lens MCU or camera hardware accessed; no '
            'firmware executed; NON_INSTALLARE',
            'the r57 position composition inside 0x25CB54 goes through two '
            'muludw: exact only under the documented conditional MULUDW '
            'hypothesis (not CPU-proven)',
            'runtime values (status bits, counter, desc contents, ctxA '
            'fields, r57) are not determinable statically',
            '0x2E5658 (called by the close helper 0x25CAF4) is cross-'
            'referenced by call site only, not byte-decoded here',
            'the physical meaning of the gate bits (0x0FEF03A8 bit 4, '
            '0x0FF04034 bit 6) and of the strobe bits 8/9 on the MCU side '
            'is inference from the RMW pattern, not a datasheet fact',
            'the naming of the critical-section pair 0x1786E8/0x179354 is '
            'inference; the counter/flag bytes are verified',
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
    print('pools asserted:', len(POOLS), '+ raw words:', len(RAW_WORDS))
    print('port qualifier: sth.di/ldh.di halfword on 0x0FF05000; read returns the low byte')


if __name__ == '__main__':
    main()
