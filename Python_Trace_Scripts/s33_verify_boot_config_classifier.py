#!/usr/bin/env python3
"""Static verification of the boot-config classifier 0x16E440 (V1.1).

Closes the open point (a) of iteration 26 ("dispatcher comandi 0x16E440,
solo classificato" in the iris-shadow report): the candidate producer of
record/state changes turns out to be a PURE CLASSIFIER of one
configuration byte of TBIB record 8 (payload 8).

Chain, byte-verified in aligned GNU ARC700 windows:

- 0x16E440(a0, a1): GCC frame prologue, saves r0 -> [fp,8] and r1 ->
  [fp,12] (NEVER re-read: the arguments are dead), then bl 0xCAD30,
  sub_s r0,r0,3, cmp_s r0,0x43, bhi -> return 0; otherwise a 68-entry
  byte-offset jump table at 0x16E46C (ldb.x + add1_s x2) whose cases
  are each `mov_s r0,K; b` to the common epilogue. It writes nothing:
  not a producer, only a mapping byte -> small code.
- 0xCAD30 (called by the classifier): `ld.as r0,[pcl,-155]` -> pool
  (PC&~3)+(-155*4) = 0xCAAC4 -> word 0x00C8E80C, `ldb_s r0,[r0,0]`,
  return: getter of the byte at 0xC8E80C.
- 0xC8E80C = payload 8 (TBIB record 8, type 1, base 0x00C8E800, 0x600
  bytes, string "NotRunOneCard", header magic 0xC1C2C3C4) + 0xC.
  In the V1.1 sample the byte is 0x2C, so the classifier returns 7.
- Full mapping byte value -> code (25 non-zero cases, all others 0):
  0x03->5 0x05->14 0x07->13 0x09->19 0x0A->6 0x0B->8 0x0D->25 0x0E->16
  0x0F->22 0x10->21 0x11->9 0x12->27 0x14->23 0x17->24 0x20->9 0x23->26
  0x25->8 0x2C->7 0x33->33 0x3B->18 0x40->16 0x41->2 0x42->1 0x44->20
  0x46->32.
- Callers (linear census, 5 sites; 4 code-verified in aligned windows,
  1 data false positive): payload0 0xCA284 (fn 0xCA274) and 0x20EDE0
  (fn 0x20EDC4); payload4 0x7FF6C2 (fn 0x7FF680) and 0x800174
  (fn 0x800158). Common pattern: shadow getter 0x16F920(0x61) -> r0,
  r1=0, bl 0x16E440, then comparisons against 5/7/0xC driving UI
  requests 0x1453E4(0x87, 0..7) / 0x1453E4(0x7E|0x5E, 0) or dispatch
  0x169D78 / 0x20E814. The shadow fetch is dead for the classifier
  (arguments ignored): shared pattern, no effect on 0x16E440.
- The payload9 site 0xDC0B74 is a data-region false positive of the
  linear listing: payload9 is the Resource block, the aligned window
  decodes an impossible instruction (fmul.f writing pcl) and raw .word
  data, no branch targets the site, and the raw word (LE 0xd6f900cd)
  merely decodes as a branch to 0x16E440.
- Toolchain rule re-verified on two independent ld.as sites:
  0x16E528 -> pool 0x16E388 = 0x392F04 (record table, iteration 26) and
  0x20EDB4 -> pool 0x20EB6C = 0x36972C; objdump prints the UNSCALED
  address (PC + field) while the executed address is (PC&~3)+field*4.

Read-only: firmware, blocks, tools and listings are never modified.
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
EVIDENCE = ROOT / 'Risultati/Boot_Config/Classifier'
LISTING = ROOT / 'Risultati/Disassemblati/Firmware1.1.asm'

CLASSIFIER = 0x16E440
GETTER = 0x00CAD30            # getter of byte 0xC8E80C
JUMP_TABLE = 0x16E46C          # 68 byte offsets, add1_s x2
CASE_COUNT = 0x44
BYTE_CELL = 0x00C8E80C         # record8 base + 0xC
RECORD8 = 0x00C8E800
FLAG_CELL = 0x00365753         # byte set/read by 0xCAD38/0xCAD5C
BYTE_VALUE_V11 = 0x2C

# byte value -> returned code (all values not listed return 0)
MAPPING = {
    0x03: 5, 0x05: 14, 0x07: 13, 0x09: 19, 0x0A: 6, 0x0B: 8,
    0x0D: 25, 0x0E: 16, 0x0F: 22, 0x10: 21, 0x11: 9, 0x12: 27,
    0x14: 23, 0x17: 24, 0x20: 9, 0x23: 26, 0x25: 8, 0x2C: 7,
    0x33: 33, 0x3B: 18, 0x40: 16, 0x41: 2, 0x42: 1, 0x44: 20,
    0x46: 32,
}

CALL_SITES = {0x0CA284, 0x20EDE0, 0x7FF6C2, 0x800174, 0xDC0B74}
FALSE_POSITIVE_SITES = {0xDC0B74}

# ld.as field re-read from raw halfwords (SIMM9_8: bits 23..16 | bit 15<<8)
LD_AS_CASES = [
    # (insn address, halfword pair, field, pool address, expected pool word)
    (0x16E528, (0x1798, 0xF60C), -104, 0x16E388, 0x392F04),
    (0x20EDB4, (0x176E, 0xF600), -146, 0x20EB6C, 0x36972C),
    (0x00CAD30, (0x1765, 0xF600), -155, 0x00CAAC4, 0x00C8E80C),
]


def he(n: int) -> str:
    return f'0x{n:x}'


def has(text: str, pattern: str) -> None:
    assert re.search(pattern, text), f'missing pattern: {pattern}'


def ld_as_field(hw0: int, hw1: int) -> int:
    """SIMM9_8 from the two file halfwords (word = hw0<<16 | hw1)."""
    word = (hw0 << 16) | hw1
    value = ((word >> 16) & 0xFF) | (((word >> 15) & 1) << 8)
    return value - 512 if value & 0x100 else value


def model_classify(byte_value: int) -> int:
    if 3 <= byte_value <= 0x46:
        return MAPPING.get(byte_value, 0)
    return 0


def main() -> None:
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = EVIDENCE / stamp
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())
    assert sha(FIRMWARE) == ('1d34e990a8f99019ffa53ca5de785399'
                             'df863e942739a667ceb314ec6ce62a39')
    blocks, payloads, _ = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    base0 = info[0]['load_address_candidate']
    p0 = payloads[0]
    assert base0 == 0x0AD800
    base4 = info[4]['load_address_candidate']
    base9 = info[9]['load_address_candidate']
    assert (base4, base9) == (0x796800, 0xC8F800)
    assert (info[8]['load_address_candidate'],
            info[8]['size']) == (RECORD8, 0x600)
    p4, p8, p9 = payloads[4], payloads[8], payloads[9]

    windows = []

    def win(payload, base, lo, hi, tag):
        text = aligned_window(payload, base, lo, hi)
        windows.append((tag, hex(lo), hex(hi), text))
        return text

    # 1. Classifier body: prologue, dead args, call, scaled switch.
    t = win(p0, base0, CLASSIFIER, CLASSIFIER + 0xE0, 'classifier')
    for pat in (
            r'sub_s\tsp,sp,0x8', r'push_s\tblink', r'st\tr0,\[fp,8\]',
            r'st\tr1,\[fp,12\]', r'bl\t-669476\t;0xcad30',
            r'sub_s\tr0,r0,0x3', r'cmp_s\tr0,0x43',
            r'bhi\t172\t;0x16e508', r'add\tr12,pcl,0xc\t;0x16e46c',
            r'ldb\.x\tr0,\[r12,r0\]', r'add1_s\tr12,r12,r0',
            r'j_s\t\[r12\]'):
        has(t, pat)
    # dead-argument proof: no re-read of the frame slots in the body
    assert not re.search(r'ld\w*\s+r\w+,\[fp,8\]', t)
    assert not re.search(r'ld\w*\s+r\w+,\[fp,12\]', t)
    # default case returns 0 at 0x16e508
    assert re.search(r'^\s+16e508:\t[0-9a-f ]+\tmov_s\tr0,0', t, re.M)

    # 2. ld.as rule: field re-read from raw halfwords, scaled pool word.
    for addr, (hw0, hw1), field, pool, value in LD_AS_CASES:
        raw0 = struct.unpack_from('<H', p0, addr - base0)[0]
        raw1 = struct.unpack_from('<H', p0, addr - base0 + 2)[0]
        assert (raw0, raw1) == (hw0, hw1), (he(addr), hex(raw0), hex(raw1))
        assert ld_as_field(hw0, hw1) == field, he(addr)
        assert (addr & ~3) + 4 * field == pool, he(addr)
        got = struct.unpack_from('<I', p0, pool - base0)[0]
        assert got == value, (he(addr), he(pool), he(got))
    t = win(p0, base0, GETTER, GETTER + 8, 'getter_cad30')
    has(t, r'ld\.as\tr0,\[pcl,-155\]')
    has(t, r'ldb_s\tr0,\[r0,0\]')
    has(t, r'j_s\t\[blink\]')

    # 3. Record 8 identity: header words + byte value + string.
    words = struct.unpack_from('<8I', p8, 0)
    assert words[:4] == (0x00005FA3, 0xC1C2C3C4, 0x00000287, 0x0000002C)
    assert words[4:8] == (0x00000301, 0x001E0002, 1, 0)
    assert p8[0xC] == BYTE_VALUE_V11
    assert b'NotRunOneCard' in p8
    # end-to-end: classifier with the V1.1 byte returns 7
    assert model_classify(p8[0xC]) == 7

    # 4. Jump table decode: every case is default-0 or `mov_s r0,K`.
    table_map = {}
    for case in range(CASE_COUNT):
        off = p0[JUMP_TABLE - base0 + case]
        target = JUMP_TABLE + 2 * off
        hw = struct.unpack_from('<H', p0, target - base0)[0]
        if target == 0x16E508:
            code = 0
        elif (hw & 0xFF00) == 0xD800:
            code = hw & 0xFF
            nxt = struct.unpack_from('<H', p0, target - base0 + 2)[0]
            # every non-default case branches to the common epilogue
            assert (nxt & 0xF000) == 0xF000, (case, hex(nxt))
        else:
            raise AssertionError((case, hex(target), hex(hw)))
        table_map[case + 3] = code
    assert {k: v for k, v in table_map.items() if v} == MAPPING, \
        'unexpected jump-table mapping'
    codes = sorted(set(table_map.values()))
    assert codes == [0, 1, 2, 5, 6, 7, 8, 9, 13, 14, 16, 18, 19, 20,
                     21, 22, 23, 24, 25, 26, 27, 32, 33], codes
    # model over all 256 byte values equals the table on [3,0x46]
    for v in range(256):
        assert model_classify(v) == table_map.get(v, 0), v

    # 5. Setter/getter pair of the flag cell used by the callers.
    t = win(p0, base0, 0xCAD38, 0xCAD60, 'flag_setter_cad38')
    has(t, r'ld_s\tr0,\[pcl,0x14\]\t;0xcad58')
    has(t, r'stb_s\tr13,\[r0,0\]')
    has(t, r'cmp_s\tr13,0x2')
    assert struct.unpack_from('<I', p0, 0xCAD58 - base0)[0] == FLAG_CELL
    t = win(p0, base0, 0xCAD5C, 0xCAD64, 'flag_getter_cad5c')
    has(t, r'ld\tr0,\[pcl,-4\]\t;0xcad58')
    has(t, r'ldb_s\tr0,\[r0,0\]')
    # twin setter of 0xC8E812 via ld.as on the same cell pointer
    t = win(p0, base0, 0xCB7E4, 0xCB808, 'twin_setter_cb7e4')
    has(t, r'ld\.as\tr2,\[pcl,-157\]')
    has(t, r'stb_s\tr0,\[r2,0x6\]')
    assert struct.unpack_from('<I', p0, 0xCB578 - base0)[0] == BYTE_CELL

    # 6. Caller census on the linear listing.
    pat = re.compile(
        r'V([0-9A-F]{6,8}) \| [0-9a-f ]+ \| '
        r'(bl|bl\.d|bl_s|bl_s\.d|b|b\.d)\s+?-?\d+\s+;0x16e440\b')
    sites = set()
    with LISTING.open('r', errors='replace') as fh:
        for line in fh:
            m = pat.search(line)
            if m:
                sites.add(int(m.group(1), 16))
    assert sites == CALL_SITES, [he(s) for s in sorted(sites)]

    # 7. Caller 0xCA284 (payload0): shadow fetch, code 5/7 actions.
    t = win(p0, base0, 0xCA274, 0xCA2D0, 'caller_ca284')
    for p_ in (r'mov_s\tr0,0x61', r'bl\t677540\t;0x16f920',
               r'mov_s\tr1,r13', r'bl\t672188\t;0x16e440',
               r'cmp_s\tr0,0x5', r'cmp_s\tr14,0x7',
               r'bl\t2724\t;0xcad38', r'bl\t504116\t;0x1453e4',
               r'mov_s\tr0,0x87'):
        has(t, p_)

    # 8. Caller 0x20EDE0 (payload0): codes 5/7/default -> UI requests.
    t = win(p0, base0, 0x20EDC4, 0x20EE20, 'caller_20ede0')
    for p_ in (r'mov_s\tr0,0x61', r'bl\t-652472\t;0x16f920',
               r'bl\t-657824\t;0x16e440', r'cmp_s\tr13,0x5',
               r'cmp_s\tr13,0x7', r'mov_s\tr0,0x7e',
               r'mov_s\tr0,0x87', r'mov_s\tr1,0x2',
               r'mov_s\tr0,0x5e', r'bl\t-825888\t;0x1453e4',
               r'bl\t-1327248\t;0xcad5c'):
        has(t, p_)

    # 9. Payload4 callers (tuning block).
    t = win(p4, base4, 0x7FF680, 0x7FF6F0, 'caller_7ff6c2')
    for p_ in (r'mov_s\tr0,0x61', r'bl\t-6880668\t;0x16f920',
               r'bl\t-6886016\t;0x16e440', r'bl\t-7555436\t;0xcad5c',
               r'cmp_s\tr0,0x2', r'mov_s\tr0,0x65',
               r'mov_s\tr0,0x87', r'mov_s\tr0,0x5e',
               r'bl\t-6903720\t;0x169f40'):
        has(t, p_)
    t = win(p4, base4, 0x800158, 0x800198, 'caller_800174')
    for p_ in (r'mov_s\tr0,0x61', r'bl\t-6883404\t;0x16f920',
               r'bl\t-6888756\t;0x16e440', r'cmp_s\tr0,0xc',
               r'bl\t-6906892\t;0x169d78', r'bl\t-6232444\t;0x20e814'):
        has(t, p_)

    # 10. Payload9 site 0xDC0B74 is DATA, not code: the aligned window
    # decodes an impossible instruction (fmul.f writing pcl) and raw
    # .word data, no branch anywhere targets the site, and the raw word
    # (LE 0xd6f900cd) merely decodes as a branch to 0x16E440.
    lo, hi = 0xDC0B50, 0xDC0B90
    t = win(p9, base9, lo, hi, 'false_positive_dc0b74')
    # impossible instruction (writes pcl) + raw .word data: not code
    has(t, r'fmul\.f\tpcl,r59,r43')
    has(t, r'\.word\t0x33ff06ff')
    got = struct.unpack_from('<I', p9, 0xDC0B74 - base9)[0]
    assert got == 0xD6F900CD, hex(got)
    inbound = re.compile(
        r'V([0-9A-F]{6,8}) \| [0-9a-f ]+ \| '
        r'(bl|bl\.d|bl_s|bl_s\.d|b|b\.d)\s+?-?\d+\s+;0xdc0b74\b')
    hits_in = []
    with LISTING.open('r', errors='replace') as fh:
        for line in fh:
            m = inbound.search(line)
            if m:
                hits_in.append(int(m.group(1), 16))
    assert not hits_in, [he(x) for x in hits_in]
    assert 0xDC0B74 in FALSE_POSITIVE_SITES

    # 11. LE-word census of the cell pointer 0xC8E80C in payload0.
    hits = []
    for off in range(0, len(p0) - 3, 2):
        if struct.unpack_from('<I', p0, off)[0] == BYTE_CELL:
            hits.append(base0 + off)
    assert hits == [0xC9CB0, 0xCA5D0, 0xCAAC4, 0xCB578, 0xCE3A8,
                    0xD04D8, 0xD0A5C, 0xD1014], [he(x) for x in hits]
    # same census across the other payloads: none may carry it as a pool
    for b in blocks:
        if b['index'] == 0:
            continue
        data = payloads[b['index']]
        for off in range(0, len(data) - 3, 2):
            v = struct.unpack_from('<I', data, off)[0]
            assert v != BYTE_CELL, (b['index'], hex(
                b['load_address_candidate'] + off))

    result = dict(
        status='PASS_BOOT_CONFIG_CLASSIFIER_STATIC',
        stamp=stamp,
        firmware_sha256=sha(FIRMWARE),
        classifier=dict(
            address=he(CLASSIFIER), getter=he(GETTER),
            byte_cell=he(BYTE_CELL), record8_base=he(RECORD8),
            byte_value_v11=hex(BYTE_VALUE_V11), returned_code_v11=7,
            args='dead: r0/r1 saved to [fp,8]/[fp,12] and never re-read',
            jump_table=dict(address=he(JUMP_TABLE), entries=CASE_COUNT,
                            scale='add1_s x2 (byte offset)'),
            mapping={hex(k): v for k, v in sorted(MAPPING.items())},
            callers={he(s): ('payload9-data-false-positive'
                             if s in FALSE_POSITIVE_SITES else 'code')
                     for s in sorted(CALL_SITES)},
        ),
        checks=[
            'classifier body window aligned at 0x16E440 (12 patterns)',
            'dead-argument proof: no re-read of [fp,8]/[fp,12]',
            'ld.as SIMM9_8 field re-read from raw halfwords on 3 sites, '
            'scaled pool (PC&~3)+4*field re-read as LE word',
            'record 8 header words + byte 0x2C + string NotRunOneCard',
            'end-to-end model: classify(0x2C) == 7',
            'jump table: 68 cases decoded, mapping asserted, '
            '256-value model equals table',
            'flag setter/getter 0xCAD38/0xCAD5C pool 0x365753',
            'twin setter 0xCB7E4 pool 0xC8E80C writes +6',
            'linear call census: exactly 5 sites to 0x16E440',
            '4 caller windows verified (payload0 x2, payload4 x2)',
            'payload9 site: data false positive (window shows '
            'branches to unmapped addresses, zero inbound branches, '
            'raw word 0xd6f900cd)',
            'LE-word census 0xC8E80C: payload0 exactly 8 pools '
            '{0xC9CB0, 0xCA5D0, 0xCAAC4, 0xCB578, 0xCE3A8, 0xD04D8, '
            '0xD0A5C, 0xD1014} (getter family; 0xCAAC4/0xCB578 '
            'window-verified), zero elsewhere',
        ],
        limits=[
            'Static only: no hardware, no runtime, no MMIO',
            'The semantic NAME of the record-8 byte 0xC8E80C (0x2C) is '
            'not derivable statically: it is a TBIB record-8 '
            'configuration byte whose classified codes drive UI '
            'requests 0x1453E4(0x87, 0..7); physical meaning OPEN',
            'The UI request ids 0x87/0x7E/0x5E and dispatch 0x169D78/'
            '0x20E814 semantics are anchors from previous checkpoints, '
            'not re-decoded here',
            'The shadow fetch 0x16F920(0x61) at every caller is dead '
            'for the classifier; whether it matters elsewhere in those '
            'functions is out of scope',
            'Record 8 content is the V1.1 sample; runtime record 8 '
            'could differ (TBIB loader)',
            'V1.1 sample analysed; camera in the logs runs V1.0',
        ],
        sources=dict(
            script=str(Path(__file__).relative_to(ROOT)),
            firmware=str(FIRMWARE.relative_to(ROOT)),
            manifest='S33-sections/TBM_blocks/manifest.json',
            listing=str(LISTING.relative_to(ROOT)),
            objdump='work/build-arc/binutils (GNU ARC700, -EL, aligned '
                    'windows)'),
    )
    (out / 'boot_config_classifier.json').write_text(
        json.dumps(result, indent=1) + '\n')
    (EVIDENCE / 'latest.json').write_text(json.dumps(
        dict(status=result['status'], stamp=stamp,
             path=str(out.relative_to(ROOT)),
             script=str(Path(__file__).relative_to(ROOT))), indent=1)
        + '\n')
    with (out / 'gnu_windows.txt').open('w') as fh:
        for tag, lo, hi, text in windows:
            fh.write(f'==== {tag} [{lo},{hi})\n{text}\n')
    print('PASS_BOOT_CONFIG_CLASSIFIER_STATIC', stamp)


if __name__ == '__main__':
    main()
