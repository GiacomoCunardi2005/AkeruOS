#!/usr/bin/env python3
"""Static byte-exact decode of 0x2E5658, the post-helper called by the
attention/transaction close 0x25CAF4 (iteration 14 open point a).

The close helper ends with: strobe clear (0x25DF9C), strobe clear
(0x25DF4C), gate SET (0x25DEE8), then `bl.d 0x2E5658` with
`mov_s r0,0x1` in the delay slot. This session byte-decodes that target
and censuses every reference to it. Byte-verified facts asserted here:

- body of 0x2E5658 (20 bytes, 0x2E5658..0x2E566B, dedicated window
  aligned on the entry):
  `st.aw fp,[sp,-4]` (0xB6C81CFC) / `mov fp,sp` (0x3700230A) /
  `mov sp,fp` (0x36C0240A) / `ld.ab fp,[sp,4]` (0x341B1404) /
  `j_s [blink]` (0x7EE0) / `nop_s` (0x78E0) - the standard GCC ARC700
  frame prologue immediately followed by the frame epilogue and NO body:
  0x2E5658 is an empty (nullsub) leaf function. The same prologue word
  appears thousands of times in payload0 (cross-check) and the epilogue
  follows with no instruction in between, so the function cannot touch
  the gate, the strobes, the port, the contexts or any register except
  the transient sp/fp pair and one scratch stack word at [sp-4];
- net effect (Python model): sp and fp restored, r0 returned unchanged
  (the argument is never read: no r0 in the body), memory unchanged
  except mem[sp-4] := fp (a scratch word below the un-moved sp);
- call-site census: exactly 14 `bl.d ... ;0x2e5658` sites in the GNU
  linear decode of payload0, each re-verified with a dedicated window
  aligned on the site (straddle-free classification): 0x25CB02 (inside
  the close helper 0x25CAF4), 0x25D3D2 and 0x25D3F6 (inside 0x25D3AC,
  the recovery/status writer that also sets bit 7 of ctxA[+2] at
  0x25D402..0x25D406), 0x2606CC (0x2606B4), 0x2607CC (0x2607B4),
  0x26092A (0x2608A8), 0x260A18 (0x2608D0), 0x260B0E (0x260AD0),
  0x260B8C (0x260B74), 0x260DF4 and 0x260E1A (0x260D9C), 0x260EE6 and
  0x260F20 (0x260EBC), 0x29DDE0 (0x29DDD4 movement primitive). No plain
  bl, no b/b.d jump-table entry, no LE word and no halfword-swapped
  (limm middle-endian) reference to 0x2E5658 in any of the 16 payloads;
- at every call site the delay slot loads an argument (imm 0/1 or
  r13/r14) and the instruction after the call never consumes r0: the
  return value is ignored everywhere, consistent with the empty body;
- the dominant pattern after the call is gate CLEAR (0x25DEAC) followed
  by the byte sender 0x25CB3C (sites 0x25D3D2, 0x2606CC, 0x2607CC,
  0x26092A, 0x260A18, 0x260B0E, 0x260B8C, 0x29DDE0): 0x2E5658 marks the
  transaction boundary right before a new gate-clear/send opening, and
  in the close helper it follows the final gate-set: a marker with no
  runtime effect in V1.1;
- 0x2E5658 is a distinct function, not the tail of the DataTransfer
  forwarder 0x2E5648 (push blink -> 0x334130 -> 0x3042A8 -> 0x33419C),
  whose window label ended exactly at 0x2E5658.

Read-only: firmware, blocks and tools are never modified. NON_INSTALLARE.
"""
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads, objdump_text
from s33_run_gnu_arc700 import ROOT, sha
from s33_verify_sensor_mmio_dialog import aligned_window

FIRMWARE = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Close_Helper'

FUNC = 0x2E5658

# raw LE words/halfwords of the body (payload0)
BODY_WORDS = {
    0x2E5658: 0xB6C81CFC,   # st.aw fp,[sp,-4]
    0x2E565C: 0x3700230A,   # mov fp,sp
    0x2E5660: 0x36C0240A,   # mov sp,fp
    0x2E5664: 0x341B1404,   # ld.ab fp,[sp,4]
}
BODY_HALVES = {
    0x2E5668: 0x7EE0,       # j_s [blink]
    0x2E566A: 0x78E0,       # nop_s
}

# call site -> (delay-slot pattern at site+4, first-consumer pattern at
# the instruction that follows the delay slot, argument description)
SITES = {
    0x25CB02: (r'mov_s\s+r0,0x1', r'pop_s\s+blink', 'imm 1 (close helper 0x25CAF4)'),
    0x25D3D2: (r'mov_s\s+r0,r13', r'bl\s+[-0-9]+\s+;0x25deac\b', 'reg r13 (0x25D3AC)'),
    0x25D3F6: (r'mov_s\s+r0,0x1', r'cmp_s\s+r13,0x1\b', 'imm 1 (0x25D3AC)'),
    0x2606CC: (r'mov_s\s+r0,r14', r'bl\s+[-0-9]+\s+;0x25deac\b', 'reg r14 (0x2606B4)'),
    0x2607CC: (r'mov_s\s+r0,r14', r'bl\s+[-0-9]+\s+;0x25deac\b', 'reg r14 (0x2607B4)'),
    0x26092A: (r'add_s\s+r15,r13,0x1', r'bl\.d\s+[-0-9]+\s+;0x25deac\b', 'none (0x2608A8)'),
    0x260A18: (r'mov_s\s+r0,r13', r'bl\.d\s+[-0-9]+\s+;0x25deac\b', 'reg r13 (0x2608D0)'),
    0x260B0E: (r'mov_s\s+r0,0\b', r'bl\s+[-0-9]+\s+;0x25deac\b', 'imm 0 (0x260AD0)'),
    0x260B8C: (r'mov_s\s+r0,r14', r'bl\s+[-0-9]+\s+;0x25deac\b', 'reg r14 (0x260B74)'),
    0x260DF4: (r'mov_s\s+r0,0\b', r'mov_s\s+r0,r15\b', 'imm 0 (0x260D9C)'),
    0x260E1A: (r'mov_s\s+r0,0x1', r'cmp_s\s+r13,0\b', 'imm 1 (0x260D9C)'),
    0x260EE6: (r'mov_s\s+r0,r14', r'cmp\s+r13,128\b', 'reg r14 (0x260EBC)'),
    0x260F20: (r'mov_s\s+r0,0x1', r'cmp_s\s+r13,0\b', 'imm 1 (0x260EBC)'),
    0x29DDE0: (r'mov_s\s+r0,r14', r'bl\s+[-0-9]+\s+;0x25deac\b', 'reg r14=0 (0x29DDD4)'),
}


def has(text: str, pattern: str) -> None:
    flat = re.sub(r'\s+', ' ', text)
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

    def u16(a: int) -> int:
        return struct.unpack_from('<H', p0, a - base0)[0]

    # --- body: raw words and dedicated window ----------------------------------
    for addr, value in BODY_WORDS.items():
        assert u32(addr) == value, (hex(addr), hex(u32(addr)), hex(value))
    for addr, value in BODY_HALVES.items():
        assert u16(addr) == value, (hex(addr), hex(u16(addr)), hex(value))

    windows = {}

    def win(name: str, lo: int, hi: int) -> str:
        w = aligned_window(p0, base0, lo, hi)
        windows[name] = f'0x{lo:x}..0x{hi:x}'
        (out / f'window_{name}.txt').write_text(w)
        return w

    body = win('body', FUNC, 0x2E566C)
    lines = [ln for ln in body.splitlines() if re.match(r'\s*[0-9a-f]+:', ln)]
    assert len(lines) == 6, len(lines)
    has(body, r'2e5658:.*st\.aw\s+fp,\[sp,-4\]')
    has(body, r'2e565c:.*mov\s+fp,sp')
    has(body, r'2e5660:.*mov\s+sp,fp')
    has(body, r'2e5664:.*ld\.ab\s+fp,\[sp,4\]')
    has(body, r'2e5668:.*j_s\s+\[blink\]')
    has(body, r'2e566a:.*nop_s')
    # no calls, no pools, no branches, no r0, no MMIO inside the body
    flat = re.sub(r'\s+', ' ', body)
    for absent in (r'\s+bl\b', r'\s+bl\.d\b', r'\s+bl_s\b', r'\s+b_s\b',
                   r'\s+b\.d\b', r'\[pcl', r'\br0\b', r'\bbset\b',
                   r'\bbclr\b', r'\bsth\.di\b', r'push_s blink\b'):
        assert not re.search(absent, flat), absent
    # the prologue word is the stock frame push used all over payload0
    stock = p0.count(struct.pack('<I', BODY_WORDS[0x2E5658]))
    assert stock > 1000, stock
    stock_mov = p0.count(struct.pack('<I', BODY_WORDS[0x2E565C]))
    assert stock_mov > 1000, stock_mov

    # --- close helper context (ties to iteration 14) -----------------------------
    close = win('close_helper', 0x25CAF4, 0x25CB0C)
    has(close, r'25caf4:.*push_s\s+blink')
    has(close, r'25caf6:.*bl\s+[-0-9]+\s+;0x25df9c')
    has(close, r'25cafa:.*bl\s+[-0-9]+\s+;0x25df4c')
    has(close, r'25cafe:.*bl\s+[-0-9]+\s+;0x25dee8')
    has(close, r'25cb02:.*bl\.d\s+[-0-9]+\s+;0x2e5658')
    has(close, r'25cb06:.*mov_s\s+r0,0x1')
    has(close, r'25cb08:.*pop_s\s+blink')
    has(close, r'25cb0a:.*j_s\s+\[blink\]')

    # --- the forwarder 0x2E5648 is a different function --------------------------
    thunk = win('forwarder_2E5648', 0x2E5648, FUNC)
    has(thunk, r'2e5648:.*push_s\s+blink')
    has(thunk, r'2e564a:.*bl\s+[-0-9]+\s+;0x334130')
    has(thunk, r'2e564e:.*bl\s+[-0-9]+\s+;0x3042a8')
    has(thunk, r'2e5652:.*b\s+[-0-9]+\s+;0x33419c')
    assert not re.search(r'bl\s+[-0-9]+\s+;0x2e5658',
                         re.sub(r'\s+', ' ', thunk))

    # --- ctxA busy-bit context inside 0x25D3AC ------------------------------------
    bit7 = win('d3ac_bit7_ctxA', 0x25D3F6, 0x25D410)
    has(bit7, r'25d3f6:.*bl\.d\s+[-0-9]+\s+;0x2e5658')
    has(bit7, r'25d400:.*ld_s\s+r1,\[sp,0\]')
    has(bit7, r'25d402:.*ldw_s\s+r0,\[r1,0x2\]')
    has(bit7, r'25d404:.*bset_s\s+r0,r0,0x7')
    has(bit7, r'25d406:.*stw_s\s+r0,\[r1,0x2\]')

    # --- call-site census from the GNU linear decode of payload0 ------------------
    listing = objdump_text(ROOT, block_dir, info[0], p0)
    bl_sites, jump_sites = [], []
    for ln in listing.splitlines():
        if re.search(r'\s+bl(\.d)?\s+[-0-9]+\s+;0x2e5658\s*$', ln):
            bl_sites.append(int(ln.split(':')[0].strip(), 16))
        if re.search(r'\s+b(\.d)?_s?\s+[-0-9]+\s+;0x2e5658\s*$', ln):
            jump_sites.append(int(ln.split(':')[0].strip(), 16))
    assert sorted(bl_sites) == sorted(SITES), [hex(a) for a in bl_sites]
    assert len(bl_sites) == 14, len(bl_sites)
    assert not jump_sites, [hex(a) for a in jump_sites]
    # every site is a bl.d (delay slot), none a plain bl
    for ln in listing.splitlines():
        if re.search(r'\s+bl\s+[-0-9]+\s+;0x2e5658\s*$', ln):
            raise AssertionError('plain bl to 0x2E5658: ' + ln)

    # --- per-site dedicated windows: delay slot + first consumer ------------------
    # the stream is aligned exactly on the site, so the decoded instruction
    # lines are: [0] the bl.d, [1] its delay slot, [2] the first consumer.
    site_facts = {}
    for site, (slot_pat, next_pat, arg) in sorted(SITES.items()):
        w = win(f'site_{site:x}', site, site + 16)
        ilines = [ln for ln in w.splitlines()
                  if re.match(r'\s*[0-9a-f]+:', ln)]
        assert len(ilines) >= 3, (hex(site), w)
        assert re.match(rf'\s*{site:x}:', ilines[0]), (hex(site), ilines[0])
        first = re.sub(r'\s+', ' ', ilines[0])
        assert re.search(rf'{site:x}:.*bl\.d\s+[-0-9]+\s+;0x2e5658', first)
        slot = re.sub(r'\s+', ' ', ilines[1])
        assert re.search(slot_pat, slot), (hex(site), slot)
        consumer = re.sub(r'\s+', ' ', ilines[2]).strip()
        assert re.search(next_pat, consumer), (hex(site), consumer)
        # the first consumer never tests r0: the return value is unused
        assert not re.search(r'cmp.*\br0\b|tst\s+r0', consumer), (hex(site), consumer)
        site_facts[hex(site)] = {'delay_slot': slot.split('\t')[-1].strip(),
                                 'first_consumer': consumer.split('\t')[-1].strip(),
                                 'argument': arg}

    # --- reference classification across all payloads ------------------------------
    le = struct.pack('<I', FUNC)
    swapped = struct.pack('<HH', FUNC & 0xFFFF, FUNC >> 16)
    for idx in sorted(payloads):
        pl = payloads[idx]
        assert pl.find(le) == -1, f'LE word ref in payload {idx}'
        assert pl.find(swapped) == -1, f'middle-endian ref in payload {idx}'

    # --- net-effect model of the body ----------------------------------------------
    def sim(sp: int, fp: int, mem: dict) -> tuple:
        mem = dict(mem)
        sp2 = sp - 4                # st.aw fp,[sp,-4]  (pre-decrement writeback)
        mem[sp2] = fp & 0xFFFFFFFF  # store fp
        fp2 = sp2                   # mov fp,sp
        sp3 = fp2                   # mov sp,fp
        fp3 = mem[sp3]              # ld.ab fp,[sp,4]  (load first)
        sp4 = sp3 + 4               # (post-increment writeback)
        return sp4, fp3, mem

    for sp, fp in ((0x1000, 0xABCD), (0x5DADCC, 0x50F52C), (0xFFFFFFF0, 1)):
        mem = {sp - 4: 0xDEADBEEF, sp: 0x1234}
        sp_out, fp_out, mem_out = sim(sp, fp, mem)
        assert sp_out == sp and fp_out == fp, (hex(sp), hex(fp))
        assert mem_out[sp] == mem[sp]
        assert mem_out[sp - 4] == (fp & 0xFFFFFFFF)   # only scratch write
        assert set(mem_out) == set(mem)

    result = {
        'topic': 'lens wire chain: 0x2E5658 post-close helper is an empty '
                 '(nullsub) leaf function; full call-site census (iteration '
                 '14 open point a)',
        'date': datetime.now(timezone.utc).isoformat(),
        'firmware_sha256': sha(FIRMWARE),
        'payload0': {'base': hex(base0), 'size': hex(info[0]['size'])},
        'body': {
            'address': hex(FUNC),
            'size_bytes': 0x14,
            'instructions': ['st.aw fp,[sp,-4]', 'mov fp,sp', 'mov sp,fp',
                             'ld.ab fp,[sp,4]', 'j_s [blink]', 'nop_s'],
            'raw_words': {hex(a): hex(v) for a, v in BODY_WORDS.items()},
            'raw_halves': {hex(a): hex(v) for a, v in BODY_HALVES.items()},
            'verdict': 'EMPTY FUNCTION (nullsub): frame prologue immediately '
                       'followed by the frame epilogue, no body, no calls, no '
                       'pools, no MMIO, no r0 access; leaf (no push_s blink)',
            'net_effect': 'sp and fp restored, r0 returned unchanged (the '
                          'argument is never read), memory unchanged except '
                          'mem[sp-4] := fp (scratch word below the un-moved '
                          'sp)',
            'stock_prologue_occurrences_payload0': stock,
        },
        'call_sites': site_facts,
        'call_site_census': {
            'count': 14,
            'enclosing_functions': {
                '0x25CB02': 'close helper 0x25CAF4',
                '0x25D3D2': '0x25D3AC (recovery/status writer, sets bit 7 of '
                            'ctxA[+2] at 0x25D402..06)',
                '0x25D3F6': '0x25D3AC',
                '0x2606CC': '0x2606B4 (bulk uploader)',
                '0x2607CC': '0x2607B4',
                '0x26092A': '0x2608A8',
                '0x260A18': '0x2608D0',
                '0x260B0E': '0x260AD0',
                '0x260B8C': '0x260B74',
                '0x260DF4': '0x260D9C',
                '0x260E1A': '0x260D9C',
                '0x260EE6': '0x260EBC',
                '0x260F20': '0x260EBC',
                '0x29DDE0': '0x29DDD4 (movement primitive)',
            },
            'pattern': '8 of 14 sites call 0x2E5658 immediately before '
                       'gate CLEAR (0x25DEAC) + byte sender (0x25CB3C), i.e. '
                       'at the opening of a new transaction; the close helper '
                       'calls it after the final gate SET: a boundary marker '
                       'with no runtime effect in V1.1',
            'return_value': 'never consumed at any site (first consumer '
                            'overwrites r0, pops, or tests r13); NB the r0 '
                            'value seen by the caller at return comes from '
                            'the caller delay slot at 13 of 14 sites (the '
                            'body never touches r0); at 0x26092A the delay '
                            'slot does not touch r0 either',
            'other_references': 'no plain bl, no b/b.d jump-table entry, no '
                                 'LE word and no halfword-swapped (limm '
                                 'middle-endian) occurrence of 0x2E5658 in '
                                 'any of the 16 payloads',
        },
        'context_windows': {
            'close_helper': '0x25CAF4: strobe clear x2, gate SET, bl.d '
                            '0x2E5658 (mov_s r0,0x1), pop, return',
            'forwarder_2E5648': 'separate function: push blink, 0x334130, '
                                '0x3042A8, tail 0x33419C (the DataTransfer '
                                'forwarder; its window label ended at '
                                '0x2E5658)',
        },
        'windows_verified': windows,
        'limits': [
            'static only: no MMIO, lens MCU or camera hardware accessed; no '
            'firmware executed; NON_INSTALLARE',
            'the empty body is byte-verified in V1.1; whether other builds '
            '(V1.0 or development firmware) share the empty body is not '
            'provable from this sample',
            'the purpose of the nullsub (compiled-out hook/trace/notify '
            'placeholder) is inference; the bytes prove only that the call '
            'has no runtime effect',
            'the enclosing functions of the 0x2608A8-0x260EBC sites are '
            'attributed by entry address (push_s blink) without full body '
            'decode; the site facts themselves are byte-verified',
            'runtime values (r13/r14 contents at the sites) are not '
            'determinable statically',
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
    print('body: 0x2E5658 empty leaf (prologue+epilogue only),',
          'stock prologue occurrences:', stock)
    print('call sites: 14, all bl.d, all boundary-marked;',
          'return value never consumed')
    print('no LE/middle-endian word references to 0x2E5658 in any payload')


if __name__ == '__main__':
    main()
