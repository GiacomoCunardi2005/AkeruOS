#!/usr/bin/env python3
"""Static classification of the 33 real callers of the lens transaction 0x25F338.

Follows the wire-protocol session (s33_verify_lens_wire_protocol.py) and
answers its open point 1: which callers inject which command byte into the
control descriptor before the transaction, and which wrapper layer feeds
them. Byte-verified layers:

- the command-injection wrapper 0x25F3F4(buf512, rec16, desc, src): saves
  desc{0,1,2}, injects {desc[1]=[src+0], desc[2]=[src+2]}, zeroes desc[0],
  calls 0x25F338, then restores the descriptor;
- the dispatcher 0x25C4B4: selects wrapper 0x25C268 (cmd 8, second path cmd
  0x11) or 0x25C3F8 (cmd 4) on flag bit 0xA of the request context, then an
  absolute-position path that writes cmd=[0x36B244+0x1c]-1 and a final
  indirect call to 0x32E508 (P1IDSTR copy);
- the fixed-parameter switch 0x1EE730(arg0 in 0..6, ..., table r3): jump
  table 04 11 1e 2b 38 70 7d at 0x1EE77A over halfword table fields
  [r3+0xC4..0xDE], converging on descriptor {0,4,0} + transaction with
  buf512=0x54D8A8, rec16=0x50E940;
- the shadow structure 0x36B25C {+0 current byte, +2 word, +4 requested
  byte}: written by the move loops (0x1EE686, 0x1EE6DC, 0x1EF0EA, 0x1EF132,
  0x29E82C) and consumed by 0x1ED488/0x1ED684 into descriptor 0x36B254.

The per-caller table is bounded-window analysis over the linear GNU listing
(candidate classification); wrapper entries, switch header/branch targets and
the shared tail are disassembled separately, skipping inline table data.
The caller list and every literal asserted here are re-read from
the raw payload bytes. pcl note: ld_s/ld annotations are unscaled pool
addresses; ld.as resolves to (PC & ~3) + s12*4.

Read-only: firmware, blocks and tools are never modified.
"""
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads, objdump_text, he
from s33_run_gnu_arc700 import ROOT, sha
from s33_verify_sensor_mmio_dialog import aligned_window

FIRMWARE = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Wrapper_Classification'

TRX = 0x25F338
FALSE_POSITIVE = 0x232B4A
INJECT_WRAPPER = 0x25F3F4

# Literal words re-read from raw payload bytes (ld_s/ld: pool address as
# annotated, unscaled; ld.as: (PC & ~3) + s12*4).
LITERALS = {
    0x25C3AC: 0x50E940,  # rec16 buffer
    0x25C3B4: 0x36B244,  # control cluster base (desc at +0x10, shadow at +0x18)
    0x1EE994: 0x50E940,
    0x1EE998: 0x54D8A8,   # buf512 for the switch function
    0x1EE9B0: 0x36B254,   # active descriptor
    0x1EE9A0: 0x36B25C,   # shadow (written at 0x1EE678..0x1EE686)
    0x1ED2F8: 0x50E940,   # ld.as-scaled pools
    0x25C3B4: 0x36B244,   # ld.as 0x25C558 -> (0x25C558 & ~3) - 105*4 = 0x25C3B4
    0x29E2BC: 0x50E140,   # zoom-family buf512
    0x29E748: 0x50E140,
    0x29E74C: 0x50E340,
    0x25FB20: 0x36B288,   # second descriptor pair (0x25F800 path)
    0x25FB34: 0x36B290,   # command source struct for the inject wrapper
    0x25D8BC: 0x36B290,   # status/target struct in the 0x25D5EE family
    0x25D8B8: 0x36B270,
    0x25D8AC: 0x511D00,
    0x1EDDDC: 0x36B254,
    0x1EDDE0: 0x3692E8,
    0x1EDE00: 0x50E980,
    0x1EDE04: 0x50D940,
    0x260620: 0x511F00,   # stack-descriptor family buf512
    0x168F94: 0x50F540,
    0x168F98: 0x36B290,
    0x168F9C: 0x50FD80,
    0x168FA0: 0x50FD40,
    0x25C848: 0x351718,   # 'P1IDSTR' string
    0x25C84C: 0x32E508,   # indirect target after the dispatcher
    0x25C844: 0x50F210,
}

# Call-verified entries for the asserted windows.
W_INJECT = (0x25F3F4, 0x25F428)      # called at 0x168C00 and 0x25F7E4
W_DISPATCH = (0x25C4B4, 0x25C4B4 + 0x3A)  # push_s blink entry, callers 0x25C4DE/0x25C4E2 sites inside
W_CMD8 = (0x25C268, 0x25C318)        # push_s blink entry
W_CMD4 = (0x25C3F8, 0x25C3F8 + 0x50)  # push_s blink entry
W_SWITCH = (0x1EE730, 0x1EE77A)      # stop BEFORE inline jump-table data

JUMP_TABLE_1EE77A = bytes([0x04, 0x11, 0x1e, 0x2b, 0x38, 0x70, 0x7d])


def pool_of(line: str, pc: int) -> int | None:
    """Pool address for a pcl load in the linear listing."""
    m = re.search(r'\tld(\.as|_s|\.ab|\.aw)?\s+r\d+,\[pcl,(-?0x[0-9a-f]+|-?\d+)\]\t;0x([0-9a-f]+)', line)
    if not m:
        return None
    off = int(m.group(2), 0)
    if m.group(1) == '.as':
        return (pc & ~3) + off * 4
    return int(m.group(3), 16)


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
    assert base0 == 0x0AD800

    def lit(addr):
        return struct.unpack_from('<I', p0, addr - base0)[0]

    for addr, value in LITERALS.items():
        got = lit(addr)
        assert got == value, (hex(addr), hex(got), hex(value))

    listing = objdump_text(ROOT, block_dir, info[0], p0)
    lines = listing.splitlines()
    addr_at = {}
    for i, ln in enumerate(lines):
        m = re.match(r'^\s*([0-9a-f]+):', ln)
        if m:
            addr_at.setdefault(int(m.group(1), 16), i)

    # --- Caller inventory (same extraction as the wire session). ---
    callers = []
    for ln in lines:
        if re.search(r'\tbl(\.d)?\t[-0-9]+\t;0x25f338\s*$', ln):
            callers.append(int(ln.split(':')[0].strip(), 16))
    assert FALSE_POSITIVE in callers
    real = sorted(c for c in callers if c != FALSE_POSITIVE)
    assert len(real) == 33, len(real)
    expected = [
        0x168C1E, 0x1ECB52, 0x1ECC60, 0x1ED488, 0x1ED684, 0x1EDB88, 0x1EE23A,
        0x1EE544, 0x1EE5E8, 0x1EE826, 0x1EEBBC, 0x1EEED0, 0x1EF086, 0x1EF33E,
        0x1EF4DA, 0x25C2AE, 0x25C30A, 0x25C440, 0x25C582, 0x25D4B6, 0x25F800,
        0x26055E, 0x2605E4, 0x2612B0, 0x2613D0, 0x29E0D0, 0x29E15E, 0x29E362,
        0x29E3D6, 0x29E414, 0x2FF986, 0x2FFAE2, 0x2FFD4E,
    ]
    assert real == expected, [hex(c) for c in real]

    # --- Asserted windows, aligned at call-verified entries. ---
    windows = {}
    for name, (lo, hi) in [
        ('inject_wrapper_25f3f4', W_INJECT),
        ('dispatcher_25c4b4', W_DISPATCH),
        ('cmd8_wrapper_25c268', W_CMD8),
        ('cmd4_wrapper_25c3f8', W_CMD4),
        ('param_switch_1ee730', W_SWITCH),
    ]:
        windows[name] = aligned_window(p0, base0, lo, hi)
        assert windows[name].strip(), name
    # GNU linear decoding over the inline byte tables shifts instruction
    # boundaries. Restart separately at each target computed by add1_s.
    jt = p0[0x1EE77A - base0:0x1EE77A - base0 + 7]
    assert jt == JUMP_TABLE_1EE77A, jt.hex()
    switch_targets = [0x1EE77A + 2 * byte for byte in jt]
    assert switch_targets == [0x1EE782, 0x1EE79C, 0x1EE7B6, 0x1EE7D0,
                              0x1EE7EA, 0x1EE85A, 0x1EE874]
    for case, target in enumerate(switch_targets):
        name = f'param_switch_case_{case}'
        windows[name] = aligned_window(p0, base0, target, target + 0x1A)
        assert f'ldh\tr0,[r3,{196 + case * 2}]' in windows[name], (case, 'first field')
        assert f'ldh\tr0,[r3,{210 + case * 2}]' in windows[name], (case, 'second field')
    windows['param_switch_shared'] = aligned_window(p0, base0, 0x1EE802, 0x1EE830)
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))

    def w(name):
        return windows[name]

    # Inject wrapper: save desc, inject {desc[1]=[src+0], desc[2]=[src+2]},
    # zero desc[0], call transaction, restore.
    t = w('inject_wrapper_25f3f4')
    assert re.search(r'\tldb_s\tr14,\[r2,0\]', t), 'desc byte0 save missing'
    assert re.search(r'\tstb_s\tr3,\[r2,0\]', t), 'desc byte0 zero missing'
    assert re.search(r'\tldw_s\tr1,\[r0,0x2\]', t), 'src word2 load missing'
    assert re.search(r'\tldw_s\tr15,\[r2,0x2\]', t), 'desc word2 save missing'
    assert re.search(r'\tldb\tr16,\[r2,1\]', t), 'desc byte1 save missing'
    assert re.search(r'\tstw_s\tr1,\[r2,0x2\]', t), 'desc word2 inject missing'
    assert re.search(r'\tldb_s\tr0,\[r0,0\]', t), 'src byte0 load missing'
    assert re.search(r'\tstb_s\tr0,\[r2,0x1\]', t), 'desc byte1 inject missing'
    assert re.search(r'\tbl_s\t-224\t;0x25f338\b', t), 'transaction call missing'
    assert re.search(r'\tstb_s\tr14,\[r13,0\]', t), 'byte0 restore missing'
    assert re.search(r'\tstw_s\tr15,\[r13,0x2\]', t), 'word2 restore missing'
    assert re.search(r'\tstb\tr16,\[r13,1\]', t), 'byte1 restore missing'

    # Dispatcher 0x25C4B4: flag bit 0xA selects cmd8 wrapper vs cmd4 wrapper.
    t = w('dispatcher_25c4b4')
    assert re.search(r'\tld\.as\tr14,\[pcl,-73\]', t), 'cluster load missing'
    assert re.search(r'\tbl\.d\t-1764288\t;0xad90c\b', t), '244-byte copy missing'
    assert re.search(r'\tmov_s\tr1,0xf4\b', t), 'copy length missing'
    assert re.search(r'\tld_s\tr15,\[pcl,0x370\]\t;0x25c844\b', t), 'ctx literal missing'
    assert re.search(r'\tbtst_s\tr0,0xa\b', t), 'flag test missing'
    assert re.search(r'\tbne_s\t6\t;0x25c4e2\b', t), 'flag branch missing'
    assert re.search(r'\tbl_s\t-628\t;0x25c268\b', t), 'cmd8 wrapper call missing'
    assert re.search(r'\tbl_s\t-232\t;0x25c3f8\b', t), 'cmd4 wrapper call missing'

    # cmd8 wrapper: [0x36B244+0x11] = 8 (two call sites of the transaction).
    t = w('cmd8_wrapper_25c268')
    assert re.search(r'\tld_s\tr15,\[pcl,0x148\]\t;0x25c3b4\b', t), 'cluster base missing'
    assert re.search(r'\tadd\tr13,r15,0x10\b', t), 'descriptor = base+0x10 missing'
    assert re.search(r'\tmov_s\tr0,0x8\b', t), 'cmd 8 immediate missing'
    assert re.search(r'\tstb_s\tr0,\[r15,0x11\]', t), 'cmd 8 store missing'
    assert re.search(r'\tmov_s\tr0,0x11\b', t), 'cmd 0x11 immediate missing'
    assert re.search(r'\tbl\.d\t13332\t;0x25f6a4\b', t), 'prepare call missing'
    assert re.search(r'\tbl\.d\t13240\t;0x25f6a4\b', t), 'second prepare call missing'
    assert re.search(r'\tbl\.d\t12428\t;0x25f338\b', t), 'transaction call A missing'
    assert re.search(r'\tbl\.d\t12336\t;0x25f338\b', t), 'transaction call B missing'

    # cmd4 wrapper: [0x36B244+0x11] = 4, stack buf512, rec16 0x50E940.
    t = w('cmd4_wrapper_25c3f8')
    assert re.search(r'\tld\tr15,\[pcl,-76\]\t;0x25c3b4\b', t), 'cluster base missing'
    assert re.search(r'\tsub3\tsp,sp,256\b', t), 'stack buffer missing'
    assert re.search(r'\tmov_s\tr0,0x4\b', t), 'cmd 4 immediate missing'
    assert re.search(r'\tstb_s\tr0,\[r15,0x11\]', t), 'cmd 4 store missing'
    assert re.search(r'\tld\tr14,\[pcl,-108\]\t;0x25c3ac\b', t), 'rec16 literal missing'
    assert re.search(r'\tmov_s\tr0,sp\b', t), 'stack buf512 arg missing'
    assert re.search(r'\tbl\.d\t12024\t;0x25f338\b', t), 'transaction call missing'

    # Parameter switch 0x1EE730: 7 cases, halfword table [r3+0xC4..0xDE],
    # descriptor {0,4,0}, buf512 0x54D8A8, rec16 0x50E940.
    t = '\n'.join(w(name) for name in windows if name.startswith('param_switch'))
    assert re.search(r'\tcmp_s\tr0,0x6\b', t), 'switch bound missing'
    assert re.search(r'\tadd\tr12,pcl,0x12\t;0x1ee77a\b', t), 'jump table base missing'
    assert re.search(r'\tldb\tr0,\[r12,r0\]', t), 'jump table read missing'
    assert re.search(r'\tj_s\.d\t\[r12\]', t), 'jump table dispatch missing'
    jt = p0[0x1EE77A - base0:0x1EE77A - base0 + 7]
    assert jt == JUMP_TABLE_1EE77A, jt.hex()
    for field in range(196, 224, 2):
        assert f'ldh\tr0,[r3,{field}]' in t, (field, 'table field missing')
    assert re.search(r'\tldw_s\tr0,\[r1,0x2\]', t) and re.search(r'\tbtst_s\tr0,0xa\b', t)
    assert re.search(r'\tld_s\tr2,\[pcl,0x19c\]\t;0x1ee9b0\b', t), 'descriptor literal missing'
    assert re.search(r'\tmov_s\tr0,0\b', t) and re.search(r'\tstb_s\tr0,\[r2,0\]', t)
    assert re.search(r'\tstw_s\tr0,\[r2,0x2\]', t)
    assert re.search(r'\tmov_s\tr0,0x4\b', t), 'fixed value 4 missing'
    assert re.search(r'\tstb_s\tr0,\[r2,0x1\]', t), 'descriptor byte1 store missing'
    assert re.search(r'\tld_s\tr0,\[pcl,0x174\]\t;0x1ee998\b', t), 'buf512 literal missing'
    assert re.search(r'\tld_s\tr1,\[pcl,0x17c\]\t;0x1ee994\b', t), 'rec16 literal missing'
    assert re.search(r'\tbl\.d\t461588\t;0x25f338\b', t), 'transaction call missing'

    # --- Mid-function byte-verified facts (raw words + listing lines). ---
    mid = {}
    for addr in (0x25C558, 0x25C572, 0x25C57A, 0x25C57C, 0x25C57E, 0x25C582,
                 0x1EE678, 0x1EE680, 0x1EE682, 0x1EE684, 0x1EE686,
                 0x1ED47C, 0x1ED480, 0x1ED656, 0x1ED65A, 0x1ED65C):
        mid[addr] = lines[addr_at[addr]]
    # Absolute-position path: cmd = [0x36B244+0x1c]-1 -> [desc+1], buf 0x50E140.
    assert 'ld.as\tr14,[pcl,-105]' in mid[0x25C558]
    assert 'ldb_s\tr0,[r14,0x1c]' in mid[0x25C572]
    assert 'sub_s\tr0,r0,0x1' in mid[0x25C57A]
    assert 'stb_s\tr0,[r14,0x11]' in mid[0x25C57C]
    assert 'ld_s\tr14,[pcl,0x2e0]\t;0x25c85c' in mid[0x25C57E]
    assert lit(0x25C85C) == 0x50E140
    assert 'bl.d\t11704\t;0x25f338' in mid[0x25C582]
    # Shadow writes: {+0 cur byte, +2 word, +4 requested byte}.
    assert 'ld_s\tr2,[pcl,0x328]\t;0x1ee9a0' in mid[0x1EE678]
    assert 'stb_s\tr1,[r2,0]' in mid[0x1EE680]
    assert 'stw_s\tr3,[r2,0x2]' in mid[0x1EE684]
    assert 'stb_s\tr1,[r2,0x4]' in mid[0x1EE686]
    # Shadow -> descriptor copies (cmd and word).
    assert 'ldb_s\tr1,[r0,0x4]' in mid[0x1ED47C]
    assert 'stb_s\tr1,[r0,0x1]' in mid[0x1ED480]
    assert 'ld_s\tr0,[pcl,0x11c]\t;0x1ed770' in mid[0x1ED656]
    assert 'stw_s\tr0,[r15,0x2]' in mid[0x1ED65A]
    assert 'stb_s\tr14,[r15,0x1]' in mid[0x1ED65C]

    # Shadow +4 store sites found by scan (bounded window after each 0x36B25C load).
    shadow4_stores = []
    ld_re = re.compile(r'^\s*([0-9a-f]+):.*\tld(\.as|_s|\.ab|\.aw)?\s+(r\d+),\[pcl,(-?0x[0-9a-f]+|-?\d+)\]\t;0x([0-9a-f]+)')
    for i, ln in enumerate(lines):
        m = ld_re.match(ln)
        if not m:
            continue
        pc = int(m.group(1), 16)
        pool = pool_of(ln, pc)
        if pool is None:
            continue
        try:
            v = lit(pool)
        except Exception:
            continue
        if v != 0x36B25C:
            continue
        reg = m.group(3)
        for j in range(i + 1, min(i + 16, len(lines))):
            s = lines[j]
            if re.search(rf'\tstb(\.ab|\.aw|_s)?\s+\w+,\[{reg},(0x4|4)\]', s):
                shadow4_stores.append(int(s.split(':')[0].strip(), 16))
                break
            if re.search(rf'\t(mov|ld)\w*\s+{reg},', s):
                break
    assert shadow4_stores == [0x1EE686, 0x1EE6DC, 0x1EF0EA, 0x1EF132, 0x29E82C], \
        [hex(a) for a in shadow4_stores]

    # --- Per-caller bounded-window classification (candidate, linear listing).---
    def classify(site):
        i = addr_at[site]
        start = max(i - 30, 0)
        window = lines[start:i + 1]
        text = '\n'.join(window)
        # r2 at the call: last assignment to r2 in the window.
        r2 = None
        for ln in window[:-1]:
            if re.search(r'\tmov_s\tr2,(r\d+|sp)\b', ln):
                r2 = re.search(r'\tmov_s\tr2,(r\d+|sp)\b', ln).group(1)
            elif re.search(r'\tld(\.as|_s)?\s+r2,\[pcl', ln):
                r2 = 'pool:' + hex(pool_of(ln, int(ln.split(':')[0].strip(), 16)) or 0)
        desc_val = 'stack(sp)' if r2 == 'sp' else (r2 if r2 else '?')
        if isinstance(r2, str) and r2.startswith('pool:'):
            desc_val = 'literal ' + hex(lit(int(r2[5:], 16)))
        # Descriptor writes with immediates before the call.
        imm_stores = re.findall(
            r'\tmov(?:_s)?\tr\d+,(0x[0-9a-f]+|\d+)\s*\n\s*[0-9a-f]+:\s*\S+\s+\tstb(?:_s)?\tr\d+,\[r\d+,0x11?\]',
            text)
        inject = bool(re.search(r'\tbl(?:\.d)?\t[-0-9]+\t;0x25f3f4\s*$', text, re.M))
        step_loop = bool(re.search(r'\tstb(?:_s)?\tr\d+,\[r\d+,0?x?1\]', text)) and \
            bool(re.search(r'\tldb(?:_s)?\tr\d+,\[r\d+,0x5\]', text)) and \
            bool(re.search(r'\tasl(?:_s)?\tr\d+,r\d+,0x9\b', text))
        fixed04 = ('mov_s\tr0,0x4' in text and 'stb_s\tr0,[r2,0x1]' in text
                   and 'stw_s\tr0,[r2,0x2]' in text)
        shadow_copy = bool(re.search(r'\tldb(?:_s)?\tr\d+,\[r\d+,0x4\]', text)) and \
            bool(re.search(r'\tstb(?:_s)?\tr\d+,\[r\d+,0x1\]', text))
        family = 'other'
        if fixed04:
            family = 'fixed_desc_{0,4,0}'
        elif inject:
            family = 'inject_wrapper_25f3f4'
        elif imm_stores and desc_val == 'literal 0x36b254':
            family = 'cmd_imm_' + ','.join(imm_stores)
        elif step_loop:
            family = 'position_step_loop'
        elif shadow_copy:
            family = 'shadow_copy_move'
        elif desc_val == 'stack(sp)':
            family = 'stack_descriptor'
        elif re.search(r'\tsub_s\tr\d+,r\d+,0x1\s*\n\s*[0-9a-f]+:\s*\S+\s+\tstb(?:_s)?\tr\d+,\[r\d+,0x11\]', text):
            family = 'absolute_position_[cluster+0x1c]-1'
        return {
            'site': he(site),
            'desc_r2': desc_val,
            'family': family,
            'imm_cmd_stores': imm_stores,
            'calls_inject_wrapper': inject,
            'position_step_loop': step_loop,
            'shadow_copy': shadow_copy,
        }

    table = [classify(c) for c in real]

    result = {
        'analysis': 'STATIC classification of the 33 real transaction callers: '
                    'wrapper layers, command-byte injection sites and descriptor families',
        'firmware_reference': 'Nikon S33 V1.1 (camera observed V1.0; offsets not portable without proof)',
        'callers_total': 33,
        'caller_sites': [he(c) for c in real],
        'wrapper_layers': {
            'inject_0x25f3f4': 'transaction wrapper: saves desc{0,1,2}, injects desc[1]=[src+0] and '
                               'desc[2]=[src+2], zeroes desc[0], calls 0x25F338(buf512,rec16,desc), '
                               'restores the descriptor; src seen as 0x36B290 at 0x168BFA/0x25F7DE',
            'dispatcher_0x25c4b4': 'copies 244 bytes from the 0x36B244 cluster, tests flag bit0xA of the '
                                   'request context: clear -> wrapper 0x25C268 (cmd 8 / cmd 0x11), '
                                   'set -> wrapper 0x25C3F8 (cmd 4); then the absolute-position path '
                                   '0x25C558..0x25C582 and an indirect call to 0x32E508 with '
                                   'r1=0x351718 (P1IDSTR)',
            'cmd8_wrapper_0x25c268': 'writes [0x36B244+0x11]=8 (path A) or 0x11 (path B) into the active '
                                     'descriptor 0x36B254, prepare 0x25F6A4, transaction '
                                     '(arg r0, 0x50E940, 0x36B254)',
            'cmd4_wrapper_0x25c3f8': 'writes [0x36B244+0x11]=4, stack reserved by sub3 sp,sp,256, '
                                     'transaction(sp, 0x50E940, 0x36B254)',
            'absolute_move_0x25c582': 'cmd = [0x36B244+0x1c]-1 = [0x36B25C+4]-1 written to [0x36B254+1]; '
                                      'transaction(0x50E140, rec16, 0x36B254)',
            'param_switch_0x1ee730': '7-case switch (jump table 04 11 1e 2b 38 70 7d at 0x1EE77A) over '
                                      'halfword table fields [r3+0xC4..0xDE]; with flag bit0xA set, '
                                      'descriptor {0,4,0} + transaction(0x54D8A8, 0x50E940, 0x36B254) '
                                      'with block data phase',
        },
        'control_structs': {
            '0x36B244': 'cluster base: +0x10 descriptor {byte0, byte1=value/step, halfword2}, '
                        '+0x11 command byte, +0x1c = 0x36B25C+4 requested byte',
            '0x36B25C': 'shadow {+0 current byte, +2 word, +4 requested byte (target-1)}; '
                        '+4 stores at 0x1EE686/0x1EE6DC/0x1EF0EA/0x1EF132/0x29E82C; '
                        'consumed into the descriptor by 0x1ED47C..0x1ED480 and 0x1ED656..0x1ED65C',
            '0x36B290': 'command source struct for the inject wrapper ([+0] cmd byte, [+2] word); '
                        'also a status/target struct in the 0x25D5EE..0x25D8CC family',
            '0x36B288': 'second descriptor pair used by the 0x25F800 path (ctx 0x36B284/0x36B290)',
        },
        'caller_table': table,
        'byte_verified': {
            'jump_table_0x1ee77a': JUMP_TABLE_1EE77A.hex(' '),
            'switch_table_fields': [hex(f) for f in range(0xC4, 0xE0, 2)],
            'switch_case_targets': [he(target) for target in switch_targets],
            'fixed_descriptor_before_0x1ee826': '{byte0=0, halfword2=0, byte1=4} at 0x1EE81C..0x1EE822',
            'shadow_plus4_store_sites': [he(a) for a in shadow4_stores],
            'literals': {he(a): hex(v) for a, v in LITERALS.items()},
        },
        'windows_verified': [hex(lo) for lo, _ in [
            W_INJECT, W_DISPATCH, W_CMD8, W_CMD4, W_SWITCH]] + [hex(t) for t in switch_targets] + ['0x1ee802'],
        'limits': [
            'static only: no MMIO, lens MCU or camera hardware accessed; no firmware executed',
            'the per-caller table is bounded 30-instruction window analysis over the linear GNU '
            'listing (candidate classification); wrapper/header windows start at documented '
            'entries, seven switch cases at raw jump-table targets, shared tail at branch target; '
            'inline jump-table bytes are excluded from instruction decoding',
            'descriptor byte1 semantics: for the position_step_loop family it is an incrementing '
            'step counter; for the cmd_imm wrappers it is a fixed value; the MCU-side meaning of '
            '4/8/0x11 and of [shadow+4]-1 remains inference',
            'r57 runtime value and RAM descriptor contents are not determinable statically',
            'which wrapper corresponds to BCIP_Aperture (iris Big/Small) is not yet anchored to '
            'string evidence; the fixed-value wrappers (4, 8, 0x11) and the absolute-position path '
            'are the candidates',
            'function entries reached only via computed dispatch (e.g. 0x1EE730 switch) have no '
            'direct bl callers; their producers remain to be identified',
            'muludw timing arithmetic is not modelled (known codebase caveat)',
        ],
        'sources': {str(p): sha(p) for p in [Path(__file__), FIRMWARE,
                                             ROOT / 'S33-sections/TBM_blocks/manifest.json',
                                             ROOT / 'work/build-arc/binutils/objcopy',
                                             ROOT / 'work/build-arc/binutils/objdump']},
    }
    (out / 'verified_evidence.json').write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    (EVIDENCE / 'latest.json').write_text(json.dumps(
        dict(evidence=str((out / 'verified_evidence.json').relative_to(ROOT)))) + '\n')
    print('PASS', out)
    fams = {}
    for row in table:
        fams.setdefault(row['family'], []).append(row['site'])
    for fam, sites in sorted(fams.items()):
        print(f'{fam}: {len(sites)} -> {sites}')


if __name__ == '__main__':
    main()
