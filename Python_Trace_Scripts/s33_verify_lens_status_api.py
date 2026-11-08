#!/usr/bin/env python3
"""INCOMPLETO: ultima esecuzione osservata fallisce con AssertionError
"semaphore 0x12A71C missing". Nessuna evidenza PASS pubblicata. Non usare
le conclusioni descrittive sotto come fatti verificati; riesaminare finestre,
chiamate e semantica prima di promuoverle.

Static verification of the lens command parameter contexts and status API.

Follows the wire-protocol and wrapper-classification sessions and answers two
of their open points with byte-verified windows:

1. Where do the runtime command parameters live? The per-command halfword
   tables read by the 7-case switch 0x1EE730 ([r3+0xC4..0xDE]) and by the
   status getter 0x16F41C ([r0+210+2*i], i.e. 0xD2..0xDE) are fields of the
   RAM contexts filled by 0x25CAEC/0x25C020: pool literals resolve to
   0x50F52C (0x25CEC4) and 0x50F420 (0x25C3A0). These structures are
   referenced only inside the lens cluster; no static template initializer
   exists in payload0, so the wire command bytes cannot be derived
   statically (consistent with a lens self-description read at boot).

2. Who consumes the lens cluster? A status API layer sits above it:
   - 0x30183C loads the function pointer 0x2FFFCC (pool 0x301888) and calls
     it with r0=1..5, returning the first nonzero result;
   - 0x2FFFCC(index) maps index 0..6 (jump table at 0x30000C) to fields of
     the payload0 data struct at 0x3548D8 (pool 0x3000E0; offsets 0x1F, 0x23,
     0x2D, 0x35, 0x4B, 0x9E, 0xAB), reads them via 0x32DE00 with the RAM
     object 0x5A26BC (pool 0x3000DC), then queries 0x16F41C(index, out);
   - 0x16F41C reads halfword command parameters at 0x50F420+0xD2+2*i and the
     result byte/word from the 0x50F52C context fields +5 / +0x10.

3. The literal-command function family of the wire dictionary is mapped to
   aligned entries: 0x2608A8 (0xFF then 0x50), 0x260C6C (0x70 + port read,
   status bit0), 0x25D3AC (0x70 + port read, status bit7), 0x25F6A4 (0x50 +
   sender, flag bit0xA gated), 0x2606B4 (0x80 + block data phase + 0x10).

Iris GUI anchors are byte-verified as well: the diagnostic panel that prints
"Iris status: Big/Small" (string pointers at 0x2C51A8/0x2C51AC, state getter
called with indices 8/9/0xA), the 12-entry liveview overlay format table at
0x323EE0..0x323F0C (last entry "Iris : %d (0:Big 1:Small)") and the capture
parameter dump entry "ucIrisIndex : %d" (word at 0x1DC42C).

pcl note: ld_s/ld annotations are unscaled pool addresses; ld.as resolves to
(PC & ~3) + s12*4. Read-only: firmware, blocks and tools are never modified.
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
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Status_API'

# Literal words re-read from raw payload bytes.
LITERALS = {
    0x301888: 0x2FFFCC,   # status getter function pointer (pool of 0x30183C)
    0x3000DC: 0x5A26BC,   # RAM object passed to 0x32DE00
    0x3000E0: 0x3548D8,   # payload0 data struct with per-index fields
    0x3000E4: 0x2900001,   # out-of-range error id
    0x25CEC4: 0x50F52C,   # context A filled by 0x25CAEC
    0x25C3A0: 0x50F420,   # context B filled by 0x25C020
    0x25C39C: 0x50F4D4,   # guard struct used by 0x25BFB8
    0x2609CC: 20000,        # ready-wait iterations for the 0x10 tail sites
    0x2609D4: 6000,         # ready-wait after the 0xFF send in 0x2608A8
    0x260C98: 0x1B00007,    # status code returned by 0x260C6C when port bit0 set
    0x1EF654: 0x50E940,     # record base of the write-verify-reinit loop 0x1EEF6C
    0x1EF260: 0x36B254,     # control descriptor of the write-verify-reinit loop 0x1EEF6C
}

JUMP_TABLE_30000C = bytes([4, 8, 12, 16, 20, 31, 26])
JUMP_TABLE_16F45C = bytes([0x00, 0x70, 0x0d, 0x0a])  # first 4 bytes raw

# 12-entry liveview overlay format table in payload0.
OVERLAY_TABLE = (0x323EE0, [
    0x41DA0E, 0x41DA3C, 0x41DA64, 0x41DA97, 0x41DACB, 0x41DB12,
    0x41DB2B, 0x41DB41, 0x41DB57, 0x41DB7A, 0x41DB8F, 0x41DBAC,
])

IRIS_STRINGS_P1 = {          # payload1 VA -> expected text
    0x406E89: 'Iris status: Big',
    0x406E9A: 'Iris status: Small',
    0x41DBAC: 'Iris : %d (0:Big 1:Small)',
    0x3B9CC5: 'ucIrisIndex : %d ',
    0x3860EE: 'Change Iris from MAX: %d  To MIN: %d  ',
    0x38612C: 'Change Iris from MAX: %d  To MIN: %d  ',
}


def main() -> None:
    out = EVIDENCE / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())
    firmware = FIRMWARE.read_bytes()
    assert sha(FIRMWARE) == '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'
    blocks, payloads, block_dir = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    base0 = info[0]['load_address_candidate']
    base1 = info[1]['load_address_candidate']
    p0, p1 = payloads[0], payloads[1]
    assert base0 == 0x0AD800 and base1 == 0x360800

    def lit0(addr):
        return struct.unpack_from('<I', p0, addr - base0)[0]

    for addr, value in LITERALS.items():
        got = lit0(addr)
        assert got == value, (hex(addr), hex(got), hex(value))

    # --- Strings byte-verified inside payload1. ---
    for va, text in IRIS_STRINGS_P1.items():
        raw = p1[va - base1: va - base1 + len(text)]
        assert raw == text.encode(), (hex(va), raw)
    # String pointer words in payload0.
    assert lit0(0x2C51A8) == 0x406E89 and lit0(0x2C51AC) == 0x406E9A
    assert lit0(0x1DC42C) == 0x3B9CC5
    # AE block 0x1236BC..0x125xxx references the AE log strings of payload1,
    # including the iris-change trace.
    assert lit0(0x124F64) == 0x3860EE and lit0(0x124F6C) == 0x38612C
    tbl_base, tbl_words = OVERLAY_TABLE
    for i, w in enumerate(tbl_words):
        assert lit0(tbl_base + 4 * i) == w, (hex(tbl_base + 4 * i), hex(lit0(tbl_base + 4 * i)))
    assert lit0(tbl_base + 4 * 11) == 0x41DBAC

    listing = objdump_text(ROOT, block_dir, info[0], p0)
    lines = listing.splitlines()

    def window(lo, hi):
        w = aligned_window(p0, base0, lo, hi)
        assert w.strip(), (hex(lo), hex(hi))
        return w

    windows = {}
    for name, lo, hi in [
        ('status_poll_30183c', 0x30183C, 0x301886),
        ('status_getter_2fffcc', 0x2FFFCC, 0x300080),
        ('status_query_16f41c', 0x16F41C, 0x16F4A8),
        ('ctx_fill_25caec', 0x25CAEC, 0x25CAF2),
        ('ctx_fill_25c020', 0x25C020, 0x25C036),
        ('cmd_ff50_2608a8', 0x2608A8, 0x2608CE),
        ('status70_bit0_260c6c', 0x260C6C, 0x260C8E),
        ('status70_bit7_25d3ac', 0x25D3AC, 0x25D3F2),
        ('cmd50_25f6a4', 0x25F6A4, 0x25F71C),
        ('block80_2606b4', 0x2606B4, 0x260700),
        ('iris_panel_2c5100', 0x2C5100, 0x2C517C),
        ('generic_move_2ff88c', 0x2FF88C, 0x2FF992),
    ]:
        windows[name] = window(lo, hi)
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))

    # --- Status poll 0x30183C: getter pointer + indices 1..5. ---
    t = windows['status_poll_30183c']
    assert re.search(r'\tld_s\tr13,\[pcl,0x48\]\t;0x301888\b', t), 'getter pointer missing'
    for idx in (1, 2, 3, 4, 5):
        assert re.search(rf'\tmov_s\tr0,0x{idx:x}\b' + r'.*\n\s*[0-9a-f]+:\s*\S+\s+\tjl_s\t\[r13\]', t), \
            (idx, 'getter call missing')
    assert re.search(r'\tcmp_s\tr0,0\b', t)

    # --- Status getter 0x2FFFCC: jump table + per-index field offsets. ---
    t = windows['status_getter_2fffcc']
    jt = p0[0x30000C - base0: 0x30000C - base0 + 7]
    assert jt == JUMP_TABLE_30000C, jt.hex()
    assert re.search(r'\tld_s\tr14,\[pcl,0x100\]\t;0x3000dc\b', t)
    assert re.search(r'\tld_s\tr13,\[pcl,0x100\]\t;0x3000e0\b', t)
    assert re.search(r'\tadd3\tr1,r13,0x9\b', t), 'field +9 prefetch missing'
    assert re.search(r'\tbl\t-1930184\t;0x128c20\b', t), 'memcpy 0x128C20 missing'
    assert re.search(r'\tadd_s\tr1,r1,0x4b\b', t), 'case offset 0x4B missing'
    assert re.search(r'\tadd1\tr1,r13,0x2d\b', t), 'case offset 0x2D missing'
    assert re.search(r'\tadd1\tr1,r13,0x35\b', t), 'case offset 0x35 missing'
    assert re.search(r'\tadd2\tr1,r13,0x1f\b', t), 'case offset 0x1F missing'
    assert re.search(r'\tadd2\tr1,r13,0x23\b', t), 'case offset 0x23 missing'
    assert re.search(r'\tadd\tr1,r1,158\b', t), 'case offset 0x9E missing'
    assert re.search(r'\tadd\tr1,r1,171\b', t), 'case offset 0xAB missing'
    assert re.search(r'\tbl\t187848\t;0x32de00\b', t), 'field read 0x32DE00 missing'
    assert re.search(r'\tbl\t-1923396\t;0x12a71c\b', t), 'semaphore 0x12A71C missing'
    assert re.search(r'\tbl\t-1641556\t;0x16f41c\b', t), 'query 0x16F41C missing'
    assert re.search(r'\tld_s\tr13,\[pcl,0x90\]\t;0x3000e4\b', t), 'range error literal missing'

    # --- Query 0x16F41C: contexts + halfword parameter fields 0xD2..0xDE. ---
    t = windows['status_query_16f41c']
    assert re.search(r'\tbl\.d\t969612\t;0x25bfb8\b', t), 'validation missing'
    assert re.search(r'\tbl\.d\t972464\t;0x25caec\b', t), 'context A fill missing'
    assert re.search(r'\tbl\.d\t969696\t;0x25c020\b', t), 'context B fill missing'
    for i, off in enumerate(range(210, 224, 2)):
        assert f'ldh\tr1,[r0,{off}]' in t, (off, 'parameter halfword missing')
    assert re.search(r'\tldb_s\tr0,\[r13,0x5\]', t), 'context A cmd byte +5 missing'
    assert re.search(r'\tldb_s\tr0,\[r13,0x10\]', t), 'context A count +0x10 missing'
    assert re.search(r'\tst_s\tr0,\[r14,0\]', t), 'result store missing'

    # --- Context fills store the RAM pointers. ---
    t = windows['ctx_fill_25caec']
    assert re.search(r'\tld_s\tr1,\[pcl,0x3d8\]\t;0x25cec4\b', t)
    assert re.search(r'\tst_s\tr1,\[r0,0\]', t)
    t = windows['ctx_fill_25c020']
    assert re.search(r'\tld_s\tr1,\[pcl,0x380\]\t;0x25c3a0\b', t)
    assert re.search(r'\tst_s\tr1,\[r0,0\]', t)

    # --- Literal-command functions of the wire dictionary. ---
    t = windows['cmd_ff50_2608a8']
    assert re.search(r'\tbl\t-10748\t;0x25deac\b', t), 'gate clear missing'
    assert re.search(r'\tbl\.d\t-15728\t;0x25cb3c\b', t), 'byte send 1 missing'
    assert re.search(r'\tmov_s\tr0,0xff\b', t), '0xFF literal missing'
    assert re.search(r'\tmov_s\tr0,0x50\b', t), '0x50 literal missing'
    assert re.search(r'\tbl\.d\t-14308\t;0x25d0d0\b', t), 'ready wait missing'
    t = windows['status70_bit0_260c6c']
    assert re.search(r'\tbl\.d\t-16696\t;0x25cb3c\b', t)
    assert re.search(r'\tmov_s\tr0,0x70\b', t), '0x70 literal missing'
    assert re.search(r'\tbl\t-11244\t;0x25e08c\b', t), 'port read missing'
    assert re.search(r'\tbtst_s\tr0,0\b', t), 'status bit0 missing'
    assert re.search(r'\tld_s\tr13,\[pcl,0x18\]\t;0x260c98\b', t), 'status constant missing'
    t = windows['status70_bit7_25d3ac']
    assert re.search(r'\tmov_s\tr0,0x90\b', t), '0x90 probe missing'
    assert re.search(r'\tbl_s\t-644\t;0x25d13c\b', t), 'probe 0x25D13C missing'
    assert re.search(r'\tbl_s\t-560\t;0x25d194\b', t), 'probe 0x25D194 missing'
    assert re.search(r'\tmov_s\tr0,0x70\b', t), '0x70 literal missing'
    assert re.search(r'\tbl\t3244\t;0x25e08c\b', t), 'port read missing'
    assert re.search(r'\tbtst_s\tr0,0x7\b', t), 'status bit7 missing'
    t = windows['cmd50_25f6a4']
    assert re.search(r'\tbtst_s\tr0,0xa\b', t), 'flag bit0xA missing'
    assert re.search(r'\tbne_s\t70\t;0x25f706\b', t), 'flag branch missing'
    assert re.search(r'\tbl\t-6164\t;0x25deac\b', t), 'gate missing'
    assert re.search(r'\tbl\.d\t-11144\t;0x25cb3c\b', t), 'byte send missing'
    assert re.search(r'\tmov_s\tr0,0x50\b', t), '0x50 literal missing'
    assert re.search(r'\tbl\.d\t-11128\t;0x25cb54\b', t), 'sender call missing'
    assert re.search(r'\tmov\tr0,1000\b', t), 'wait 1000 missing'
    # Parameter record write tail: 16-byte record via 0x25F31C then a 0x00 byte.
    assert re.search(r'\tbl_s\t-984\t;0x25f31c\b', t), 'record write 0x25F31C missing'
    assert re.search(r'\tbl\.d\t-11192\t;0x25cb3c\b', t), '0x00 tail send missing'
    assert re.search(r'\tmov_s\tr0,r13\b', t), '0x00 tail value missing'
    # Bit0xA-set variant: dispatch to 0x25F4EC / 0x25F5C8 record writers.
    assert re.search(r'\tbl_s\t-552\t;0x25f4ec\b', t), 'variant 0x25F4EC missing'
    assert re.search(r'\tbl_s\t-336\t;0x25f5c8\b', t), 'variant 0x25F5C8 missing'
    t = windows['block80_2606b4']
    assert re.search(r'\tbl\.d\t-15320\t;0x25caec\b', t), 'context fill missing'
    assert re.search(r'\tbl\.d\t544652\t;0x2e5658\b', t), 'helper 0x2E5658 missing'
    assert re.search(r'\tbl\.d\t-15256\t;0x25cb3c\b', t), 'byte send missing'
    assert re.search(r'\tmov_s\tr0,0x80\b', t), '0x80 literal missing'
    assert re.search(r'\tbl\.d\t-15240\t;0x25cb54\b', t), 'sender call missing'
    assert re.search(r'\tasl\tr1,r14,0x9\b', t), '512-byte stride missing'
    assert re.search(r'\tbl_s\t-208\t;0x260624\b', t), 'block write helper missing'

    # --- Iris panel: getter indices 8/9/0xA select Big/Small printouts. ---
    t = windows['iris_panel_2c5100']
    assert re.search(r'\tmov_s\tr0,0x8\b', t) and re.search(r'\tmov_s\tr0,0x9\b', t) \
        and re.search(r'\tmov_s\tr0,0xa\b', t), 'getter indices 8/9/0xA missing'
    assert re.search(r'\tld_s\tr2,\[pcl,0x74\]\t;0x2c51a8\b', t), 'Big string load missing'
    assert re.search(r'\tld_s\tr2,\[pcl,0x48\]\t;0x2c51ac\b', t), 'Small string load missing'
    assert re.search(r'\tbl\t-1502300\t;0x1564a8\b', t), 'draw call 0x1564A8 missing'
    assert re.search(r'\tmov_s\tr1,0x96\b', t), 'draw y coordinate missing'

    # --- Generic move API 0x2FF88C: mutex, length helper, stack descriptor. ---
    t = windows['generic_move_2ff88c']
    assert re.search(r'\tld_s\tr0,\[pcl,0x29c\]\t;0x2ffb3c\b', t), 'mutex literal missing'
    assert re.search(r'\tbl\.d\t-1729784\t;0x1593ac\b', t), 'mutex acquire missing'
    assert re.search(r'\tbl\.d\t-652336\t;0x26048c\b', t), 'length helper missing'
    assert re.search(r'\tbl\t-656992\t;0x25f28c\b', t), 'prefetch 0x25F28C missing'
    assert re.search(r'\tbl\.d\t-656972\t;0x25f338\b', t), 'transaction call missing'
    assert re.search(r'\tstb\tr16,\[sp,1\]', t), 'descriptor cmd byte from ctx+5 missing'
    assert re.search(r'\tsth\tr1,\[sp,2\]', t), 'descriptor halfword from ctx+6 missing'
    assert re.search(r'\tasl\tr0,r17,0x9\b', t) or re.search(r'\tasl\tr0,r14,0x9\b', t), \
        'block stride missing'

    # --- Caller census over the linear listing (candidate classification). ---
    def callers_of(target):
        found = []
        pat = re.compile(r'\tbl(?:\.d|_s)?\t[-0-9]+\t;0x' + f'{target:x}' + r'\b')
        for ln in lines:
            m = re.match(r'^\s*([0-9a-f]+):', ln)
            if m and pat.search(ln):
                found.append(he(int(m.group(1), 16)))
        return found

    census = {
        '0x25f6a4_cmd50': callers_of(0x25F6A4),
        '0x2608a8_ff50': callers_of(0x2608A8),
        '0x260c6c_status70_b0': callers_of(0x260C6C),
        '0x25d3ac_status70_b7': callers_of(0x25D3AC),
        '0x29ddd4_variant60d0': callers_of(0x29DDD4),
        '0x2606b4_block80': callers_of(0x2606B4),
        '0x260b74_block80_c': callers_of(0x260B74),
        '0x25c4b4_dispatcher': callers_of(0x25C4B4),
        '0x16f41c_status_query': callers_of(0x16F41C),
        '0x30183c_status_poll': callers_of(0x30183C),
    }
    assert len(census['0x25f6a4_cmd50']) == 32, len(census['0x25f6a4_cmd50'])
    assert len(census['0x260c6c_status70_b0']) == 25
    assert len(census['0x25d3ac_status70_b7']) == 8
    assert len(census['0x29ddd4_variant60d0']) == 29
    assert census['0x25c4b4_dispatcher'] == ['0x25c7e6']

    result = {
        'analysis': 'STATIC lens command parameter contexts and status API layer above '
                     'the wire dictionary; iris GUI anchors byte-verified',
        'firmware_reference': 'Nikon S33 V1.1 (camera observed V1.0; offsets not portable without proof)',
        'parameter_contexts': {
            '0x50F52C': 'context A, pointer stored by 0x25CAEC (pool 0x25CEC4); fields used: '
                        '+2 flag bit0xA, +5 command byte, +0x10 count; same struct as the wire '
                        'session [0x50F52C] flags',
            '0x50F420': 'context B, pointer stored by 0x25C020 (pool 0x25C3A0); halfword command '
                        'parameters at +0xD2..0xDE read by 0x16F41C cases (same field family as '
                        'the 0x1EE730 switch fields +0xC4..0xDE)',
            '0x50F4D4': 'guard struct of validator 0x25BFB8 (pool 0x25C39C)',
            'conclusion': 'no static template initializer for these contexts exists in payload0: '
                          'they are referenced only inside the lens cluster, so the runtime wire '
                          'command bytes are not statically derivable (lens self-description '
                          'hypothesis, not proven)',
        },
        'status_api_layer': {
            '0x30183c': 'loads function pointer 0x2FFFCC (pool 0x301888) and calls it with '
                        'r0=1..5, returning the first nonzero result (status aggregation)',
            '0x2fffcc': 'get-status-by-index 0..6: jump table at 0x30000C (bytes 04 08 0c 10 14 '
                        '1f 26) over fields of the payload0 struct 0x3548D8 (offsets 0x1F, 0x23, '
                        '0x2D, 0x35, 0x4B, 0x9E, 0xAB) read via 0x32DE00 with RAM object '
                        '0x5A26BC, then synchronized query 0x16F41C(index, out)',
            '0x16f41c': 'query: validates via 0x25BFB8, fills contexts (0x25CAEC -> 0x50F52C, '
                        '0x25C020 -> 0x50F420), reads halfword command parameter at '
                        '0x50F420+0xD2+2*index, result from context A fields +5/+0x10',
            'consumers': 'the lens cluster now has an identified consumer layer (status API), '
                         'but the full path from UI keys to the 33 transaction callers is '
                         'still open',
        },
        'literal_command_functions': {
            '0x2608a8': 'gate, send 0xFF, wait (1000 pool 0x2609D4), send 0x50, close',
            '0x260c6c': 'gate, send 0x70, read port 0x25E08C, status bit0 -> 0x1B00007 or 0',
            '0x25d3ac': 'probe 0x25D13C(0x90)/0x25D194 then send 0x70, read port, status bit7',
            '0x25f6a4': 'parameter record writer: flag bit0xA of context A clear -> gate, send '
                        '0x50, sender 0x25CB54, wait 1000, write a 16-byte record via 0x25F31C, '
                        'send 0x00; bit0xA set -> variants 0x25F4EC / 0x25F5C8 (multi-record); '
                        'called by the cmd8 wrapper 0x25C268 (prepare), the record writer '
                        '0x25C1F0 and 30 more sites',
            '0x2606b4': 'send 0x80, sender, 512-byte block data phase (0x260624/0x260678), '
                        '0x10 tail, ready wait',
        },
        'iris_anchors': {
            'diagnostic_panel_0x2c5100': 'prints "Iris status: Big/Small" (payload1 strings '
                                          '0x406E89/0x406E9A, pointer words 0x2C51A8/0x2C51AC) '
                                          'driven by a state getter [r14] called with indices '
                                          '8/9/0xA and draw API 0x1564A8',
            'liveview_overlay_table_0x323ee0': '12 format pointers, last is '
                                               '"Iris : %d (0:Big 1:Small)" 0x41DBAC',
            'capture_param_dump_0x1dc4xx': '"ucIrisIndex : %d" pointer word 0x1DC42C in the '
                                           'capture parameter field dump',
            'ae_block_0x1236xx': 'the AE/flash block 0x1236BC..0x125xxx of Main references the '
                                 'payload1 AE log strings (pointer tables 0x123688..0x12480C), '
                                 'including "Change Iris from MAX: %d  To MIN: %d" (payload1 '
                                 '0x3860EE/0x38612C, pointer words 0x124F64/0x124F6C) and the '
                                 'FE_Para.txt / FlashColorModify.txt fixtures',
        },
        'caller_census': census,
        'byte_verified': {
            'jump_table_0x30000c': JUMP_TABLE_30000C.hex(' '),
            'literals': {he(a): hex(v) for a, v in LITERALS.items()},
            'overlay_table': [hex(w) for w in tbl_words],
            'iris_strings_payload1': {hex(va): t for va, t in IRIS_STRINGS_P1.items()},
        },
        'windows_verified': ['0x30183c', '0x2fffcc', '0x16f41c', '0x25caec', '0x25c020',
                             '0x2608a8', '0x260c6c', '0x25d3ac', '0x25f6a4', '0x2606b4',
                             '0x2c5100', '0x2ff88c'],
        'limits': [
            'static only: no MMIO, lens MCU or camera hardware accessed; no firmware executed',
            'the RAM contexts 0x50F420/0x50F52C/0x50F514 are runtime-filled; their content and '
            'the physical meaning of the halfword command parameters are not determinable '
            'statically',
            'the iris transport among the 33 transaction callers is STILL not pinpointed: '
            '0x25F6A4 is decoded as a parameter-record writer (send 0x50 + sender + 16-byte '
            'record via 0x25F31C + 0x00 tail), the natural carrier for lens parameters, but '
            'which caller feeds the iris record is not anchored; 0x29DDD4 (0x60/0xD0) is the '
            'movement primitive that writes the position halfword directly on port 0x0FF05000 '
            'via 0x25E078',
            'the 0x2FFFCC field struct 0x3548D8 and the RAM object 0x5A26BC are identified by '
            'pool literals only; their writers are not traced here',
            'caller census is over the linear GNU listing (candidate classification); computed '
            'dispatch entries (0x2FFFCC via pointer, band entries 0x2FF88C etc.) have no direct '
            'bl callers in the linear listing',
            'muludw timing arithmetic is not modelled (known codebase caveat); helper 0x2E5658 '
            'not decoded; V1.1 analysed vs V1.0 camera',
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
    for k, v in census.items():
        print(f'{k}: {len(v)} callers')


if __name__ == '__main__':
    main()
