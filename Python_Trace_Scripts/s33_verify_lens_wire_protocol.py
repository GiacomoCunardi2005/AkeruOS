#!/usr/bin/env python3
"""Static verification of the lens-MCU wire protocol over port 0x0FF05000.

Decodes the byte-level dialogue layers left open by the previous lens/iris
sessions (wire format and callers):
- the GNU millicode thunks 0x334124/0x334128/0x33418c/0x3341a4 (push/pop r13-r16),
  which previous linear readings mistook for a "descriptor conversion" call;
- the command sender 0x25CB54 (descriptor bytes desc[0]/desc[1]/word desc[2],
  flags from RAM context 0x50F514+0x1a, raw port writes through 0x25E078);
- the transaction 0x25F338(buf512, buf16, desc) with context 0x50F52C,
  0x00 prefix, optional 0x30 suffix, ready-wait, 0xFF attention retry and
  the data phase (512-byte blocks via 0x25F2B8 + 16-byte reads via 0x25F31C);
- the literal command-byte dictionary sent through 0x25CB3C
  (immediate in the delay slot of each bl.d);
- the direct-send variant 0x29DDD4 (0x60, lo/hi(r57), [desc0], 0xD0);
- the port gates 0x25DEAC/0x25DEE8 (bit4 of 0x0FEF03A8, bit6 of 0x0FF04034)
  and the port strobes 0x25DF24/4C/74/9C (bits 8/9 of 0x0FF04020);
- the response-frame validator 0x25CBF0 (markers 0x55/0xAA, type byte at [5]).

Read-only: firmware, blocks and tools are never modified. Linear GNU listings
are candidate decodings; every asserted window is re-disassembled aligned at a
call-verified entry, and every literal asserted here is re-read from the raw
payload bytes.
"""
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
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Wire_Protocol'

# Verified entries (Main = block0, base 0x0AD800).
W_SENDER = (0x25CB54, 0x25CBB8)          # command sender (raw port writes)
W_TRANSACTION = (0x25F338, 0x25F3F2)     # descriptor transaction
W_VARIANT = (0x29DDD4, 0x29DE80)         # direct-send variant (0x60/0xD0)
W_GATE_CLEAR = (0x25DEAC, 0x25DEE8)      # clear port gates
W_GATE_SET = (0x25DEE8, 0x25DF24)        # set port gates
W_STROBE_SET9 = (0x25DF24, 0x25DF4C)     # 0x0FF04020: set bit9, clear bit8
W_STROBE_CLEAR = (0x25DF4C, 0x25DF74)    # 0x0FF04020: clear bits 8/9
W_STROBE_SET8 = (0x25DF74, 0x25DF9C)     # 0x0FF04020: set bit8
W_PORT_WRITE = (0x25E064, 0x25E078)      # halfword write to 0x0FF05000
W_BLOCK_READ = (0x25F2B8, 0x25F31C)      # two 256-byte reads + position log
W_READ16 = (0x25F31C, 0x25F338)         # 16-byte read
W_VALIDATOR = (0x25CBF0, 0x25CC48)       # response-frame validator
W_CTX_SLOT = (0x25CAEC, 0x25CB0C)        # [sp] = 0x50F52C context setter
W_READY_WAIT = (0x25D0D0, 0x25D100)      # ready poll with 1e6 bound

# Literal words re-read from raw payload bytes (objdump pcl annotations are
# unscaled: literal = (PC & ~3) + u6; verified against the raw words).
LITERALS = {
    0x25CEC8: 0x50F514,   # sender context A (flags +0x1a)
    0x25CECC: 0x25E078,   # raw port write used by the sender
    0x25CEC4: 0x50F52C,   # transaction context B (flags +2, count +0x10)
    0x25F694: 0x50F514,   # block read: position log base 1
    0x25F698: 0x50F520,   # block read: position log base 2
    0x25DEB8: 0x0FEF03A8, # gate clear/set: peripheral register
    0x25DED0: 0x0FF04034, # gate clear/set: lens-port register
    0x25DF30: 0x0FF04020, # strobe register
    0x25DF58: 0x0FF04020,
    0x25DF80: 0x0FF04020,
    0x25DFA8: 0x0FF04020,
    0x25E06C: 0x0FF05000, # data port (write variant 1)
    0x25E080: 0x0FF05000, # data port (write variant 2)
    0x29DE78: 0x00061A80, # variant wait bound: 400000
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
    p0 = payloads[0]
    assert base0 == 0x0AD800

    # Literal words verified against raw payload bytes.
    for addr, value in LITERALS.items():
        got = struct.unpack_from('<I', p0, addr - base0)[0]
        assert got == value, (hex(addr), hex(got), hex(value))

    windows = {}
    for name, (lo, hi) in [
        ('sender_25CB54', W_SENDER), ('transaction_25F338', W_TRANSACTION),
        ('variant_29DDD4', W_VARIANT), ('gate_clear_25DEAC', W_GATE_CLEAR),
        ('gate_set_25DEE8', W_GATE_SET), ('strobe_set9_25DF24', W_STROBE_SET9),
        ('strobe_clear_25DF4C', W_STROBE_CLEAR), ('strobe_set8_25DF74', W_STROBE_SET8),
        ('port_write_25E064', W_PORT_WRITE), ('block_read_25F2B8', W_BLOCK_READ),
        ('read16_25F31C', W_READ16), ('validator_25CBF0', W_VALIDATOR),
        ('ctx_slot_25CAEC', W_CTX_SLOT), ('ready_wait_25D0D0', W_READY_WAIT),
    ]:
        windows[name] = aligned_window(p0, base0, lo, hi)
        assert windows[name].strip(), name
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))

    def w(name):
        return windows[name]

    # Sender 0x25CB54: millicode prologue (push r13-r16), descriptor bytes,
    # context A flags, raw port writes through r14 = 0x25E078.
    t = w('sender_25CB54')
    assert re.search(r'\tbl\t\d+\t;0x334128\b', t), 'millicode prologue missing'
    assert re.search(r'\tld_s\tr15,\[pcl,0x36c\]\t;0x25cec8\b', t), 'ctx A literal missing'
    assert re.search(r'\tld_s\tr14,\[pcl,0x35c\]\t;0x25cecc\b', t), 'port-write literal missing'
    assert re.search(r'\tldb_s\tr1,\[r0,0\]', t), 'desc byte0 delay load missing'
    assert re.search(r'\tldw_s\tr0,\[r13,0x2\]', t), 'desc word2 missing'
    assert re.search(r'\tldb_s\tr0,\[r13,0x1\]', t), 'desc byte1 missing'
    assert re.search(r'\tldw_s\tr0,\[r15,0x1a\]', t), 'ctx A flags missing'
    assert re.search(r'\tbtst_s\tr0,0xa\b', t) and re.search(r'\tbtst_s\tr0,0x8\b', t)
    assert len(re.findall(r'\tjl_s\.d\t\[r14\]', t)) == 5, 'raw write calls missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25df74\b', t), 'strobe set8 missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25df9c\b', t), 'strobe clear missing'

    # Transaction 0x25F338: ctx slot, 0x00 prefix, sender call with arg2,
    # optional 0x30, ready wait, attention retry, 512/16-byte data phase.
    t = w('transaction_25F338')
    assert re.search(r'\tbl\.d\t-?\d+\t;0x25caec\b', t), 'ctx slot helper missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25deac\b', t), 'gate clear missing'
    assert re.search(r'\tbl\.d\t-?\d+\t;0x25cb3c\b', t), 'byte send missing'
    assert re.search(r'\tbl\.d\t-?\d+\t;0x25cb54\b', t), 'sender call missing'
    assert re.search(r'\tmov_s\tr0,r14\b', t), 'sender arg = transaction arg2 missing'
    assert re.search(r'\tldw_s\tr0,\[r0,0x2\]', t) and re.search(r'\tbtst_s\tr0,0xa\b', t)
    assert re.search(r'\tmov_s\tr0,0x30\b', t), '0x30 suffix missing'
    assert re.search(r'\tmov\tr0,1000\b', t), 'wait arg missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25d0d0\b', t), 'ready wait missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25cb0c\b', t), 'attention retry missing'
    assert re.search(r'\tldb_s\tr0,\[r14,0\]', t) and re.search(r'\tldw_s\tr1,\[r14,0x2\]', t)
    assert t.count('asl\tr0,r14,0x9') >= 1, '512-byte stride missing'
    assert t.count('asl_s\tr0,r13,0x4') >= 1, '16-byte stride missing'
    assert re.search(r'\tbl_s\t-?\d+\t;0x25f2b8\b', t) or '0x25f2b8' in t
    assert re.search(r'\tbl_s\t-?\d+\t;0x25f31c\b', t) or '0x25f31c' in t
    assert re.search(r'\tldb_s\tr0,\[r0,0x10\]', t), 'ctx B block count missing'

    # Variant 0x29DDD4: 0x60 prefix, lo/hi(r57) raw writes, optional desc[0],
    # 0xD0 suffix, 400000-bound wait, 0xFF attention on failure.
    t = w('variant_29DDD4')
    assert re.search(r'\tbl\t\d+\t;0x334128\b', t), 'millicode prologue missing'
    assert re.search(r'\tmov_s\tr0,0x60\b', t), '0x60 prefix missing'
    assert re.search(r'\tmov\tr16,r57\b', t), 'r57 lo capture missing'
    assert re.search(r'\textw\tr14,r57\b', t), 'r57 hi capture missing'
    assert re.search(r'\tbl\.d\t-?\d+\t;0x25e078\b', t), 'raw port write missing'
    assert re.search(r'\tldb_s\tr2,\[r13,0\]', t), 'desc byte0 missing'
    assert re.search(r'\tldw_s\tr0,\[r13,0x2\]', t), 'desc word2 missing'
    assert re.search(r'\tldw_s\tr0,\[r1,0x6\]', t), 'ctx B timing field missing'
    assert re.search(r'\tldb_s\tr1,\[r1,0x5\]', t), 'ctx B timing byte missing'
    assert re.search(r'\tmov_s\tr0,0xd0\b', t), '0xD0 suffix missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25d0d0\b', t), 'ready wait missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25cb0c\b', t), 'attention retry missing'
    assert re.search(r'\tbl\t-?\d+\t;0x25dee8\b', t), 'gate set missing'

    # Port gates and strobes.
    t = w('gate_clear_25DEAC')
    assert re.search(r'\tld_s\tr1,\[pcl,0x8\]\t;0x25deb8\b', t)
    assert re.search(r'\tld_s\tr1,\[pcl,0x8\]\t;0x25ded0\b', t)
    assert t.count('bclr\tr10,r10,r0') == 2, 'gate clears missing'
    t = w('gate_set_25DEE8')
    assert t.count('bset\tr10,r10,r0') >= 1, 'gate set missing'
    for name, bit in [('strobe_set9_25DF24', '0x9'), ('strobe_set8_25DF74', '0x8')]:
        assert re.search(rf'\tbset_s\tr0,r0,{bit}\b', w(name)), (name, 'strobe set missing')
        assert re.search(r'\tand\tr0,r0,-769\b', w(name)), (name, 'strobe mask missing')
    for name in ('strobe_clear_25DF4C',):
        assert re.search(r'\tand\tr0,r0,-769\b', w(name)), (name, 'strobe mask missing')
        assert not re.search(r'\tbset_s\b', w(name)), (name, 'unexpected set')
    t = w('port_write_25E064')
    assert re.search(r'\tld_s\tr1,\[pcl,0x8\]\t;0x25e06c\b', t), 'port literal missing'

    # Block read: two 256-byte loops, position pack into 0x50F514+2*idx and
    # 0x50F520+2*idx via the 3-byte pack 0x25CBBC.
    t = w('block_read_25F2B8')
    assert t.count('mov\tr14,256') == 2, 'two 256-byte loops missing'
    assert t.count('stb.ab\tr0,[r13,1]') == 2
    assert re.search(r'\tld_s\tr12,\[pcl,0x3b0\]\t;0x25f694\b', t)
    assert re.search(r'\tld_s\tr12,\[pcl,0x38c\]\t;0x25f698\b', t)
    assert t.count('bl.d\t-10028\t;0x25cbbc') + t.count('bl.d\t-10064\t;0x25cbbc') == 2
    t = w('read16_25F31C')
    assert re.search(r'\tmov_s\tr14,0x10\b', t), '16-byte count missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25e08c\b', t), 'port read missing'

    # Response validator: length >= 7, type byte at [5] (0xF0 with 55/AA
    # markers at [1]/[2] and [6]/[7]; 255 accepted; 1..4 accepted; 0 rejected).
    t = w('validator_25CBF0')
    assert re.search(r'\tcmp_s\tr0,0x7\b', t), 'length check missing'
    assert re.search(r'\tldb\.aw\tr0,\[r13,5\]', t), 'type byte load missing'
    assert re.search(r'\tcmp\tr0,240\b', t), 'type 0xF0 check missing'
    assert re.search(r'\tcmp_s\tr0,0x55\b', t) and re.search(r'\tcmp\tr0,170\b', t), 'markers missing'

    # Context slot helper and ready wait.
    t = w('ctx_slot_25CAEC')
    assert re.search(r'\tld_s\tr1,\[pcl,0x3d8\]\t;0x25cec4\b', t), 'ctx B literal missing'
    assert re.search(r'\tst_s\tr1,\[r0,0\]', t), 'ctx slot store missing'
    t = w('ready_wait_25D0D0')
    assert re.search(r'\tcmp_s\tr13,0xf4240\b', t), 'timeout bound missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25e0b8\b', t), 'status poll missing'
    timeout_code = struct.unpack_from('<I', p0, 0x25D128 - base0)[0]
    assert timeout_code == 0x01B00003, hex(timeout_code)

    # Literal command-byte dictionary: immediate in the delay slot of every
    # bl.d -> 0x25CB3C, extracted from the full linear listing.
    listing = objdump_text(ROOT, block_dir, info[0], p0)
    bytewords = {}
    byte_re = re.compile(r'^\s*([0-9a-f]+):.*\tbl\.d\t[-0-9]+\t;0x25cb3c\s*$')
    mov_re = re.compile(r'^\s*([0-9a-f]+):.*\tmov_s\tr0,(0x[0-9a-f]+|\d+)\s*$')
    lines = listing.splitlines()
    addr_at = {}
    for i, ln in enumerate(lines):
        m = re.match(r'^\s*([0-9a-f]+):', ln)
        if m:
            addr_at.setdefault(int(m.group(1), 16), i)
    imm_sites = []
    reg_sites = []
    for i, ln in enumerate(lines):
        if byte_re.match(ln):
            pc = int(ln.split(':')[0].strip(), 16)
            j = addr_at.get(pc + 4)
            nxt = lines[j] if j is not None else ''
            m = re.search(r'\tmov_s\tr0,(0x[0-9a-f]+|\d+)\s*$', nxt)
            if m:
                imm_sites.append((pc, int(m.group(1), 0) & 0xFF))
            else:
                reg_sites.append((pc, nxt.strip()[:80]))
    found_bytes = sorted({b for _, b in imm_sites})
    assert found_bytes == [0x00, 0x10, 0x30, 0x50, 0x60, 0x70, 0x80, 0xD0, 0xFF], \
        [hex(b) for b in found_bytes]
    assert len(imm_sites) == 29, len(imm_sites)

    # Direct callers of the sender 0x25CB54 (descriptor pointer in r0).
    sender_callers = []
    for ln in lines:
        if re.search(r'\tbl\.d\t[-0-9]+\t;0x25cb54\s*$', ln):
            sender_callers.append(int(ln.split(':')[0].strip(), 16))
    assert sorted(sender_callers) == [
        0x25F35A, 0x25F448, 0x25F6CC, 0x2606DC, 0x2607DC, 0x260B1E, 0x260B9C], \
        [hex(c) for c in sender_callers]

    # Callers of the transaction 0x25F338 (inventory only here; the
    # classification of the 33 real sites is in the session report).
    trx_callers = []
    for ln in lines:
        if re.search(r'\tbl(\.d)?\t[-0-9]+\t;0x25f338\s*$', ln):
            trx_callers.append(int(ln.split(':')[0].strip(), 16))
    # 0x232B4A is a linear-decode false positive: a literal pool skipped by
    # the b_s at 0x232B42 (words 0x0036A3B0 / 0x0FF20054, re-read from bytes).
    assert 0x232B4A in trx_callers
    for addr, value in (0x232B44, 0x0036A3B0), (0x232B48, 0x0FF20054):
        got = struct.unpack_from('<I', p0, addr - base0)[0]
        assert got == value, (hex(addr), hex(got))
    real_trx_callers = [c for c in trx_callers if c != 0x232B4A]
    assert len(real_trx_callers) == 33, len(real_trx_callers)

    result = {
        'analysis': 'STATIC lens-MCU wire protocol: sender/transaction/variant decode '
                    'plus literal command-byte dictionary over port 0x0FF05000',
        'firmware_reference': 'Nikon S33 V1.1 (camera observed V1.0; offsets not portable without proof)',
        'wire_protocol': {
            'port': '0x0FF05000 halfword .di (write 0x25E064/0x25E078, read 0x25E08C); status bit7 of 0x0FF04024',
            'port_gates': '0x25DEAC clears bit4 of 0x0FEF03A8 and bit6 of 0x0FF04034; 0x25DEE8 sets them',
            'port_strobes': '0x25DF24 sets bit9 of 0x0FF04020 (bit8 cleared); 0x25DF74 sets bit8; '
                            '0x25DF4C/0x25DF9C clear bits 8/9 (mask -769)',
            'byte_send_0x25CB3C': 'strobes + write byte + strobe back (used for the literal command bytes)',
            'attention_0x25CB0C': '0xFF then ready poll up to 0xF4240 iterations',
            'command_sender_0x25CB54': 'descriptor {byte0, byte1, word2}; timing muludw with ctx A '
                                       '(0x50F514 +0x1d/+0x1e); wire = [00 if flag0xA of 0x50F514+0x1a] '
                                       '00 lo/hi(byte1 + r57 sign-extended 16-bit) [byte0 if flag8], '
                                       'raw writes through 0x25E078',
            'transaction_0x25F338': '(buf512, buf16, desc): gate clear; send 0x00; sender(desc); '
                                    'if flag0xA of 0x50F52C+2 send 0x30; ready-wait 0x25D0D0 '
                                    '(bound 0xF4240, timeout code 0x01B00003); on failure attention 0xFF '
                                    'and retry; data phase: count from 0x50F52C+0x10, 512-byte blocks '
                                    '(buf512 + idx*0x200) and 16-byte reads (buf16 + idx*0x10)',
            'variant_0x29DDD4': 'send 0x60; timing muludw with ctx B (0x50F52C +5/+6) on desc[0] and '
                                'desc[2]+r57; raw writes lo/hi(r57); [desc[0]] if flag8 of 0x50F52C+2; '
                                'send 0xD0; ready-wait (args 1000/0 passed but unused by the decoded '
                                'body; variant loads 400000 at 0x29DE78); 0xFF attention on failure',
            'literal_command_bytes': {
                'dictionary': [hex(b) for b in found_bytes],
                'sites': {he(pc): hex(b) for pc, b in imm_sites},
            },
            'sender_direct_callers': [he(c) for c in sorted(sender_callers)],
            'transaction_callers_count': len(real_trx_callers),
            'transaction_callers_note': 'linear listing shows 34 sites; 0x232B4A is a literal-pool '
                                         'false positive (words 0x0036A3B0/0x0FF20054 skipped by the '
                                         'b_s at 0x232B42); real callers = 33; classification in the '
                                         'session report (dominant statics: r1 = 0x50E940, '
                                         'r2 = 0x36B254 control descriptor, r0 = variable 512B base)',
            'response_validator_0x25CBF0': 'buffer [0] >= 7; type byte at [5]: 0xF0 requires '
                                           '[1]=0x55 [2]=0xAA [6]=0x55 [7]=0xAA; 255 accepted; '
                                           '1..4 accepted; 0 rejected',
            'context_structs': {'0x50F514': 'flags +0x1a, timing +0x1d/+0x1e, position log +2*idx',
                               '0x50F52C': 'flags +2, block count +0x10, timing +5/+6'},
            'r57': 'core register used as a live global (2261 mentions); set at runtime by init code '
                   '(e.g. mov r57,r0 at 0xB2EBA); static value unknown',
            'millicode_thunks': '0x334124/0x334128 push r13-r16; 0x33418c/0x3341a4 pop; '
                                'they are GCC runtime helpers, not lens functions',
        },
        'windows_verified': [hex(lo) for lo, _ in [
            W_SENDER, W_TRANSACTION, W_VARIANT, W_GATE_CLEAR, W_GATE_SET,
            W_STROBE_SET9, W_STROBE_CLEAR, W_STROBE_SET8, W_PORT_WRITE,
            W_BLOCK_READ, W_READ16, W_VALIDATOR, W_CTX_SLOT, W_READY_WAIT]],
        'literals_verified': {he(a): hex(v) for a, v in LITERALS.items()},
        'register_sites_with_computed_byte': {he(pc): s for pc, s in reg_sites},
        'limits': [
            'GNU listings are linear candidate decodings; only the 14 asserted windows are aligned at verified entries',
            'pcl annotations are unscaled ((PC & ~3) + u6); every asserted literal is re-read from raw payload bytes',
            'r57 runtime value, descriptor RAM contents (0x50E140/0x50E340) and the physical meaning of '
            'the gate/strobe bits are not determinable statically',
            '0x2E5658 helper called before several sends is not decoded (possible lock/claim)',
            'muludw timing arithmetic is not modelled (known muludw semantics caveat in this codebase)',
            'the 0x25D0D0 ready-wait ignores its r0/r1 arguments in the decoded body',
            'no MMIO, lens MCU or camera hardware was accessed; no firmware executed; no candidate install',
            'wire bytes are byte-verified immediates; their MCU-side semantics (opcodes) remain inference',
        ],
        'sources': {str(p): sha(p) for p in [Path(__file__), FIRMWARE,
                                             ROOT / 'S33-sections/TBM_blocks/manifest.json',
                                             ROOT / 'work/build-arc/binutils/objcopy',
                                             ROOT / 'work/build-arc/binutils/objdump']},
    }
    (out / 'verified_evidence.json').write_text(
        __import__('json').dumps(result, indent=2, ensure_ascii=False) + '\n')
    (EVIDENCE / 'latest.json').write_text(__import__('json').dumps(
        dict(evidence=str((out / 'verified_evidence.json').relative_to(ROOT)))) + '\n')
    print('PASS', out)
    print('literal wire bytes:', [hex(b) for b in found_bytes], len(imm_sites), 'immediate sites')
    print('sender callers:', [hex(c) for c in sorted(sender_callers)])
    print('transaction callers:', len(real_trx_callers), 'real (1 false positive excluded)')


if __name__ == '__main__':
    main()
