#!/usr/bin/env python3
"""Static verification of the callers of the lens command orchestrator module.

Answers the open point (b) of iteration 4 (MDs/S33_Vibe_Offline_Checkpoint.md):
before declaring the dead end, search for computed references (middle-endian
limm, LE pool words) and direct calls toward the orchestrators and the outer
boundary of the lens command subsystem.

Byte-verified results (see MDs/S33_Obiettivo_Chiamanti_Modulo_Orchestrazione.md):

1. CORRECTION of iteration 3: the REAL function entries of the orchestrators
   are 0x29E680, 0x29E8F0 and 0x29E9C4. Each starts with `sub_s sp,sp,0x18`
   followed by `push_s blink`; the addresses used by the previous negative
   census (0x29E682/0x29E8F2/0x29E9C6, +2) are the push_s blink INSIDE the
   prologue, so a bl census toward them could not find the real callers.
   0x29E738 is an INTERNAL multi-entry of 0x29E680 (after the template
   memcpys: st_s r14,[sp,8]; ctxA fill 0x25CAEC on [sp+8]; 0x25CFE4).

2. Direct-call census (bl/bl_s/bl.d/bln) of all 16 payloads toward the module
   range [0x29E600,0x29EA00) finds EXACTLY 10 sites in payload 0 and 1 site in
   payload 9:
   - 6 bln at 0x25E75E/0x25E7B2/0x25E7D2/0x25E85A/0x25E8AE/0x25E8CE toward the
     band entries 0x29E85C..0x29E9CC: the known ENTRY-ALIGNMENT ARTIFACTS
     (proven in s33_verify_lens_aux_mmio_accessors.py);
   - 0x29E99E bl_s -> 0x29E680: INTRA-module (inside the body of 0x29E8F0);
   - 0x29EC44 bl_s -> 0x29E680: INTRA-module (inside the band-entry module,
     it reloads 6 args from the frame and calls the main orchestrator);
   - 0x29F082 bl_s -> 0x29E9C4: INTRA-module wrapper 0x29EFC4 (memcpy of the
     22-byte record, bit0xA dispatch of ctxA[+2], error id 0x1B00001 through
     0x1593AC/0x1594A4, 8 args r0-r7 to the twin orchestrator);
   - 0x301E92 bl -> 0x29E8F0: **the FIRST EXTERNAL static caller** of an
     orchestrator, function 0x301E1C of the state-API layer.
   - payload 9 0xC9E1E6 bl -> 0x29E738 is a DATA COINCIDENCE: the aligned
     window decodes invalid mnemonics (movbi.f, bnj.d, nonsense branches), the
     region is resource data, not code.

3. The external caller 0x301E1C (byte-verified window): zero-initialises a
   22-byte record on its frame (memcpy from the zero area 0x354DE4, right
   after the strings "BootNANDBase.bin"/"BootNANDBase.dmp", pool 0x301EBC),
   calls 0x301EC0, then the state-API validators 0x3013A0, 0x30183C,
   (0x30026C | 0x30144C on arg0==1), 0x300D94, loads 7 args r0-r6 from the
   frame and calls the orchestrator 0x29E8F0, then 0x16F200 and 0x30188C.

4. Callers of 0x301E1C: EXACTLY 3 sites, all in payload 4 (the CCD_Tune_DVT
   tuning block): 0x7D470A (r0=1, r1=r16), 0x7D4734 (r0=r16, r1=1) and
   0x80FAAE (r0=0, r1=1) inside the dispatcher 0x80F9C8, which switches on
   r14 in [0x19,0x36) with a byte-offset jump table at 0x80FA0C
   (ldb.x/add1_s/j_s [r12]; add1_s scales the byte by 2, so the case target
   is 0x80FA0C + 2*byte). Opcode 0x33 (byte 0x4F) selects the case 0x80FAAA
   that calls 0x301E1C(0,1); the default 0x80FAC8 loads the shared error id
   0xFFFF0009 from pool 0x80FAF8. No other payload calls it.

5. Computed-reference census (the open point (b) of iteration 4):
   - Middle-endian limm byte patterns (bytes = pack('<HH', V>>16, V&0xFFFF))
     toward the orchestrator module [0x29E600,0x29F200) over all 16 payloads:
     only 2 coincidences inside DATA payloads, p11 0x1099F60 -> 0x29E680
     (right next to the ASCII string "1080p") and p9 0xD6ADD6 -> 0x29EF17
     (odd value, resource data). ZERO patterns in every code payload.
   - The cluster range [0x1EC000,0x1F0000) DOES contain byte patterns inside
     instruction encodings (39 in payload 0, 89 in payload 6, ...); every one
     is either odd (cannot be an ARC branch target) or does not render as a
     32-bit immediate in the linear GNU listing: a scan of the operand-position
     immediates of all 16 listings finds NO mov/add/sub/and/or with an
     immediate in the module, cluster or caller ranges, so none of them is a
     real limm load of a subsystem address.

6. LE word census: no halfword-aligned LE word equals 0x29E680, 0x29E8F0,
   0x29E9C4, 0x301E1C or 0x301EC0 in any of the 16 payloads (no function
   table entry); the only LE words inside the module range are 4 odd-value
   coincidences in payload 9 data (0x29E81D x2, 0x29E91D, 0x29E751), which
   cannot be branch targets.

7. The module also CALLS OUT with computed dispatch: the band-entry region
   loads 0x1ED11C from pool 0x29EB94 and jumps with jl_s.d [r15] (visible at
   0x29EAD0 etc.), so 0x1ED11C is a shared helper of the cluster used by the
   orchestrator module itself.

Conclusion: the lens command subsystem is NOT statically isolated. The
static route payload4(tuning) -> 0x301E1C(state-API layer) -> 0x29E8F0
(orchestrator) -> ctrl writers -> wire exists; the previous "no static
caller" negative was an off-by-two census artifact.

pcl notes: ld_s pool words resolve at (PC & ~3) + offset (unscaled);
ld.as at (PC & ~3) + s9*4 (project convention). Read-only: firmware,
blocks and tools are never modified.
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
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Module_Callers'

BASE0, END0 = 0x0AD800, 0x35BC00
BASE1 = 0x360800
BASE4 = 0x796800

ORCH_LO, ORCH_HI = 0x29E600, 0x29EA00
CLUSTER_LO, CLUSTER_HI = 0x1EC000, 0x1F0000
ENTRIES = (0x29E680, 0x29E8F0, 0x29E9C4)
CALLER = 0x301E1C
CALLER_SIBLING = 0x301EC0

# Expected direct-call sites (site, mnemonic, target) from the full objdump
# listings; the 6 bln are the known artifacts of the accessor family.
EXPECTED_ORCH_P0 = [
    (0x25E75E, 'bln', 0x29E85C), (0x25E7B2, 'bln', 0x29E8B0),
    (0x25E7D2, 'bln', 0x29E8D0), (0x25E85A, 'bln', 0x29E958),
    (0x25E8AE, 'bln', 0x29E9AC), (0x25E8CE, 'bln', 0x29E9CC),
    (0x29E99E, 'bl_s', 0x29E680),
    (0x29EC44, 'bl_s', 0x29E680),
    (0x29F082, 'bl_s', 0x29E9C4),
    (0x301E92, 'bl', 0x29E8F0),
]
EXPECTED_ORCH_P9 = [(0xC9E1E6, 'bl', 0x29E738)]  # data coincidence (see below)
EXPECTED_CALLER_P4 = [(0x7D470A, 'bl', 0x301E1C),
                      (0x7D4734, 'bl', 0x301E1C),
                      (0x80FAAE, 'bl', 0x301E1C)]

# Middle-endian byte coincidences toward the module range [0x29E600,0x29F200)
# (payload, site, value): both inside data payloads, none inside code.
EXPECTED_ME = [
    (9, 0xD6ADD6, 0x29EF17), (11, 0x1099F60, 0x29E680),
]
# Odd-value LE word coincidences inside the module range (payload 9 data).
EXPECTED_LE_ORCH_P9 = [(0xCF4026, 0x29E81D), (0xCF90D2, 0x29E91D),
                      (0xD0E32E, 0x29E81D), (0xE47838, 0x29E751)]

CALL_RE = re.compile(
    r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{4})(?:\s+[0-9a-f]{4})?\s+\t?'
    r'(bl|bl_s|bl\.d|bln)\t([-0-9]+)\t;0x([0-9a-f]+)$')

WINDOWS = [
    ('entry_29e680', 0, 0x29E680, 0x29E700),
    ('orch_template_29e700', 0, 0x29E700, 0x29E760),
    ('entry_29e8f0', 0, 0x29E8F0, 0x29E9D0),
    ('entry_29e9c4', 0, 0x29E9C4, 0x29EA04),
    ('caller_301e1c', 0, 0x301E1C, 0x301EC0),
    ('wrapper_29efc4', 0, 0x29EFC4, 0x29F098),
    ('p4_case_7d46f6', 4, 0x7D46F6, 0x7D4740),
    ('p4_dispatcher_80f9c8', 4, 0x80F9C8, 0x80FAC0),
    ('p9_artifact_c9e1c0', 9, 0xC9E1C0, 0xC9E200),
    ('p9_artifact_e12a80', 9, 0xE12A80, 0xE12AA0),
    ('p9_artifact_e640d0', 9, 0xE640D0, 0xE640F0),
    ('p12_artifact_1062dc8', 12, 0x1062DC8, 0x1062DE8),
]


def call_census(listing_text: str):
    out = []
    for line in listing_text.splitlines():
        m = CALL_RE.match(line)
        if m:
            out.append((int(m.group(1), 16), m.group(2), int(m.group(4), 16)))
    return out


def main() -> None:
    out = EVIDENCE / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())
    firmware = FIRMWARE.read_bytes()
    assert sha(FIRMWARE) == '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'
    blocks, payloads, block_dir = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    p0, p4 = bytes(payloads[0]), bytes(payloads[4])

    # --- 1. Real entries: sub_s prologue precedes the push_s blink. ---
    for entry in ENTRIES:
        assert entry >= BASE0 and entry < END0
    for entry, thunk in ((0x29E680, 0x33412C), (0x29E8F0, 0x334130),
                         (0x29E9C4, 0x334104)):
        w = aligned_window(p0, BASE0, entry, entry + 0x10)
        assert re.search(r'\tsub_s\tsp,sp,0x18\b', w), (hex(entry), 'sub_s missing')
        assert re.search(r'\tpush_s\tblink\b', w), (hex(entry), 'push_s missing')
        assert re.search(r'\tbl(?:\.d)?\t[-0-9]+\t;0x' + f'{thunk:x}' + r'\b', w), \
            (hex(entry), 'thunk missing')
        # the +2 address (previous census target) is INSIDE the prologue
        w2 = aligned_window(p0, BASE0, entry, entry + 0x6)
        assert 'push_s\tblink' in w2, (hex(entry), '+2 is not the push_s blink')

    # --- 2. Internal entry 0x29E738 (multi-entry, after the memcpys). ---
    t = aligned_window(p0, BASE0, 0x29E700, 0x29E760)
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x13a954\b', t), 'fixture call missing'
    assert re.search(r'\tmov\tr2,528\b', t), 'template len 528 missing'
    assert re.search(r'\tmov_s\tr2,0xf4\b', t), 'template len 244 missing'
    assert len(re.findall(r'\tbl\.d\t[-0-9]+\t;0x128c20\b', t)) == 2, 'memcpys missing'
    for pool in (0x29E760, 0x29E764, 0x29E768, 0x29E76C):
        assert re.search(r'\tld_s\tr\d+,\[pcl,0x[0-9a-f]+\]\t;0x'
                         + f'{pool:x}' + r'\b', t), (hex(pool), 'pool load missing')
    assert re.search(r'\tst_s\tr14,\[sp,0x8\]', t), 'internal entry store missing'
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x25caec\b', t), 'ctxA fill missing'
    assert re.search(r'\tbl\t[-0-9]+\t;0x25cfe4\b', t), '0x25cfe4 call missing'

    # --- 3. Orchestrator 0x29E8F0 body: record copy, dispatch, intra call. ---
    t = aligned_window(p0, BASE0, 0x29E8F0, 0x29E9D0)
    assert re.search(r'\tst_s\tr0,\[sp,0x28\]', t) and \
        re.search(r'\tst\tr5,\[sp,60\]', t), 'arg stores missing'
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x25caec\b', t), 'ctxA fill missing'
    assert re.search(r'\tadd_s\tr0,sp,0x4\b', t) and \
        re.search(r'\tadd_s\tr1,sp,0x28\b', t), 'memcpy args missing'
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x128c20\b', t), 'memcpy call missing'
    assert re.search(r'\tmov_s\tr2,0x16\b', t), 'record length 22 missing'
    assert re.search(r'\tldw_s\tr0,\[r0,0x2\]', t) and \
        re.search(r'\tbtst_s\tr0,0xa\b', t), 'bit0xA dispatch missing'
    assert re.search(r'\tbmsk\.f\t0,r0,0x2\b', t), 'halfword rounding missing'
    assert re.search(r'\tld_s\tr0,\[pcl,0x204\]\t;0x29eb84\b', t), 'error-id pool missing'
    assert struct.unpack_from('<I', p0, 0x29EB84 - BASE0)[0] == 0x1B00001
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x1593ac\b', t), 'error service missing'
    assert re.search(r'\tbl_s\t-796\t;0x29e680\b', t), 'INTRA call to 0x29E680 missing'
    assert re.search(r'\tadd_s\tsp,sp,0x1c\b', t), 'epilogue missing'

    # --- 4. Twin orchestrator 0x29E9C4 prologue (8 args via st.as mirror). ---
    t = aligned_window(p0, BASE0, 0x29E9C4, 0x29EA04)
    assert re.search(r'\tsub\tsp,sp,316\b', t), '316-byte frame missing'
    assert re.search(r'\tst\.as\tr1,\[sp,94\]', t) and \
        re.search(r'\tst\.as\tr3,\[sp,96\]', t), 'st.as arg mirror missing'
    assert re.search(r'\tmov_s\tr14,r6\b', t) and \
        re.search(r'\tmov_s\tr13,r7\b', t), 'r6/r7 capture missing'
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x25bfb8\b', t), 'guard call missing'

    # --- 5. External caller 0x301E1C (state-API layer). ---
    t = aligned_window(p0, BASE0, 0x301E1C, 0x301EC0)
    assert re.search(r'\tpush_s\tblink\b', t), 'prologue missing'
    assert re.search(r'\tmov_s\tr14,r0\b', t) and \
        re.search(r'\tmov_s\tr13,r1\b', t), 'arg capture missing'
    assert re.search(r'\tld_s\tr1,\[pcl,0x8c\]\t;0x301ebc\b', t), 'zero-area pool missing'
    assert struct.unpack_from('<I', p0, 0x301EBC - BASE0)[0] == 0x354DE4
    assert p0[0x354DE4 - BASE0:0x354DE4 - BASE0 + 22] == bytes(22), \
        'the 22-byte source must be the zero area'
    assert b'BootNANDBase.bin\x00' in p0[0x354DC0 - BASE0:0x354DE4 - BASE0], \
        'zero area must follow the BootNANDBase strings'
    assert re.search(r'\tmov_s\tr2,0x16\b', t), 'record len 22 missing'
    assert re.search(r'\tbl\t[-0-9]+\t;0x128c20\b', t), 'memcpy call missing'
    assert re.search(r'\tbl\t132\t;0x301ec0\b', t), 'sibling call missing'
    for call in (0x3013A0, 0x30183C, 0x30026C, 0x30144C, 0x300D94,
                 0x29E8F0, 0x16F200, 0x30188C):
        assert re.search(r'\tbl(?:\.d|_s)?\t[-0-9]+\t;0x' + f'{call:x}' + r'\b', t), \
            (hex(call), 'missing')
    assert re.search(r'\tcmp_s\tr14,0x1\b', t), 'arg0 switch missing'
    # 7 args r0-r6 loaded from the frame right before the orchestrator call
    for rx in (r'\tld\tr15,\[fp,-8\]', r'\tld\tr5,\[fp,-4\]',
               r'\tmov_s\tr6,r13\b', r'\tld\tr0,\[fp,-24\]',
               r'\tmov_s\tr4,r15\b', r'\tld\tr3,\[fp,-12\]'):
        assert re.search(rx, t), ('frame arg load', rx)

    # --- 6. Intra-module wrapper 0x29EFC4 -> 0x29E9C4. ---
    t = aligned_window(p0, BASE0, 0x29EFC4, 0x29F098)
    assert re.search(r'\tsub_s\tsp,sp,0x18\b', t) and \
        re.search(r'\tpush_s\tblink\b', t), 'wrapper prologue missing'
    assert re.search(r'\tmov_s\tr2,0x16\b', t), 'record len 22 missing'
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x128c20\b', t), 'memcpy call missing'
    assert re.search(r'\tbtst_s\tr0,0xa\b', t), 'bit0xA dispatch missing'
    assert re.search(r'\tld_s\tr0,\[pcl,0x44\]\t;0x29f09c\b', t), 'error-id pool missing'
    assert struct.unpack_from('<I', p0, 0x29F09C - BASE0)[0] == 0x1B00001
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0x1593ac\b', t) and \
        re.search(r'\tbl\.d\t[-0-9]+\t;0x1594a4\b', t), 'error services missing'
    assert re.search(r'\tmov\tr7,r16\b', t), 'r16 -> r7 arg missing'
    assert re.search(r'\tbl_s\t-1724\t;0x29e9c4\b', t), 'call to twin missing'

    # --- 7. Band-entry region: computed call out to 0x1ED11C via pool. ---
    t = aligned_window(p0, BASE0, 0x29EAC4, 0x29EAD4)
    assert re.search(r'\tld_s\tr15,\[pcl,0xd0\]\t;0x29eb94\b', t), 'helper pool missing'
    assert struct.unpack_from('<I', p0, 0x29EB94 - BASE0)[0] == 0x1ED11C
    assert re.search(r'\tjl_s\.d\t\[r15\]', t), 'computed jump missing'

    # --- 8. Payload 4 call sites of 0x301E1C. ---
    t = aligned_window(p4, BASE4, 0x7D46F6, 0x7D4740)
    assert re.search(r'\tbl\.d\t[-0-9]+\t;0xcda24\b', t), 'tuning service missing'
    assert re.search(r'\tmov\tr18,0x1\b', t), 'r18 store missing'
    assert re.search(r'\tmov_s\tr0,0x1\b', t) and \
        re.search(r'\tmov_s\tr1,r16\b', t), 'first call args missing'
    assert len(re.findall(r'\tbl\t[-0-9]+\t;0x301e1c\b', t)) == 2, \
        'both 0x301E1C calls missing'
    assert re.search(r'\tstb\tr16,\[r1,8\]', t), 'stb store missing'

    t = aligned_window(p4, BASE4, 0x80F9C8, 0x80FAC0)
    assert re.search(r'\tpush_s\tblink\b', t) and \
        re.search(r'\tst\.aw\tfp,\[sp,-4\]', t), 'dispatcher prologue missing'
    for call in (0x12845C, 0x15A5C8, 0x1453F4, 0x1490FC, 0x2FFF0C,
                 0x12A794, 0xC76FC, 0x301E1C):
        assert re.search(r'\tbl(?:\.d)?\t[-0-9]+\t;0x' + f'{call:x}' + r'\b', t), \
            (hex(call), 'missing')
    assert re.search(r'\tsub2\tr0,r14,0x19\b', t) and \
        re.search(r'\tcmp_s\tr0,0x1d\b', t) and re.search(r'\tbhi\t[-0-9]+\t;0x80fac8\b', t), \
        'opcode range check missing'
    assert re.search(r'\tadd\tr12,pcl,0xc\t;0x80fa0c\b', t), 'jump table base missing'
    assert re.search(r'\tldb\.x\tr0,\[r12,r0\]', t) and \
        re.search(r'\tadd1_s\tr12,r12,r0\b', t) and \
        re.search(r'\tj_s\t\[r12\]', t), 'computed dispatch missing'
    assert re.search(r'\tmov_s\tr0,0\b', t) and re.search(r'\tmov_s\tr1,0x1\b', t), \
        '0x301E1C(0,1) args missing'

    # --- 8b. Opcode -> case mapping: add1_s scales the byte offset by 2
    # (r12 = 0x80FA0C + 2*byte), so opcode 0x33 (byte 0x4F) selects the case
    # 0x80FAAA that calls 0x301E1C(0,1); the default 0x80FAC8 loads the
    # shared error id 0xFFFF0009 from pool 0x80FAF8. ---
    table = p4[0x80FA0C - BASE4:0x80FA0C - BASE4 + 29]
    assert table[0] == 0x0F and table[1] == 0x18, 'table head mismatch'
    assert table[0x33 - 0x19] == 0x4F, 'opcode 0x33 must select the 0x4F case'
    assert 0x80FA0C + 2 * table[0x33 - 0x19] == 0x80FAAA
    t = aligned_window(p4, BASE4, 0x80FAAA, 0x80FAC8)
    assert re.search(r'\tmov_s\tr0,0\b', t) and \
        re.search(r'\tmov_s\tr1,0x1\b', t), 'case 0x80FAAA args missing'
    assert re.search(r'\tbl\t[-0-9]+\t;0x301e1c\b', t), 'case 0x80FAAA call missing'
    assert re.search(r'\tmov_s\tr13,r0\b', t) and \
        re.search(r'\tb_s\t[-0-9]+\t;0x80faca\b', t), 'case tail missing'
    assert struct.unpack_from('<I', p4, 0x80FAF8 - BASE4)[0] == 0xFFFF0009, \
        'default error id missing'

    # --- 9. Data-coincidence classifications. ---
    t = aligned_window(bytes(payloads[9]), info[9]['load_address_candidate'],
                       0xC9E1C0, 0xC9E200)
    assert re.search(r'\tbl\t-10484396\t;0x29e738\b', t), 'artifact bl decode missing'
    assert re.search(r'\tmovbi\.f\b', t) and re.search(r'\.word\t', t), \
        'payload 9 region must decode as data, not code'
    t = aligned_window(bytes(payloads[9]), info[9]['load_address_candidate'],
                       0xE12A80, 0xE12AA0)
    assert '.word\t0x3fdca2ff' in t, 'p9 0xE12A8E window must be data garbage'
    t = aligned_window(bytes(payloads[9]), info[9]['load_address_candidate'],
                       0xE640D0, 0xE640F0)
    assert 'subsdw' in t, 'p9 0xE640DE window must be data garbage'
    t = aligned_window(bytes(payloads[12]), info[12]['load_address_candidate'],
                       0x1062DC8, 0x1062DE8)
    assert 'bnv\t' in t, 'p12 0x1062DD4 window must be data garbage'
    p11 = bytes(payloads[11])
    assert p11[0x1099F60 - info[11]['load_address_candidate']:
               0x1099F60 - info[11]['load_address_candidate'] + 4] == \
        struct.pack('<HH', 0x0029, 0xE680), 'p11 ME bytes missing'
    seg = p11[0x1099F50 - info[11]['load_address_candidate']:
              0x1099F78 - info[11]['load_address_candidate']]
    assert b'1080p' in seg, 'p11 hit must sit in a string data region'

    # --- 10. Censuses over the 16 payload listings. ---
    orch_census, caller_census, listings = {}, {}, {}
    for idx in sorted(payloads):
        listing = objdump_text(ROOT, block_dir, info[idx], payloads[idx])
        listings[idx] = listing
        calls = call_census(listing)
        orch_census[idx] = [(s, mn, tg) for s, mn, tg in calls
                            if ORCH_LO <= tg < ORCH_HI]
        caller_census[idx] = [(s, mn, tg) for s, mn, tg in calls if tg == CALLER]
    assert orch_census[0] == EXPECTED_ORCH_P0, orch_census[0]
    assert orch_census[9] == EXPECTED_ORCH_P9, orch_census[9]
    for idx in sorted(payloads):
        if idx not in (0, 9):
            assert orch_census[idx] == [], (idx, orch_census[idx])
    assert caller_census[4] == EXPECTED_CALLER_P4, caller_census[4]
    for idx in sorted(payloads):
        if idx != 4:
            assert caller_census[idx] == [], (idx, caller_census[idx])

    # --- 11. Middle-endian limm census + operand-immediate rendering scan. ---
    # Module range including the band entries and the wrapper 0x29EFC4.
    MOD_LO, MOD_HI_SCAN = 0x29E600, 0x29F200
    me_orch, me_cluster, me_caller = {}, {}, []
    for idx in sorted(payloads):
        p = bytes(payloads[idx])
        base = info[idx]['load_address_candidate']
        for off in range(0, len(p) - 3, 2):
            hw_hi, hw_lo = struct.unpack_from('<HH', p, off)
            v = (hw_hi << 16) | hw_lo
            if MOD_LO <= v < MOD_HI_SCAN:
                me_orch.setdefault(idx, []).append((base + off, v))
            if CLUSTER_LO <= v < CLUSTER_HI:
                me_cluster.setdefault(idx, []).append((base + off, v))
            if v == CALLER:
                me_caller.append((idx, base + off, v))
    # Module-range byte patterns exist ONLY as the two data coincidences.
    assert me_orch == {9: [(0xD6ADD6, 0x29EF17)], 11: [(0x1099F60, 0x29E680)]}, \
        {k: [(hex(a), hex(v)) for a, v in l] for k, l in me_orch.items()}
    assert 0x29EF17 & 1, 'the payload 9 hit is odd: cannot be an ARC target'
    assert me_caller == [], 'no limm may load the caller address'
    # Cluster-range byte patterns DO occur inside instruction encodings of
    # code payloads (39 in payload 0, 89 in payload 6, ...). None of them is
    # a real limm load: a scan of the operand-position immediates of all 16
    # linear GNU listings finds no instruction whose immediate falls in the
    # module, cluster or caller ranges.
    imm_line = re.compile(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{4})(?:\s+[0-9a-f]{4})?'
                          r'\s+\t([^\t]+)\t(.*)$')
    imm_violations = []
    for idx in sorted(payloads):
        for line in listings[idx].splitlines():
            m = imm_line.match(line)
            if not m or m.group(2).startswith('.word'):
                continue
            ops = m.group(3).split(';')[0]
            for tok in re.findall(r'(?<![\w.])0x[0-9a-f]+', ops):
                v = int(tok, 16)
                if MOD_LO <= v < MOD_HI_SCAN or CLUSTER_LO <= v < CLUSTER_HI \
                        or v == CALLER:
                    imm_violations.append((idx, line.strip()))
    assert imm_violations == [], imm_violations[:8]

    # --- 12. LE word census: no function-table entry for the subsystem. ---
    le_entries = {e: [] for e in (*ENTRIES, CALLER, CALLER_SIBLING)}
    le_orch = {}
    for idx in sorted(payloads):
        p = bytes(payloads[idx])
        base = info[idx]['load_address_candidate']
        for off in range(0, len(p) - 3, 2):
            v = struct.unpack_from('<I', p, off)[0]
            if v in le_entries:
                le_entries[v].append((idx, base + off))
            if ORCH_LO <= v < ORCH_HI:
                le_orch.setdefault(idx, []).append((base + off, v))
    for e, hits in le_entries.items():
        assert hits == [], (hex(e), hits)
    assert le_orch == {9: EXPECTED_LE_ORCH_P9}, le_orch
    for _, v in EXPECTED_LE_ORCH_P9:
        assert v & 1, 'odd values cannot be ARC branch targets'

    # --- Evidence. ---
    windows = {}
    for name, idx, lo, hi in WINDOWS:
        w = aligned_window(bytes(payloads[idx]), info[idx]['load_address_candidate'],
                           lo, hi)
        assert w.strip(), (name, hex(lo))
        windows[name] = w
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))

    result = {
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'firmware_sha256': sha(FIRMWARE),
        'correction': 'the orchestrator entries are 0x29E680/0x29E8F0/0x29E9C4 '
                      '(sub_s sp,sp,0x18 + push_s blink); the +2 addresses of the '
                      'iteration-3 negative census were the push_s blink inside the '
                      'prologue, so its bl census could not see the real callers',
        'external_static_route': {
            'payload4_tuning': 'dispatcher 0x80F9C8 (opcode r14 in [0x19,0x36), '
                               'byte-offset jump table at 0x80FA0C, add1_s '
                               'scales the byte by 2) and the tuning case block '
                               'at 0x7D46F6 call 0x301E1C',
            'state_api_layer': '0x301E1C zero-inits a 22-byte record from the zero '
                               'area 0x354DE4 (after the "BootNANDBase" strings), '
                               'validates through 0x3013A0/0x30183C/0x30026C/'
                               '0x30144C/0x300D94, then calls 0x29E8F0 with 7 args '
                               'r0-r6, then 0x16F200 and 0x30188C',
            'orchestrator': '0x29E8F0 copies the 22-byte record, dispatches on '
                            'bit0xA of ctxA[+2] and reaches the ctrl writers/wire',
        },
        'intra_module_callers': {
            '0x29e99e': 'bl_s -> 0x29E680 from inside the 0x29E8F0 body',
            '0x29ec44': 'bl_s -> 0x29E680 from the band-entry module (6 args reloaded)',
            '0x29f082': 'bl_s -> 0x29E9C4 from wrapper 0x29EFC4 (memcpy 22B, bit0xA, '
                        'error id 0x1B00001 via 0x1593AC/0x1594A4, r16 -> r7)',
            'computed_out': 'the band-entry region loads 0x1ED11C from pool 0x29EB94 '
                            'and jumps with jl_s.d [r15] (0x29EAD0)',
        },
        'artifact_rejections': {
            'bln_band_entries': 'the 6 bln of the accessor family are the known '
                                'entry-alignment artifacts (iteration 4)',
            'payload9_0xc9e1e6': 'bl -> 0x29E738 decodes inside resource data '
                                  '(movbi.f/.word nonsense), not code',
            'me_limm_coincidences': 'p9 0xE12A8E/0xE640DE, p11 0x1099F60 (next to '
                                    '"1080p"), p12 0x1062DD4 (bnv garbage): data '
                                    'coincidences, no computed jump loads any '
                                    'subsystem address as limm',
            'le_word_coincidences': 'only odd values in payload 9 data '
                                    '(0x29E81D x2, 0x29E91D, 0x29E751): cannot be '
                                    'branch targets; no LE word equals any entry',
        },
        'census': {
            'orch_range_calls_payload0': [[he(s), mn, he(tg)] for s, mn, tg in EXPECTED_ORCH_P0],
            'orch_range_calls_payload9': [[he(s), mn, he(tg)] for s, mn, tg in EXPECTED_ORCH_P9],
            'caller_0x301e1c_calls_payload4': [[he(s), mn, he(tg)] for s, mn, tg in EXPECTED_CALLER_P4],
            'dispatcher_opcode_selection': 'opcode 0x33 of dispatcher 0x80F9C8 '
                                           '(jump-table byte 0x4F, add1_s scale '
                                           'by 2) selects case 0x80FAAA, which '
                                           'calls 0x301E1C(0,1); default case '
                                           '0x80FAC8 loads error id 0xFFFF0009 '
                                           'from pool 0x80FAF8',
            'me_limm_hits': [[idx, he(a), he(v)]
                             for idx, lst in me_orch.items() for a, v in lst],
            'me_cluster_coincidences': {str(idx): len(lst)
                                       for idx, lst in me_cluster.items()},
            'operand_immediate_scan': 'no instruction of the 16 linear GNU '
                                      'listings has an operand-position '
                                      'immediate in the module [0x29E600,'
                                      '0x29F200), cluster [0x1EC000,'
                                      '0x1F0000) or caller (0x301E1C) ranges',
            'le_word_orch_range': [[idx, he(a), he(v)] for idx, lst in le_orch.items()
                                   for a, v in lst],
        },
        'windows_verified': [w[0] for w in WINDOWS],
        'limits': [
            'static only: no MMIO, lens MCU or camera hardware accessed; no firmware executed',
            'the census covers bl/bl_s/bl.d/bln of the linear GNU listings plus '
            'aligned windows for every accepted/rejected site; computed calls with '
            'runtime-computed targets (not from pools/limm) cannot be excluded',
            'payload 4 is the CCD_Tune_DVT tuning block of V1.1: whether its '
            'dispatcher 0x80F9C8 runs in the normal photographic path (and which '
            'opcode selects the 0x301E1C(0,1) handler) is still open',
            'the semantics of the 7 arguments of 0x29E8F0 and of the 22-byte record '
            'are not decoded: the mapping to zoom/focus/iris commands remains open',
            'the AE/iris block 0x1236BC is still not hooked to this route; no caller '
            'of 0x301E1C was found there',
            'jl [reg] sites whose register is computed at runtime are not censused; '
            'only pool/limm-sourced computed targets are excluded by sections 11-12',
            'V1.1 analysed vs V1.0 camera; NON_INSTALLARE',
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
    print('external route: payload4 -> 0x301E1C -> 0x29E8F0')
    print('census payload0 orch calls:', len(EXPECTED_ORCH_P0),
          '(6 artifacts, 3 intra, 1 external)')


if __name__ == '__main__':
    main()
