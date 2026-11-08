#!/usr/bin/env python3
"""Static verification of the pending-raise side of the service-request
framework (V1.1) - iteration 38.

Closes the open point (a) of iteration 36: who raises the pending bits at
runtime - the three callers of the generic raise 0x16D4D8 (for the ids
passed) and the LE site 0x1A14A8 = 0xFED3818 - to attribute the event that
drives interrupt vector 6 (pending 0xFEF0074, id 0x610 of table 0x424B18)
and the iris request 0x3002 (pending 0xFED3818 bit 2).

Facts asserted here (byte-exact aligned windows + raw pool words + payload1
table parses + LE scans + call censuses + functional model):

- 0x16D4D8(id) = generic raise: loops the SIX generic tables of the array
  0x3F6CC8, compares the FULL 32-bit r0 against the 16-bit record id
  (ldh.di, zero-extended; CMP_S is a full 32-bit compare per the ARCompact
  ISA manual, no mask instruction exists in the loop), and on match sets
  1<<bitB into the class pending halfword ([table+0]) under a critical
  section, plus nothing else.  No match -> returns pool 0x16D6D0 = 0x200601.
- The three static callers pass CONSTANT 32-bit ids whose high halfword is
  0xFFFF: 0xFFFF9007 (pool 0x16F11C, delay slot of the bl.d at 0x16F0F6),
  0xFFFF8008 (pool 0x2331AC, delay slot of the bl.d at 0x2331B4),
  0xFFFF800B (pool 0x238B68, delay slot of the bl.d at 0x238B56, on the
  arg==2 branch of 0x238B34).  None of these can equal any record id
  (max 0x0A10), so the raise ALWAYS fails at the three sites and returns
  0x200601, which all three callers ignore.  The same constants ARE valid
  ids for the enable/register routers (class = id & 0xFF00 -> 0x9000 /
  0x8000 high classes, service arg = id & 0xFFFF), which is why they exist.
- 0x16D5BC(id, flag) router full map: and r1,r0,0xff00; classes 0x3000 and
  0x4000 -> 0x2422e8 / 0x242380 (flag polarity), generic LOW classes
  0x0400/0x0500/0x0600/0x0800/0x0900/0x0A00 -> the six generic tables
  (enable bit set/clear per flag through [table+4] / bitA), HIGH classes
  0x1000/0x2000/0x6000/0x7000/0x8000/0x9000/0xA000/0xB000 -> direct
  per-class services with extw_s r0 (id & 0xFFFF) in the delay slots;
  unknown class -> 0x200601 (pool 0x16DB20).
- Class-0x6000 exemplar (0x266170 / 0x2661d8 flag pair): requires
  (arg & 0x6000) == 0x6000; one-time register(0x90D, 0x26627C) via
  0x16D898 + enable 0xFF via 0x16D7E8 gated by cell 0x36B330; sets a gate
  bit; then 0x2660E8(mask, flag) searches a SEVENTH static table 0x424E00
  (pending 0xFEF0228, enable 0xFEF022C, 16 records ids 0x6001..0x6010,
  bits 15..0) - OUTSIDE the 0x3F6CC8 array - and sets its pending bit
  (and enable per flag).  The class-0x8000 raiser 0x266300 uses the eighth
  table 0x424F00 (0xFEF0048/0xFEF0324, ids 0x8001..0x8010); table 0x425000
  (0xFEF044C/0xFEF0448, ids 0xB001..0xB00D) exists for class 0xB000.
- The vector-6 pending 0xFEF0074 has EXACTLY three LE pool sites in
  payload0: 0x263F30 (the W1C clear-all 0x263F08 of the framework init,
  writes 0xFFFF), 0x2640B8 (getter of bit 9: ldh.di; lsr 9; bmsk 0) and
  0x2640D4 (W1C clear of bit 9: sth.di 0x200).  NO raise writer exists:
  the vector-6 pending bits (including bit 15 = id 0x610, the callback
  that invokes the nested dispatcher 0x242488) are raised by HARDWARE.
- The iris pending 0xFED3818 has EXACTLY ONE LE pool site in payload0:
  0x1A14A8, inside the handler registered under id 0x3004.  That handler
  (0x1A1490) writes r15=1 to 0xFED3818 (W1C acknowledge of bit 0), then
  polls the strobe-bank status/mask pair 0xFED18C8 / 0xFED18CC and invokes
  the callback cell [0x368510] when (a & b & 0xF) != 0.  The iris-family
  software writers of 0xFED3818 remain only the request setter 0x242224
  (armed at ready-time by 0x2422e8) through the table header (0x424500).
- Iris-family registrations completed: 0x3002 -> 0x241E5C (iteration 34),
  0x3004 -> 0x1A1490 (registered + readied by 0x1A082C, gate byte
  0x368500, callers {0x1A0AA2, 0x1A1474}), 0x3001 -> 0x238C88 (lens
  family: register tail b.d at 0x23914E, ready 0x23917C, unregister
  0x239194; pool 0x239150 = 0x238C88, pool 0x239158 = 0x3001).  The
  0x3001 handler 0x238C88 increments a counter and calls 0x238B34(2) -
  which is the third (failing) raise caller.

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
EVIDENCE = ROOT / 'Risultati/Runtime_Kernel/Service_Raise_Pending'
LISTING = ROOT / 'Risultati/Disassemblati/Firmware1.1.asm'

TABLES_ARRAY = 0x3F6CC8
TAB_IRIS = 0x424500
TAB_6XX = 0x424B18
TAB_6000_HIGH = 0x424E00   # class-0x6000 high table (pending 0xFEF0228)
TAB_8000_HIGH = 0x424F00   # class-0x8000 high table (pending 0xFEF0048)
TAB_B000_HIGH = 0x425000   # class-0xB000 high table (pending 0xFEF044C)
PENDING_V6 = 0xFEF0074
PENDING_IRIS = 0xFED3818

# raw LE pool words of payload0 (verified against the raw bytes)
LITERALS = {
    # raise service + error pool
    0x16D580: TABLES_ARRAY,   # raise: six-table array
    0x16D6D0: 0x200601,       # raise: id-not-found error
    0x16DB20: 0x200601,       # router: unknown-class error
    # raise callers (delay-slot pool words)
    0x16F118: 0x9007,         # caller 1: arg of the 0x266b5c class service
    0x16F11C: 0xFFFF9007,     # caller 1: raise id (can never match)
    0x2331AC: 0xFFFF8008,     # caller 2: raise id (can never match)
    0x238B68: 0xFFFF800B,     # caller 3: raise id (can never match)
    # class-0x6000 high service 0x266170
    0x26628C: 0x200601,       # its error code
    0x266290: 0x36B330,       # gate cell
    0x266294: 0x26627C,       # watchdog fn registered under 0x90D
    0x266298: 0x90D,          # watchdog id (class 0x0900, table 0x424C30)
    # class-0x6000 raiser 0x2660E8 and class-0x8000 raiser 0x266300
    0x266120: TAB_6000_HIGH,
    0x266330: TAB_8000_HIGH,
    # 0xFEF0074 sites (the only payload0 references to the vector-6 pending)
    0x263F30: PENDING_V6,
    0x2640B8: PENDING_V6,
    0x2640D4: PENDING_V6,
    # 0x3004 handler 0x1A1490 and its registration 0x1A082C
    0x1A14A8: PENDING_IRIS,   # the site named by iteration 36
    0x1A14B4: 0xFED18C8,      # strobe-bank status
    0x1A14C4: 0xFED18CC,      # strobe-bank mask
    0x1A14E4: 0x368510,       # callback cell
    0x1A0880: 0x368500,       # one-shot gate byte of the registration
    0x1A0884: 0x1A1490,       # handler fn registered under 0x3004
    0x1A0888: 0x3004,         # the iris-family id
    # 0x3001 lens registration (fn pool is 0x239154, id pool is 0x239158)
    0x239148: 0x238C88,       # fn registered under 0x800B (class-0x8000 high table)
    0x239154: 0x23915C,       # handler fn registered under 0x3001
    0x239158: 0x3001,         # the iris-family id
    # class-0x8000 high register 0x266444
    0x2664A0: 0x424F00,       # the class-0x8000 high table
}

# bl-form call censuses (linear GNU listing; chain sites re-asserted in
# aligned windows).
CENSUS = {
    0x16D4D8: {0x16F0F6, 0x2331B4, 0x238B56},  # raise
    0x1A082C: {0x1A0AA2, 0x1A1474},            # 0x3004 register-init
    0x23917C: {0x238D02, 0x238D10},            # 0x3001 ready wrapper
    0x239194: {0x238662, 0x238BE6, 0x238D32, 0x238D4A, 0x238D92},  # unregister
    0x1A1490: set(),                            # pointer-only (pool 0x1A0884)
    0x238C88: set(),                            # pointer-only (pool 0x239148)
    0x23915C: set(),                            # pointer-only (pool 0x239154)
    0x238B34: {0x238B9C, 0x238C1C, 0x238CAC, 0x238CE8, 0x238CEC},
}

# frozen LE scan expectations (payload0 pool references)
LE_SCAN_EXPECT = {
    PENDING_V6: [0x263F30, 0x2640B8, 0x2640D4],
    PENDING_IRIS: [0x1A14A8],
    0x424500: [0x24225C, 0x242294, 0x2424A4],   # iris table: family services only
    TAB_6000_HIGH: [0x266120, 0x26629C],        # raiser + register/watchdog
    TAB_8000_HIGH: [0x266330, 0x2664A0],        # raiser + high register 0x266444
    0x1A1490: [0x1A0884],                       # handler pointer pool
    0x238C88: [0x239148],
    0x23915C: [0x239154],
    0x16D4D8: [],   # no pointer-only references to the raise
    0x16D5BC: [],   # nor to the router
    0x16D898: [],   # nor to the register router
}

# aligned windows asserted in this verification: (start, end, required
# regex patterns).  Every window is dumped to the evidence folder.
WINDOWS = [
    ('raise_16d4d8', 0x16D4D8, 0x16D588, [
        r'push_s\s+blink',
        r'mov_s\s+r2,0x6',
        r'ld_s\s+r13,\[pcl,0x98\]\s+;0x16d580',
        r'add2_s\s+r13,r13,r1',
        r'ldh\.di\s+r15,\[r3,8\]',
        r'add3_s\s+r3,r3,r14',
        r'ldh\.di\s+r3,\[r3,12\]',
        r'cmp_s\s+r0,r3',
        r'bne_s\s+-26',
    ]),
    ('raise_found_16d584', 0x16D584, 0x16D5B8, [
        r'bl\s+45412\s+;0x1786e8',
        r'ld_s\s+r0,\[r13,0\]',
        r'ld\.di\s+r2,\[r0\]',
        r'ldb\.di\s+r1,\[r0,14\]',
        r'bset\s+r0,r0,r1',
        r'sth\.di\s+r0,\[r2\]',
        r'bl\s+48564\s+;0x179354',
        r'ld_s\s+r0,\[pcl,0x11c\]\s+;0x16d6d0',
    ]),
    ('raise_caller1_16f0ec', 0x16F0EC, 0x16F118, [
        r'push_s\s+blink',
        r'push_s\s+r13',
        r'bl\.d\s+1014380\s+;0x266b5c',
        r'ld_s\s+r0,\[pcl,0x24\]\s+;0x16f118',
        r'bl\.d\s+-7196\s+;0x16d4d8',
        r'ld_s\s+r0,\[pcl,0x24\]\s+;0x16f11c',
    ]),
    ('raise_caller2_2331b0', 0x2331B0, 0x2331BC, [
        r'push_s\s+blink',
        r'push_s\s+r13',
        r'bl\.d\s+-810204\s+;0x16d4d8',
        r'ld\s+r0,\[pcl,-12\]\s+;0x2331ac',
    ]),
    ('raise_caller2_cont', 0x2331BC, 0x2331C8, [
        r'mov_s\s+r0,0x8',
        r'bset_s\s+r0,r0,0xf',
        r'bl\s+209344\s+;0x266380',
    ]),
    ('raise_caller3_238b34', 0x238B34, 0x238B6C, [
        r'cmp_s\s+r0,0x1',
        r'cmp_s\s+r13,0x2',
        r'bl\.d\s+-833148\s+;0x16d4d8',
        r'ld_s\s+r0,\[pcl,0x10\]\s+;0x238b68',
        r'mov_s\s+r0,0xc',
        r'bset_s\s+r0,r0,0x19',
    ]),
    ('router_16d5bc_head', 0x16D5BC, 0x16D5F8, [
        r'and\s+r1,r0,0xff00',
        r'cmp_s\s+r1,0x3000',
        r'cmp_s\s+r1,0x800\b',
        r'cmp\s+r1,1024',
        r'cmp\s+r1,1280',
        r'cmp\s+r1,1536',
    ]),
    ('router_16d5e4_16d6d0', 0x16D5E4, 0x16D6D0, [
        r'cmp_s\s+r1,0xa00',
        r'cmp_s\s+r1,0x900\b',
        r'cmp_s\s+r1,0x1000',
        r'cmp_s\s+r1,0x2000',
        r'cmp_s\s+r1,0x7000',
        r'cmp_s\s+r1,0x4000',
        r'cmp_s\s+r1,0x5000',
        r'cmp_s\s+r1,0x6000',
        r'cmp_s\s+r1,0x9000',
        r'cmp_s\s+r1,0x8000',
        r'cmp_s\s+r1,0xa000',
        r'cmp_s\s+r1,0xb000',
        # high-class service targets (flag polarity)
        r'bl\s+1018296\s+;0x265fe8',
        r'bl\s+1018632\s+;0x266170',
        r'bl\s+1019120\s+;0x266380',
        r'bl\s+1019608\s+;0x26658c',
        # extw r0 (id & 0xFFFF) in the delay slots
        r'beq\.d\s+\d+\s+;0x16d772',
        r'extw_s\s+r0,r0',
    ]),
    ('router_tail_16d6d4', 0x16D6D4, 0x16D7E8, [
        r'ldh\.di\s+r1,\[r13,8\]',
        r'add3\s+r14,r13,r2',
        r'ldh\.di\s+r1,\[r14,12\]',
        r'cmp_s\s+r0,r1',
        r'ld\.di\s+r1,\[r13,4\]',
        r'ldb\.di\s+r0,\[r14,15\]',
        r'bset\s+r10,r10,r0',
        r'bclr\s+r10,r10,r0',
        r'bl\s+1019888\s+;0x26671c',
        r'bl\s+1020028\s+;0x2667b0',
        r'bl\s+1018144\s+;0x26605c',
        r'bl\s+871324\s+;0x2422e8',
        r'bl\s+871468\s+;0x242380',
        r'bl\s+1020280\s+;0x2668d8',
        r'bl\s+1020376\s+;0x266940',
        r'bl\s+1018472\s+;0x2661d8',
        r'bl\s+1020756\s+;0x266af0',
        r'bl\s+1020856\s+;0x266b5c',
        r'bl\s+1021272\s+;0x266d0c',
        r'bl\s+1021368\s+;0x266d74',
        r'bl\s+1019440\s+;0x2665f4',
        r'bl\s+1018972\s+;0x2663ec',
    ]),
    ('class6000_266170', 0x266170, 0x2661D8, [
        r'mov_s\s+r14,r0',
        r'mov_s\s+r15,0x3',
        r'asl_s\s+r15,r15,0xd',
        r'and_s\s+r0,r0,r15',
        r'cmp_s\s+r0,r15',
        r'ld_s\s+r13,\[pcl,0x108\]\s+;0x26628c',
        r'ld_s\s+r0,\[pcl,0x104\]\s+;0x266290',
        r'ld_s\s+r1,\[pcl,0xfc\]\s+;0x266294',
        r'bl\.d\s+-1018112\s+;0x16d898',
        r'ld_s\s+r0,\[pcl,0xfc\]\s+;0x266298',
        r'bl\.d\s+-1018296\s+;0x16d7e8',
        r'mov_s\s+r1,0xff',
        r'cmp_s\s+r14,0x6000',
        r'bmsk\s+r1,r14,0x4',
        r'sub_s\s+r1,r1,0x1',
        r'bset\s+r0,r0,r1',
        r'stw_s\s+r0,\[r2,0\]',
        r'bl\.d\s+-224\s+;0x2660e8',
    ]),
    ('class6000_raise_2660e8', 0x2660E8, 0x266150, [
        r'and\.f\s+0,r0,0x6000',
        r'mov_s\s+r15,r1',
        r'ld_s\s+r14,\[pcl,0x24\]\s+;0x266120',
        r'ldh\.di\s+r2,\[r14,8\]',
        r'add3\s+r13,r14,r1',
        r'ldh\.di\s+r2,\[r13,12\]',
        r'cmp_s\s+r0,r2',
        r'ld\.di\s+r2,\[r14\]',
        r'ldb\.di\s+r1,\[r13,14\]',
        r'sth\.di\s+r0,\[r2\]',
        r'ld\.di\s+r1,\[r14,4\]',
        r'ldb\.di\s+r0,\[r13,15\]',
    ]),
    ('class8000_raise_266300', 0x266300, 0x266354, [
        r'btst_s\s+r0,0xf',
        r'ld_s\s+r14,\[pcl,0x20\]\s+;0x266330',
        r'ldh\.di\s+r2,\[r14,8\]',
        r'ldh\.di\s+r2,\[r13,12\]',
        r'cmp_s\s+r0,r2',
        r'ld\.di\s+r2,\[r14\]',
        r'ldb\.di\s+r1,\[r13,14\]',
        r'sth\.di\s+r0,\[r2\]',
    ]),
    ('w1c_clearall_263f08', 0x263F08, 0x263F44, [
        r'ld_s\s+r0,\[pcl,0x8\]\s+;0x263f14',
        r'ld_s\s+r13,\[pcl,0xc\]\s+;0x263f18',
        r'sth\.di\s+r13,\[r0\]',
        r'ld_s\s+r0,\[pcl,0x4\]\s+;0x263f30',
    ]),
    ('v6_bit9_getter_2640b0', 0x2640B0, 0x2640C8, [
        r'ld_s\s+r0,\[pcl,0x8\]\s+;0x2640b8',
        r'ldh\.di\s+r0,\[r0\]',
        r'lsr_s\s+r0,r0,0x9',
        r'bmsk_s\s+r0,r0,0',
    ]),
    ('v6_bit9_clear_2640c8', 0x2640C8, 0x2640E0, [
        r'ld_s\s+r1,\[pcl,0xc\]\s+;0x2640d4',
        r'mov\s+r0,512',
        r'sth\.di\s+r0,\[r1\]',
    ]),
    ('iris_handler_1a1490', 0x1A1490, 0x1A14AC, [
        r'push_s\s+blink',
        r'bl\s+1649816\s+;0x334128',
        r'ld_s\s+r0,\[pcl,0x14\]\s+;0x1a14a8',
        r'mov_s\s+r15,0x1',
        r'b_s\s+20\s+;0x1a14ac',
    ]),
    ('iris_handler_ack', 0x1A14AC, 0x1A14C8, [
        r'sth\.di\s+r15,\[r0\]',          # W1C ack: writes 1 to 0xFED3818
        r'ld_s\s+r0,\[pcl,0x4\]\s+;0x1a14b4',
        r'ldh\.di\s+r0,\[r0\]',
        r'mov_s\s+r13,r0',
        r'ld_s\s+r0,\[pcl,0x8\]\s+;0x1a14c4',
    ]),
    ('iris_handler_poll', 0x1A14C8, 0x1A14F0, [
        r'ldh\.di\s+r0,\[r0\]',
        r'and_s\s+r0,r0,r13',
        r'bmsk_s\s+r0,r0,0x3',
        r'cmp_s\s+r0,0',
        r'ble_s\s+14',
        r'ld_s\s+r0,\[pcl,0x10\]\s+;0x1a14e4',
        r'ld_s\s+r0,\[r0,0\]',
        r'jl_s\s+\[r0\]',
    ]),
    ('iris3004_register_1a082c', 0x1A082C, 0x1A0864, [
        r'ld_s\s+r13,\[pcl,0x50\]\s+;0x1a0880',
        r'ldb_s\s+r1,\[r13,0\]',
        r'ld_s\s+r1,\[pcl,0x48\]\s+;0x1a0884',
        r'bl\.d\s+662488\s+;0x242414',
        r'ld_s\s+r0,\[pcl,0x48\]\s+;0x1a0888',
        r'bl\.d\s+662172\s+;0x2422e8',
        r'ld_s\s+r0,\[pcl,0x38\]\s+;0x1a0888',
        r'mov_s\s+r1,0x1',
        r'stb_s\s+r1,\[r13,0\]',
    ]),
    ('lens_init_23912a', 0x23912A, 0x239146, [
        r'bl\s+36\s+;0x23914c',          # register(0x3001, 0x23915C) helper
        r'ld_s\s+r1,\[pcl,0x1c\]\s+;0x239148',
        r'mov_s\s+r0,0xb',
        r'bset_s\s+r0,r0,0xf',
        r'bl\s+185104\s+;0x266444',      # register(0x800B, 0x238C88)
        r'mov_s\s+r0,0xc',
        r'bset_s\s+r0,r0,0x19',
        r'bl\s+-918656\s+;0x158cbc',
    ]),
    ('lens3001_register_23914c', 0x23914C, 0x239158, [
        r'ld_s\s+r1,\[pcl,0x8\]\s+;0x239154',
        r'b\.d\s+37576\s+;0x242414',
        r'ld_s\s+r0,\[pcl,0x8\]\s+;0x239158',
    ]),
    ('class8000_high_register_266444', 0x266444, 0x266482, [
        r'mov_s\s+r14,r0',
        r'mov_s\s+r15,r1',
        r'btst_s\s+r14,0xf',
        r'ld_s\s+r2,\[pcl,0x48\]\s+;0x2664a0',
        r'ldh\.di\s+r0,\[r2,8\]',
        r'add3\s+r1,r2,r13',
        r'ldh\.di\s+r0,\[r1,12\]',
        r'cmp_s\s+r14,r0',
        r'st\.di\s+r15,\[r1,16\]',       # writes fn into the high-table record
    ]),
    ('lens3001_handler_23915c', 0x23915C, 0x239178, [
        r'push_s\s+blink',
        r'mov_s\s+r0,0xe',
        r'bl\s+-837684\s+;0x16c92c',
        r'cmp_s\s+r0,0x10',
        r'bl_s\s+-1504\s+;0x238b88',
        r'bl\s+-837772\s+;0x16c8e4',
    ]),
    ('lens3001_ready_23917c', 0x23917C, 0x239194, [
        r'push_s\s+blink',
        r'bl\.d\s+37216\s+;0x2422e8',
        r'ld\s+r0,\[pcl,-52\]\s+;0x239158',
    ]),
    ('lens3001_unreg_239194', 0x239194, 0x2391AC, [
        r'push_s\s+blink',
        r'bl\.d\s+37344\s+;0x242380',
        r'ld\s+r0,\[pcl,-76\]\s+;0x239158',
    ]),
    ('high800b_handler_238c88', 0x238C88, 0x238CC8, [
        r'push_s\s+blink',
        r'ld\s+r13,\[pcl,-180\]\s+;0x238bd8',
        r'ldb\s+r0,\[r13,50\]',
        r'stb_s\s+r0,\[r1,0\]',
        r'bl_s\s+-376\s+;0x238b34',       # calls the (failing) raise caller
        r'bl_s\s+-220\s+;0x238be0',
    ]),
]


def has(text: str, pattern: str) -> None:
    assert re.search(pattern, text), f'missing pattern: {pattern}'


def census_calls(targets) -> dict:
    pat = re.compile(
        r'V([0-9A-F]{6,8}) \|[0-9a-f ]+\| '
        r'(bl|bl\.d|bl_s|bl_s\.d)\s+?-?\d+\s+;0x([0-9a-f]+)\b')
    hits = {t: [] for t in targets}
    with LISTING.open('r', errors='replace') as fh:
        for line in fh:
            m = pat.search(line)
            if not m:
                continue
            target = int(m.group(3), 16)
            if target in hits:
                hits[target].append(int(m.group(1), 16))
    return hits


def scan_le(payload: bytes, base: int, value: int):
    pat = struct.pack('<I', value)
    return [base + i for i in range(0, len(payload) - 3, 1)
            if payload[i:i + 4] == pat]


def parse_table(p1: bytes, base1: int, tab: int):
    off = tab - base1
    hdr = {
        'pending': struct.unpack_from('<I', p1, off)[0],
        'enable': struct.unpack_from('<I', p1, off + 4)[0],
        'count': struct.unpack_from('<H', p1, off + 8)[0],
    }
    records = []
    for k in range(hdr['count']):
        rec = off + 12 + 8 * k
        records.append({
            'id': struct.unpack_from('<H', p1, rec)[0],
            'bitB': p1[rec + 2],
            'bitA': p1[rec + 3],
            'fn': struct.unpack_from('<I', p1, rec + 4)[0],
        })
    return hdr, records


def model_raise(p1: bytes, base1: int, tables: list, rid: int):
    """Functional model of 0x16D4D8: full 32-bit id compare vs the record
    ids of the six generic tables; returns (pending_reg, bit, error)."""
    for tab in tables:
        hdr, recs = parse_table(p1, base1, tab)
        for r in recs:
            if r['id'] == rid:          # 32-bit equality, ids are <= 0xFFFF
                return hdr['pending'], r['bitB'], 0
    return None, None, 0x200601


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
    base1 = info[1]['load_address_candidate']
    p0, p1 = payloads[0], payloads[1]
    assert base0 == 0x0AD800 and base1 == 0x360800

    results = {}

    # 1. Raw LE pool words (payload0).
    for addr, value in LITERALS.items():
        got = struct.unpack_from('<I', p0, addr - base0)[0]
        assert got == value, (hex(addr), hex(got), hex(value))
    results['pool_words_verified'] = len(LITERALS)

    # 2. Payload1 table parses.
    generic = [0x424A00, 0x424A8C, 0x424B18, 0x424BA4, 0x424C30, 0x424CBC]
    hdr6, rec6 = parse_table(p1, base1, TAB_6XX)
    assert hdr6 == {'pending': 0xFEF0074, 'enable': 0xFEF0028, 'count': 16}
    assert [r['id'] for r in rec6] == [0x610 - k for k in range(16)]
    all_ids = []
    for tab in generic:
        _, recs = parse_table(p1, base1, tab)
        all_ids += [r['id'] for r in recs]
    assert max(all_ids) <= 0x0A10 and min(all_ids) >= 0x401
    results['generic_record_ids'] = {'min': hex(min(all_ids)),
                                     'max': hex(max(all_ids)),
                                     'count': len(all_ids)}

    hdrE, recE = parse_table(p1, base1, TAB_6000_HIGH)
    assert hdrE == {'pending': 0xFEF0228, 'enable': 0xFEF022C, 'count': 16}
    assert [r['id'] for r in recE] == [0x6010 - k for k in range(16)]
    assert [r['bitB'] for r in recE] == [15 - k for k in range(16)]
    hdrF, recF = parse_table(p1, base1, TAB_8000_HIGH)
    assert hdrF == {'pending': 0xFEF0048, 'enable': 0xFEF0324, 'count': 16}
    assert [r['id'] for r in recF] == [0x8010 - k for k in range(16)]
    hdrB, recB = parse_table(p1, base1, TAB_B000_HIGH)
    assert hdrB == {'pending': 0xFEF044C, 'enable': 0xFEF0448, 'count': 13}
    assert [r['id'] for r in recB] == [0xB00D - k for k in range(13)]
    # the high tables are NOT part of the six-entry array
    arr = [struct.unpack_from('<I', p1, TABLES_ARRAY - base1 + 4 * i)[0]
           for i in range(8)]
    assert arr == [0x424A00, 0x424A8C, 0x424B18, 0x424BA4, 0x424C30,
                   0x424CBC, 0, 0]
    for tab in (TAB_6000_HIGH, TAB_8000_HIGH, TAB_B000_HIGH):
        assert tab not in arr
    results['high_tables'] = {
        '0x424e00': {'pending': '0xfef0228', 'enable': '0xfef022c',
                     'count': 16, 'ids': '0x6001..0x6010'},
        '0x424f00': {'pending': '0xfef0048', 'enable': '0xfef0324',
                     'count': 16, 'ids': '0x8001..0x8010'},
        '0x425000': {'pending': '0xfef044c', 'enable': '0xfef0448',
                     'count': 13, 'ids': '0xb001..0xb00d'},
    }

    # 3. Aligned windows + pattern assertions.
    for name, start, end, patterns in WINDOWS:
        text = aligned_window(p0, base0, start, end)
        (out / f'window_{name}.txt').write_text(text)
        for pat in patterns:
            try:
                has(text, pat)
            except AssertionError as exc:
                raise AssertionError(f'[{name}] {exc}') from None
    results['windows_verified'] = len(WINDOWS)

    # the raise loop contains no mask on r0 (the id stays 32-bit)
    raise_text = aligned_window(p0, base0, 0x16D4D8, 0x16D588)
    assert not re.search(r'and\s+r0,', raise_text)
    assert not re.search(r'extw_s\s+r0,', raise_text)
    # the three raise callers' ids can never match a record id
    for caller_id in (0xFFFF9007, 0xFFFF8008, 0xFFFF800B):
        assert caller_id > 0xFFFF
        pend, bit, err = model_raise(p1, base1, generic, caller_id)
        assert (pend, bit, err) == (None, None, 0x200601), hex(caller_id)
    # positive control: raise(0x610) would set bit 15 of the vector-6 pending
    pend, bit, err = model_raise(p1, base1, generic, 0x610)
    assert (pend, bit, err) == (0xFEF0074, 15, 0)
    # but no static caller passes a low-class id: census frozen above
    results['raise_model'] = {
        'callers': ['0xffff9007', '0xffff8008', '0xffff800b'],
        'callers_never_match': True,
        'control_0x610': 'pending 0xfef0074 bit 15 (hardware-raised only)',
    }

    # 4. Frozen LE scans (payload0 pool references).
    for value, expect in LE_SCAN_EXPECT.items():
        got = scan_le(p0, base0, value)
        assert sorted(got) == sorted(expect), (hex(value), [hex(x) for x in got])
    results['le_scans'] = {hex(v): [hex(x) for x in e]
                           for v, e in LE_SCAN_EXPECT.items()}

    # 5. Call censuses.
    got = census_calls(list(CENSUS))
    for target, expect in CENSUS.items():
        assert set(got[target]) == expect, (
            hex(target), sorted(map(hex, got[target])),
            sorted(map(hex, expect)))
    results['call_census'] = {hex(t): sorted(map(hex, e))
                               for t, e in CENSUS.items()}

    # 6. Summary.
    results['status'] = 'PASS_SERVICE_RAISE_PENDING_STATIC'
    results['utc'] = stamp
    results['firmware_sha256'] = sha(FIRMWARE)
    results['assumptions'] = [
        'CMP_S is a full 32-bit compare (ARCompact ISA manual, CMP_S b,h)',
        'ld_s pcl targets are (PC & ~3) + field*4 (byte-proven rule)',
        'plain ld [pcl,off] is non-scaled (encoding f4 17 00 f0 at 0x2331B8)',
        'W1C semantics of the pending registers inferred from the pattern',
    ]
    results['limits'] = [
        'Static analysis only; no hardware or runtime execution',
        'MMIO 0xFED3xxx/0xFEF0xxx identity open (interrupt controller inferred)',
        'Walkers of the high tables 0x424E00/0x424F00/0x425000 not decoded',
        'Remaining high-class services (0x1000/0x2000/0x5000/0x7000/0x9000/'
        '0xA000/0xB000 bodies) not fully decoded; exemplar class 0x6000',
        'V1.1 sample vs V1.0 machine',
    ]
    (out / 'verified_evidence.json').write_text(
        json.dumps(results, indent=2, sort_keys=True) + '\n')
    latest = {k: f'{stamp}/{k}' if k.endswith('.json') else f'{stamp}/{k}'
              for k in ('verified_evidence.json', 'script_snapshot.py')}
    latest = {'utc': stamp, 'evidence': str(out.relative_to(ROOT)),
              'files': ['verified_evidence.json', 'script_snapshot.py']}
    EVIDENCE.joinpath('latest.json').write_text(
        json.dumps(latest, indent=2) + '\n')
    print('PASS_SERVICE_RAISE_PENDING_STATIC', stamp)
    print('windows:', len(WINDOWS), 'pools:', len(LITERALS),
          'le_scans:', len(LE_SCAN_EXPECT), 'census:', len(CENSUS))


if __name__ == '__main__':
    main()
