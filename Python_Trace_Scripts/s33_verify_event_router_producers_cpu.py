#!/usr/bin/env python3
"""Static + CPU verification of the GUI event-delivery chain that carries the
bridge events (0x3B81/0x3181/0x3301/0x4006) to the window with the event table
0x99AB8C (V1.1) - the producers side of the it.44 dataflow.

Closes the open point (a) of iteration 44 (checkpoint 2026-11-01): who sends
0x3B81/0x3181 (and the extended bridges 0x0100/0x0180/0x0400) to the window,
via the WindowManager queue/router, to turn "save -> 0x4405 -> 0x89A330 ->
bridge handler -> guard" into a demonstrated runtime sequence.

Facts asserted here (frozen event table + node words + pool words + LE scans +
bl censuses + producer classification over the GNU listing + frozen aligned
objdump windows + raw window bytes/sha256 + 8 CPU cases on the GNU ARC700
simulator executing ORIGINAL firmware bytes):

- DELIVERY CHAIN (static, bl targets byte-verified):
  post wrappers 0x169EB4/0x169F40/0x169F00 -> ring queue insert 0x17BC7C
  (records {u16 arg0, u16 event, u32 arg}, stride 12, 128 entries, base
  pool 0x17C000=0x47A848, halfword read index at pool 0x17BFF8=0x367BBC+0,
  write index at +2 - CPU-proven: the ldw_s.x/stw_s [r2,2] offset is
  UNSCALED, not x2) or push-front 0x17BCE4 -> WindowManager cycle
  0x15AF1C/0x15AF2E extracts via 0x17BD4C -> 0x169E1C([sp+0], event, [sp+8]):
  event 0x440F -> request executor 0x1453E4(lo16(arg), hi16(arg)); desc==0 and
  event < 0x4400 -> current node resolver 0x1453F4 = [[0x366EA4]] -> delivery
  0x169D78(node, event, arg) -> default (node > 8) target pool
  0x16A160 = 0x16A6E4 -> 0x16A028 -> callback resolver 0x14505C -> [node+0xC].
- The window node is 0x99AB6C (payload5): id 0x402, flags 0x0021007E,
  subwindow list 0x99AAE8, callback at +0xC = 0x7F6824 (the ONLY LE of
  0x7F6824 in all 16 payloads), event table at +0x20 = 0x99AB8C.
- Router 0x7F6824(arg0, event, arg2): stores 0 -> [0x89A318+0xA]; events
  outside [128, 0x307F] bypass the key machine and forward DIRECTLY to
  0x169F60(0x99ACAC, 0x99AB8C, arg0, event, arg2) (pool words 0x7F6A48/0x7F6A4C
  are the ONLY LE occurrences of 0x99ACAC/0x99AB8C).
- 0x169F60(exclusion_array, table, ctx, event, arg): if event is IN the
  16-ID array -> return 0 WITHOUT any dispatch (exclusion list); if not in the
  array -> scan the 8-byte (id, handler) table entries, terminator id==0, and
  call handler(ctx). CPU: 0x3181 -> 0x7F871C executes the bridge (guard :=
  [0x89A330]); with the array patched to contain 0x3181 -> NO dispatch.
- PRODUCERS (classification of every bl caller of 0x169EB4 (304),
  0x169F40 (28), 0x169F00 (33) by the event argument r1, pool-resolved):
  0x3181 x11 (0xC9A7C, 0x2CCBCE, 0x65CAB0, 0x7E33BE, 0x7E3BD0, 0x7FDE46,
  0x7FE36E, 0x80095E, 0x802626, 0x9D82DA, 0x9DBEEA), 0x3301 x4 (0x2D348C,
  0x9D1F70, 0x2D40C4, 0x803422), 0x3081 x1 (0x7E8D66), 0x3101 x1 (0x7F73E2),
  0x3281 x7 (0x7FA986, 0x9D47E2, 0x9D621E, 0x9E1DC4, 0x13556E, 0x7F888E,
  0x7FF6EA) - all posting desc=0 (delivered to the CURRENT window).
  0x3B81: EXACTLY ONE producer chain - dispatcher case 229 at 0x80B48E ->
  wrapper 0x8101C8 (bl caller census: exactly 0x80B48E; zero LE words) ->
  0x169F40(0, 0x3181... no: 0x3B81, caller arg).
  0x4006: NO producer with a constant event id in any post API - it appears
  as a table entry of >= 8 other window tables in payload5 (0x98E7E0,
  0x99AC8C, 0x99BBDC, 0x99C5D8, 0x99C8AC, 0x99D4DC, 0x9A0688, 0x9A3034):
  its delivery mechanism is OPEN.
- 0x169E1C has EXACTLY ONE bl caller: 0x15AF42, inside the WindowManager
  cycle fragment 0x15AF1C..0x15AF48 (extract -> deliver).
- CPU cases (original bytes; stubs at original addresses; windows cut before
  the final 32-bit b as in it.44 - the sim wraps the 13-bit b displacement
  mod 8192):
  1 post3181: 0x169EB4(0, 0x3181, 0x77) -> 0x17BC7C inserts the record
     {0, 0x3181, 0x77} at ring index 0, read=0 write=1, then the signal stub
     0x158CBC checks memory and faults 0xDEADA201.
  BANK FINDING (delay slot semantics, CPU-proven): in 0x17BC7C the
  `bl.d 0x1786e8` delay slot `mov r17,r0` copies r0 BEFORE the call, so r17
  holds the CRITICAL-SECTION TOKEN returned by the lock stub 0x1593AC (the
  delay slot of the preceding bl.d), not the 0x1786E8 return; the lock stub
  must return nonzero or the insert falls into the error path 0x1594A4.
  2 post3181_overflow: ring full (read=0, write=0x7F) -> NO insert, NO
     signal, record and indexes untouched -> probe at the cut 0x17BCDE
     faults 0xDEADA202.
  3 extract3181: 0x17BD4C(buf) with the ring as left by case 1 -> buf =
     {0, 0x3181, 0x77}, read advances to 1 -> probe faults 0xDEADA301.
  4 extract3181_empty: empty ring -> error path 0x1594A4 called once, buf
     untouched -> probe faults 0xDEADA401.
  5 resolve3181: 0x169E1C(0, 0x3181, 0x77) with [0x366EA4]=0x99AB6C (node
     copied from payload5) -> 0x1453F4 resolves it, 0x169D78 stub receives
     (0x99AB6C, 0x3181, 0x77) -> probe faults 0xDEADA501.
  6 resolve3181_none: [0x366EA4]=0 -> 0x169D78 NOT called, returns 0 ->
     probe faults 0xDEADA601.
  7 dispatch3181: router 0x7F6824(0x6001, 0x3181, 0x77) -> 0x169F60 ->
     table 0x99AB8C -> handler 0x7F871C (ORIGINAL) -> guard 0x365751 :=
     [0x89A330] = 7, transition to the desired mode 0x2C, ordered stub
     sequence fault 0xDEADA701.
  8 dispatch3181_blocked: same, but the array copy patched with 0x3181 ->
     NO dispatch, guard sentinel intact, router store [0x89A322]=0 proves
     the router ran -> the probe sits at the 0x169F60 tail cut 0x169FB0
     (4-byte trampoline, no epilogue emulation) and faults 0xDEADA801.
  BANK FINDING (trampolines): when the landing address borders original
  pool data (0x7F6A28 vs the router pools at 0x7F6A2C) the trampoline is
  4 bytes with no nop padding; probes that only check-and-fault never need
  epilogue emulation.

Read-only: firmware, blocks, tools and listings are never modified.
No hardware, no USB/SD access; NON_INSTALLARE state unchanged.
"""
import hashlib
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads
from s33_verify_capture_guard_setter_census import census, LISTING
from s33_verify_capture_transition_caller_census import window_lines
from s33_verify_capture_restore_caller_census import le_scan
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha, elf_loads

STACK = 0xC8F000
LOG_BASE = 0x367000
NODE = 0x99AB6C
NODE_CALLBACK = 0x7F6824
CUR_NODE_CELL = 0x366EA4
QUEUE = 0x367BBC            # pool 0x17BFF8
QUEUE_WRITE = QUEUE + 2     # ldw_s.x/stw_s [r2,2] UNSCALED (CPU-proven)
RECORDS = 0x47A848          # pool 0x17C000
BUF = 0x367400
GUARD_CELL = 0x365751
DESIRED_CELL = 0x3657C8
SAVED_GUARD_CELL = 0x3657CC
BRIDGE_CELL = 0x89A330

# --- frozen node (payload5) --------------------------------------------------
NODE_WORDS = [0x00000402, 0x0021007E, 0x0099AAE8, 0x007F6824,
              0x00000000, 0x0099ACF9, 0x00000000, 0x00000000]

# --- frozen event table (payload5, it.44) ------------------------------------
EVENT_TABLE = [
    (0x4401, 0x7F6A50), (0x4405, 0x7F6A90), (0x4406, 0x7F7218),
    (0x440E, 0x7F7438), (0x440C, 0x7F8394), (0x0080, 0x7F7BC4),
    (0x0081, 0x7F7E34), (0x0100, 0x7F7EB0), (0x0101, 0x7F7F78),
    (0x2180, 0x7F7F8C), (0x0180, 0x7F7FAC), (0x0200, 0x7F8374),
    (0x0900, 0x7F8000), (0x0901, 0x7F8028), (0x0280, 0x7F8048),
    (0x0300, 0x7F8048), (0x0281, 0x7F8230), (0x0301, 0x7F8230),
    (0x0700, 0x7F833C), (0x3101, 0x7F831C), (0x4817, 0x7F8414),
    (0x0600, 0x7F84CC), (0x0400, 0x7F850C), (0x0480, 0x7F850C),
    (0x0500, 0x7F850C), (0x0780, 0x7F8374), (0x3081, 0x7F85B4),
    (0x4001, 0x7F860C), (0x4110, 0x7F9E6C), (0x3281, 0x7F863C),
    (0x3301, 0x7F86C0), (0x3181, 0x7F871C), (0x4006, 0x7F877C),
    (0x3B81, 0x7F8674), (0x4002, 0x7F9EB4),
]
EVENT_TABLE_BASE = 0x99AB8C
EVENT_TABLE_TERMINATOR = (0x0000, 0x20E814)      # at 0x99ACA4
TRAILING_EVENT_IDS = [0x0480, 0x0481, 0x0500, 0x0501, 0x0380, 0x0381,
                      0x0400, 0x0401, 0x0580, 0x0700, 0x2180, 0x2700,
                      0x0581, 0x0701, 0x2181, 0x2701]   # words 0x99ACAC..ACC8

# --- frozen pool words --------------------------------------------------------
POOLS = {
    (0, 0x17BFF4): 0x00300008,   # signal object id (0x158CBC arg)
    (0, 0x17BFF8): 0x00367BBC,   # queue index cell
    (0, 0x17BFFC): 0x00300004,   # lock object id
    (0, 0x17C000): 0x0047A848,   # record array base
    (0, 0x16A128): 0x00367800,   # pre/post hook cell (0x169E1C)
    (0, 0x16A12C): 0x00367808,   # pre-hook cell (0x169D78)
    (0, 0x16A130): 0x0036780C,   # hook cell (0x169EB4)
    (0, 0x16A134): 0x00367810,   # hook cell (0x16A028)
    (0, 0x16A160): 0x0016A6E4,   # default node>8 delivery target
    (0, 0x14579C): 0x00366EA4,   # current-window cell
    (0, 0xD0530): 0x003657C8,    # desired-mode cell (getter 0xD0528)
    (0, 0xCA30C): 0x00365751,    # guard cell (setter 0xCA2F4)
    (4, 0x7F6A2C): 0x0089A318,   # router pool
    (4, 0x7F6A30): 0x0089A2FC,   # router pool
    (4, 0x7F6A48): 0x0099ACAC,   # exclusion array (router)
    (4, 0x7F6A4C): 0x0099AB8C,   # event table (router)
    (4, 0x7F86BC): 0x0089A330,   # bridge cell (handler B pool)
}

# --- frozen bl censuses -------------------------------------------------------
CENSUS_EXPECT = {
    0x169E1C: [0x15AF42],          # WindowManager cycle fragment only
    0x7F6824: [],                  # pure callback (registered at node+0xC)
    0x17BC7C: [0x1492F6, 0x169EF4, 0x16F71E],
    0x17BCE4: [0x169F36],          # push-front, only from 0x169F00
    0x16A028: [0x16a0b4, 0x16a0c6, 0x16a1f2, 0x16a21a, 0x16a404, 0x16a446, 0x16a4f0, 0x16a622, 0x16a660, 0x16a69e, 0x16a6da, 0x16a79c, 0x16a82a, 0x16a87c, 0x16a884, 0x16a8b4, 0x16a90a, 0x16a912, 0x16a932],  # shared callback invoker (19 sites incl. 0x16A79C)
    0x8101C8: [0x80B48E],          # 0x3B81 wrapper, single caller
}

# --- frozen LE scans ----------------------------------------------------------
LE_EXPECT = {
    0x7F6824: [(5, 0x99AB78)],     # node callback registration
    0x16A6E4: [(0, 0x16A160)],     # default delivery pool
    0x8101C8: [],                  # no table/pointer entry
    0x99ACAC: [(4, 0x7F6A48)],     # router array pool
    0x99AB8C: [(4, 0x7F6A4C)],     # router table pool
}

# --- frozen producer sites: api -> event -> [(site, pool_idx, pool_addr)] -----
PRODUCERS = {
    0x169EB4: {
        0x3181: [(0xC9A7C, 0, 0xC9BA4), (0x2CCBCE, 0, 0x2CCDC0),
                 (0x65CAB0, 2, 0x65CC20), (0x7E33BE, 4, 0x7E342C),
                 (0x7E3BD0, 4, 0x7E3C90), (0x7FDE46, 4, 0x7FDEA0),
                 (0x7FE36E, 4, 0x7FE418), (0x80095E, 4, 0x80099C),
                 (0x802626, 4, 0x802730), (0x9D82DA, 6, 0x9D8348),
                 (0x9DBEEA, 6, 0x9DBF4C)],
        0x3301: [(0x2D348C, 0, 0x2D36B8), (0x9D1F70, 6, 0x9D1FA4)],
        0x3081: [(0x7E8D66, 4, 0x7E8E5C)],
        0x3101: [(0x7F73E2, 4, 0x7F7430)],
        0x3281: [(0x7FA986, 4, 0x7FA9F8), (0x9D47E2, 6, 0x9D47F0),
                 (0x9D621E, 6, 0x9D622C), (0x9E1DC4, 6, 0x9E1DD4)],
    },
    0x169F40: {
        0x3281: [(0x13556E, 0, 0x1355F0), (0x7F888E, 4, 0x7F88A8),
                 (0x7FF6EA, 4, 0x7FF704)],
        0x3301: [(0x2D40C4, 0, 0x2D40D0), (0x803422, 4, 0x803444)],
        0x3B81: [(0x8101DC, 4, 0x8101EC)],
    },
    0x169F00: {},               # no bridge event posted push-front
}
API_CALLER_COUNTS = {0x169EB4: 304, 0x169F40: 28, 0x169F00: 33}
BRIDGE_EVENTS = (0x3181, 0x3301, 0x3B81, 0x3081, 0x3101, 0x3281)
# 0x4006 has NO constant producer in any post API (documented open point).
NO_PRODUCER_EVENTS = (0x4006, 0x4001, 0x4002)
# 0x4006 as a table entry in other payload5 window tables (broadcast hint)
P5_4006_TABLE_WORDS = [0x98E7E0, 0x99AC8C, 0x99BBDC, 0x99C5D8, 0x99C8AC,
                        0x99D4DC, 0x9A0688, 0x9A3034]

# --- frozen CPU windows (raw bytes, sha256 of the full original region) ------
ROUTER_BYTES = dict(idx=4, lo=0x7F6824, hi=0x7F6A28)
HANDLER_B_BYTES = dict(idx=4, lo=0x7F871C, hi=0x7F8776)
TABLE_DATA = dict(idx=5, lo=0x99AB8C, hi=0x99ACCC)
NODE_DATA = dict(idx=5, lo=0x99AB6C, hi=0x99AB8C)


def raw_window(payloads, base, spec):
    return payloads[spec['idx']][spec['lo'] - base[spec['idx']]:
                                 spec['hi'] - base[spec['idx']]]


W_169EB4 = [
    (0x169EB4, 'push_s	blink'),
    (0x169EB6, 'bl	1876592	;0x334124'),
    (0x169EBA, 'mov_s	r17,r0'),
    (0x169EBC, 'ld_s	r0,[pcl,0x274]	;0x16a130'),
    (0x169EBE, 'mov_s	r13,r1'),
    (0x169EC0, 'ld_s	r3,[r0,0]'),
    (0x169EC2, 'cmp_s	r3,0'),
    (0x169EC4, 'mov_s	r16,r2'),
    (0x169EC6, 'beq_s	8	;0x169ecc'),
    (0x169EC8, 'jl_s.d	[r3]'),
    (0x169ECA, 'mov_s	r0,r17'),
    (0x169ECC, 'cmp_s	r13,0x4409'),
    (0x169ED2, 'beq_s	12	;0x169edc'),
    (0x169ED4, 'cmp_s	r13,0x440e'),
    (0x169EDA, 'bne_s	22	;0x169eee'),
    (0x169EDC, 'mov_s	r0,r17'),
    (0x169EDE, 'mov_s	r1,r13'),
    (0x169EE0, 'bl.d	73632	;0x17be80'),
    (0x169EE4, 'mov_s	r2,r16'),
    (0x169EE6, 'cmp_s	r0,0'),
    (0x169EE8, 'beq_s	6	;0x169eee'),
    (0x169EEA, 'mov_s	r0,0x1'),
    (0x169EEC, 'b_s	14	;0x169efa'),
    (0x169EEE, 'mov_s	r0,r17'),
    (0x169EF0, 'mov_s	r1,r13'),
    (0x169EF2, 'mov_s	r2,r16'),
    (0x169EF4, 'bl.d	73096	;0x17bc7c'),
    (0x169EF8, 'mov_s	r3,0'),
]

W_17BC7C = [
    (0x17BC7C, 'push_s	blink'),
    (0x17BC7E, 'bl	1803428	;0x334120'),
    (0x17BC82, 'mov_s	r15,r0'),
    (0x17BC84, 'mov_s	r18,r1'),
    (0x17BC86, 'mov_s	r16,r2'),
    (0x17BC88, 'mov_s	r14,0'),
    (0x17BC8A, 'ld_s	r0,[pcl,0x374]	;0x17bffc'),
    (0x17BC8C, 'bl.d	-141536	;0x1593ac'),
    (0x17BC90, 'mov_s	r1,r14'),
    (0x17BC92, 'bl.d	-13736	;0x1786e8'),
    (0x17BC96, 'mov_s	r17,r0'),
    (0x17BC98, 'ld_s	r2,[pcl,0x360]	;0x17bff8'),
    (0x17BC9A, 'ldw_s.x	r13,[r2,0x2]'),
    (0x17BC9C, 'ldw_s.x	r1,[r2,0]'),
    (0x17BC9E, 'add_s	r0,r13,0x1'),
    (0x17BCA0, 'bmsk_s	r0,r0,0x6'),
    (0x17BCA2, 'cmp_s	r0,r1'),
    (0x17BCA4, 'bne_s	4	;0x17bca8'),
    (0x17BCA6, 'b_s	8	;0x17bcac'),
    (0x17BCA8, 'stw_s	r0,[r2,0x2]'),
    (0x17BCAA, 'mov_s	r14,0x1'),
    (0x17BCAC, 'bl	-10584	;0x179354'),
    (0x17BCB0, 'cmp_s	r14,0'),
    (0x17BCB2, 'beq_s	22	;0x17bcc6'),
    (0x17BCB4, 'ld_s	r12,[pcl,0x34c]	;0x17c000'),
    (0x17BCB6, 'asl_s	r13,r13,0x2'),
    (0x17BCB8, 'add1_s	r13,r13,r13'),
    (0x17BCBA, 'add_s	r13,r13,r12'),
    (0x17BCBC, 'st_s	r15,[r13,0]'),
    (0x17BCBE, 'sth	r18,[r13,4]'),
    (0x17BCC2, 'st	r16,[r13,8]'),
    (0x17BCC6, 'cmp	r17,0'),
    (0x17BCCA, 'bne_s	10	;0x17bcd2'),
    (0x17BCCC, 'bl.d	-141352	;0x1594a4'),
    (0x17BCD0, 'ld_s	r0,[pcl,0x32c]	;0x17bffc'),
    (0x17BCD2, 'cmp_s	r14,0'),
    (0x17BCD4, 'beq_s	10	;0x17bcde'),
    (0x17BCD6, 'ld_s	r0,[pcl,0x320]	;0x17bff4'),
    (0x17BCD8, 'bl.d	-143388	;0x158cbc'),
    (0x17BCDC, 'mov_s	r1,0x1'),
]

W_17BD4C = [
    (0x17BD4C, 'push_s	blink'),
    (0x17BD4E, 'bl	1803236	;0x334130'),
    (0x17BD52, 'mov_s	r14,r0'),
    (0x17BD54, 'mov_s	r13,0'),
    (0x17BD56, 'ld_s	r0,[pcl,0x2a8]	;0x17bffc'),
    (0x17BD58, 'bl.d	-141740	;0x1593ac'),
    (0x17BD5C, 'mov_s	r1,r13'),
    (0x17BD5E, 'ld_s	r2,[pcl,0x29c]	;0x17bff8'),
    (0x17BD60, 'ldw_s.x	r3,[r2,0x2]'),
    (0x17BD62, 'ldw_s.x	r1,[r2,0]'),
    (0x17BD64, 'cmp_s	r1,r3'),
    (0x17BD66, 'bne_s	6	;0x17bd6a'),
    (0x17BD68, 'b_s	30	;0x17bd86'),
    (0x17BD6A, 'ld_s	r12,[pcl,0x298]	;0x17c000'),
    (0x17BD6C, 'asl_s	r3,r1,0x2'),
    (0x17BD6E, 'add1_s	r3,r3,r3'),
    (0x17BD70, 'add_s	r1,r1,0x1'),
    (0x17BD72, 'ld.aw	r13,[r3,r12]'),
    (0x17BD76, 'bmsk_s	r1,r1,0x6'),
    (0x17BD78, 'stw_s	r1,[r2,0]'),
    (0x17BD7A, 'st_s	r13,[r14,0]'),
    (0x17BD7C, 'ldw_s.x	r13,[r3,0x4]'),
    (0x17BD7E, 'stw_s	r13,[r14,0x4]'),
    (0x17BD80, 'ld_s	r3,[r3,0x8]'),
    (0x17BD82, 'mov_s	r13,0x1'),
    (0x17BD84, 'st_s	r3,[r14,0x8]'),
    (0x17BD86, 'cmp_s	r0,0'),
    (0x17BD88, 'bne_s	8	;0x17bd90'),
    (0x17BD8A, 'bl.d	-141540	;0x1594a4'),
    (0x17BD8E, 'ld_s	r0,[pcl,0x270]	;0x17bffc'),
]

W_169E1C = [
    (0x169E1C, 'push_s	blink'),
    (0x169E1E, 'bl	1876748	;0x334128'),
    (0x169E22, 'mov_s	r13,r0'),
    (0x169E24, 'ld_s	r0,[pcl,0x304]	;0x16a128'),
    (0x169E26, 'mov_s	r14,r1'),
    (0x169E28, 'ld_s	r3,[r0,0]'),
    (0x169E2A, 'cmp_s	r3,0'),
    (0x169E2C, 'mov_s	r15,r2'),
    (0x169E2E, 'beq_s	20	;0x169e40'),
    (0x169E30, 'jl_s.d	[r3]'),
    (0x169E32, 'mov_s	r0,r13'),
    (0x169E34, 'cmp	r0,-1'),
    (0x169E38, 'bne_s	8	;0x169e40'),
    (0x169E3A, 'mov	r16,0'),
    (0x169E3E, 'b_s	90	;0x169e96'),
    (0x169E40, 'cmp_s	r14,0'),
    (0x169E42, 'bne_s	8	;0x169e48'),
    (0x169E44, 'mov_s	r0,0'),
    (0x169E46, 'b_s	64	;0x169e84'),
    (0x169E48, 'cmp_s	r14,0x440f'),
    (0x169E4E, 'bne_s	16	;0x169e5c'),
    (0x169E50, 'sexw_s	r0,r15'),
    (0x169E52, 'bl.d	-150124	;0x1453e4'),
    (0x169E56, 'lsr	r1,r15,0x10'),
    (0x169E5A, 'b_s	42	;0x169e82'),
    (0x169E5C, 'cmp_s	r13,0'),
    (0x169E5E, 'bne_s	26	;0x169e76'),
    (0x169E60, 'cmp_s	r14,0x4400'),
    (0x169E66, 'blt_s	12	;0x169e70'),
    (0x169E68, 'cmp_s	r14,0x47ff'),
    (0x169E6E, 'ble_s	10	;0x169e76'),
    (0x169E70, 'bl	-150140	;0x1453f4'),
    (0x169E74, 'mov_s	r13,r0'),
    (0x169E76, 'cmp_s	r13,0'),
    (0x169E78, 'beq_s	-52	;0x169e44'),
    (0x169E7A, 'mov_s	r0,r13'),
    (0x169E7C, 'mov_s	r1,r14'),
    (0x169E7E, 'mov_s	r2,r15'),
    (0x169E80, 'bl_s	-264	;0x169d78'),
    (0x169E82, 'mov_s	r0,0x1'),
    (0x169E84, 'mov_s	r16,r0'),
    (0x169E86, 'ld_s	r0,[pcl,0x2a4]	;0x16a128'),
    (0x169E88, 'ld_s	r3,[r0,0x4]'),
    (0x169E8A, 'cmp_s	r3,0'),
    (0x169E8C, 'beq_s	10	;0x169e96'),
    (0x169E8E, 'mov_s	r0,r13'),
    (0x169E90, 'mov_s	r1,r14'),
    (0x169E92, 'jl_s.d	[r3]'),
    (0x169E94, 'mov_s	r2,r15'),
]

W_1453F4 = [
    (0x1453F4, 'ld_s	r0,[pcl,0x3a8]	;0x14579c'),
    (0x1453F6, 'j_s.d	[blink]'),
    (0x1453F8, 'ld_s	r0,[r0,0]'),
]

W_169F60 = [
    (0x169F60, 'push_s	blink'),
    (0x169F62, 'bl	1876432	;0x334130'),
    (0x169F66, 'mov_s	r14,r1'),
    (0x169F68, 'mov_s	r13,r2'),
    (0x169F6A, 'mov_s	r1,r3'),
    (0x169F6C, 'mov_s	r2,r4'),
    (0x169F6E, 'cmp_s	r0,0'),
    (0x169F70, 'mov_s	r3,0'),
    (0x169F72, 'bne_s	14	;0x169f7e'),
    (0x169F74, 'mov_s	r0,r3'),
    (0x169F76, 'b_s	22	;0x169f8a'),
    (0x169F78, 'cmp_s	r1,r3'),
    (0x169F7A, 'beq_s	16	;0x169f88'),
    (0x169F7C, 'add_s	r0,r0,0x2'),
    (0x169F7E, 'ldw_s.x	r3,[r0,0]'),
    (0x169F80, 'cmp_s	r3,0'),
    (0x169F82, 'bne_s	-8	;0x169f78'),
    (0x169F84, 'mov_s	r0,0'),
    (0x169F86, 'b_s	6	;0x169f8a'),
    (0x169F88, 'mov_s	r0,0x1'),
    (0x169F8A, 'cmp_s	r0,0'),
    (0x169F8C, 'bne_s	28	;0x169fa8'),
    (0x169F8E, 'cmp_s	r14,0'),
    (0x169F90, 'bne_s	8	;0x169f98'),
    (0x169F92, 'mov_s	r14,0'),
    (0x169F94, 'b_s	14	;0x169fa2'),
    (0x169F96, 'add_s	r14,r14,0x8'),
    (0x169F98, 'ldw_s.x	r0,[r14,0]'),
    (0x169F9A, 'cmp_s	r1,r0'),
    (0x169F9C, 'beq_s	6	;0x169fa2'),
    (0x169F9E, 'cmp_s	r0,0'),
    (0x169FA0, 'bne_s	-10	;0x169f96'),
    (0x169FA2, 'ld_s	r3,[r14,0x4]'),
    (0x169FA4, 'cmp_s	r3,0'),
    (0x169FA6, 'bne_s	8	;0x169fac'),
    (0x169FA8, 'mov_s	r0,0'),
    (0x169FAA, 'b_s	8	;0x169fb0'),
    (0x169FAC, 'jl_s.d	[r3]'),
    (0x169FAE, 'mov_s	r0,r13'),
]

W_16A028 = [
    (0x16A028, 'push_s	blink'),
    (0x16A02A, 'bl	1876220	;0x334124'),
    (0x16A02E, 'mov_s	r13,r0'),
    (0x16A030, 'ld_s	r0,[pcl,0x104]	;0x16a134'),
    (0x16A032, 'mov_s	r17,r1'),
    (0x16A034, 'ld_s	r3,[r0,0]'),
    (0x16A036, 'cmp_s	r3,0'),
    (0x16A038, 'mov_s	r16,r2'),
    (0x16A03A, 'beq_s	8	;0x16a040'),
    (0x16A03C, 'jl_s.d	[r3]'),
    (0x16A03E, 'mov_s	r0,r13'),
    (0x16A040, 'bl.d	-151524	;0x14505c'),
    (0x16A044, 'mov_s	r0,r13'),
    (0x16A046, 'mov.f	r3,r0'),
    (0x16A04A, 'bne_s	8	;0x16a050'),
    (0x16A04C, 'mov_s	r0,0'),
    (0x16A04E, 'b_s	12	;0x16a058'),
    (0x16A050, 'mov_s	r0,r13'),
    (0x16A052, 'mov_s	r1,r17'),
    (0x16A054, 'jl_s.d	[r3]'),
    (0x16A056, 'mov_s	r2,r16'),
    (0x16A058, 'b	1876268	;0x334184'),
]

W_16A6E4 = [
    (0x16A6E4, 'push_s	blink'),
    (0x16A6E6, 'bl	1874496	;0x334124'),
    (0x16A6EA, 'mov_s	r16,r0'),
    (0x16A6EC, 'mov_s	r13,r1'),
    (0x16A6EE, 'bl.d	-151388	;0x145790'),
    (0x16A6F2, 'mov_s	r17,r2'),
    (0x16A6F4, 'mov_s	r15,r0'),
    (0x16A6F6, 'mov_s	r0,r16'),
    (0x16A6F8, 'bl.d	-153276	;0x14503c'),
    (0x16A6FC, 'mov_s	r1,0'),
    (0x16A6FE, 'btst_s	r0,0'),
    (0x16A700, 'bne_s	150	;0x16a796'),
    (0x16A702, 'cmp_s	r15,0'),
    (0x16A704, 'beq_s	146	;0x16a796'),
    (0x16A706, 'cmp	r13,128'),
    (0x16A70A, 'blt	142	;0x16a796'),
    (0x16A70E, 'cmp_s	r13,0x307f'),
    (0x16A714, 'bgt	130	;0x16a796'),
    (0x16A718, 'ld	r14,[pcl,-220]	;0x16a63c'),
    (0x16A71C, 'ldb_s	r0,[r14,0x14]'),
    (0x16A71E, 'cmp_s	r0,0'),
    (0x16A720, 'beq_s	14	;0x16a72e'),
    (0x16A722, 'mov_s	r0,r15'),
    (0x16A724, 'mov_s	r1,r13'),
    (0x16A726, 'mov_s	r2,r17'),
    (0x16A728, 'bl_s	-2480	;0x169d78'),
    (0x16A72A, 'cmp_s	r0,0'),
    (0x16A72C, 'bne_s	102	;0x16a792'),
    (0x16A72E, 'cmp_s	r13,0'),
    (0x16A730, 'ble_s	22	;0x16a746'),
    (0x16A732, 'cmp_s	r13,0x3fff'),
    (0x16A738, 'bgt_s	14	;0x16a746'),
    (0x16A742, 'asr_s	r0,r0,0x7'),
    (0x16A744, 'b_s	4	;0x16a748'),
    (0x16A746, 'mov_s	r0,0'),
    (0x16A748, 'ldb_s	r1,[r14,0x16]'),
    (0x16A74A, 'cmp_s	r0,r1'),
    (0x16A74C, 'beq_s	8	;0x16a754'),
    (0x16A74E, 'ldb_s	r2,[r14,0x17]'),
    (0x16A750, 'cmp_s	r0,r2'),
    (0x16A752, 'bne_s	70	;0x16a796'),
    (0x16A754, 'ldb_s	r0,[r14,0x15]'),
    (0x16A756, 'cmp_s	r0,0'),
    (0x16A758, 'beq_s	62	;0x16a796'),
    (0x16A75A, 'asl_s	r1,r1,0x7'),
    (0x16A75C, 'sexw_s	r0,r1'),
    (0x16A75E, 'cmp_s	r13,r0'),
    (0x16A760, 'bne_s	14	;0x16a76e'),
    (0x16A762, 'bl.d	-151152	;0x1458f0'),
    (0x16A766, 'mov_s	r0,r16'),
    (0x16A768, 'cmp_s	r0,0'),
    (0x16A76A, 'beq_s	46	;0x16a796'),
    (0x16A76C, 'b_s	38	;0x16a792'),
    (0x16A76E, 'ldb_s	r0,[r14,0x17]'),
    (0x16A770, 'asl_s	r0,r0,0x7'),
    (0x16A772, 'cmp_s	r13,r0'),
    (0x16A774, 'bne_s	14	;0x16a782'),
    (0x16A776, 'bl.d	-151148	;0x145908'),
    (0x16A77A, 'mov_s	r0,r16'),
    (0x16A77C, 'cmp_s	r0,0'),
    (0x16A77E, 'beq_s	26	;0x16a796'),
    (0x16A780, 'b_s	18	;0x16a792'),
    (0x16A782, 'bset_s	r1,r1,0'),
    (0x16A784, 'sexw_s	r1,r1'),
    (0x16A786, 'cmp_s	r13,r1'),
    (0x16A788, 'beq_s	10	;0x16a792'),
    (0x16A78A, 'bset_s	r0,r0,0'),
    (0x16A78C, 'sexw_s	r0,r0'),
    (0x16A78E, 'cmp_s	r13,r0'),
    (0x16A790, 'bne_s	6	;0x16a796'),
    (0x16A792, 'mov_s	r0,0'),
    (0x16A794, 'b_s	10	;0x16a79e'),
    (0x16A796, 'mov_s	r0,r16'),
    (0x16A798, 'mov_s	r1,r13'),
    (0x16A79A, 'mov_s	r2,r17'),
    (0x16A79C, 'bl_s	-1908	;0x16a028'),
    (0x16A79E, 'b	1874408	;0x334184'),
]

W_8101C8 = [
    (0x8101C8, 'push_s	blink'),
    (0x8101CA, 'push_s	r13'),
    (0x8101CC, 'st.aw	fp,[sp,-4]'),
    (0x8101D0, 'mov	fp,sp'),
    (0x8101D4, 'mov_s	r13,r0'),
    (0x8101D6, 'mov_s	r0,0'),
    (0x8101D8, 'ld_s	r1,[pcl,0x14]	;0x8101ec'),
    (0x8101DA, 'mov_s	r2,r13'),
    (0x8101DC, 'bl	-6972060	;0x169f40'),
]


# ---------------------------------------------------------------------------
# producer classification: every bl caller of the post APIs, event arg r1
# resolved through pool words or mov constants (frozen expectation above)
# ---------------------------------------------------------------------------
CALL_T = r'V([0-9A-F]{6,8}) \| [0-9a-f ]+\| (bl|bl\.d|bl_s|bl_s\.d)\s+?-?\d+\s+;0x(%s)\b'
INSN_RE = re.compile(r'V([0-9A-F]{6,8}) \| [0-9a-f ]+\| (\S+)\s*(.*)')


def payload_of(blocks, addr):
    for b in blocks:
        if b['load_address_candidate'] <= addr < b['load_address_candidate'] + b['size']:
            return b['index']
    return None


def classify_producers(payloads, base, blocks):
    lines = LISTING.read_text(errors='replace').splitlines()
    found = {api: {ev: [] for ev in BRIDGE_EVENTS} for api in PRODUCERS}
    counts = {}
    for api, events in PRODUCERS.items():
        pat = re.compile(CALL_T % hex(api)[2:])
        callers = []
        for i, ln in enumerate(lines):
            m = pat.search(ln)
            if m:
                callers.append((i, int(m.group(1), 16)))
        counts[api] = len(callers)
        for i, site in callers:
            ev = None
            pool = None
            for j in range(i, max(0, i - 40), -1):
                m = INSN_RE.search(lines[j])
                if not m:
                    continue
                pc = int(m.group(1), 16)
                op = m.group(2)
                args = m.group(3).strip()
                if op in ('bl', 'bl.d', 'bl_s', 'bl_s.d', 'jl', 'jl_s',
                          'jl_s.d', 'j', 'j_s') and j < i:
                    break                      # event clobbered by a call
                if op in ('mov_s', 'mov') and args.startswith('r1,'):
                    rest = args[3:].strip()
                    if re.fullmatch(r'(0x[0-9a-f]+|\d+)', rest):
                        ev = int(rest, 0)
                    break
                if op in ('ld_s', 'ld') and args.startswith('r1,') and 'pcl' in args:
                    mm = re.search(r';0x([0-9a-f]+)', args)
                    if mm:
                        paddr = int(mm.group(1), 16)
                        pidx = payload_of(blocks, paddr)
                        if pidx is not None:
                            ev = struct.unpack_from(
                                '<I', payloads[pidx], paddr - base[pidx])[0]
                            pool = (pidx, paddr)
                    break
            if ev in BRIDGE_EVENTS:
                found[api][ev].append((site,) + (pool if pool else (None, None)))
    return found, counts


# ---------------------------------------------------------------------------
# CPU case helpers (it.44 method: original windows, stubs at original
# addresses, hand-encoded 32-bit b trampolines at the cut points)
# ---------------------------------------------------------------------------
def probe(words, bytes_, success, base_marker=0xdeadcc00):
    """Probe asm: log word checks (offset, value), byte checks (addr, value),
    distinct fault markers per failed check, success fault last."""
    text = [f' mov r3,{hex(LOG_BASE)}']
    n = 0
    for off, val in words:
        text += [f' ld r4,[r3,{off}]', f' mov r5,{hex(val)}',
                 ' cmp r4,r5', f' bne bad{n}']
        n += 1
    for addr, val in bytes_:
        text += [f' mov r1,{hex(addr)}', ' ldb r2,[r1,0]',
                 f' mov r5,{hex(val)}', ' cmp r2,r5', f' bne bad{n}']
        n += 1
    text += [f' mov r5,{hex(success)}', ' ldb r0,[r5,0]']
    for k in range(n):
        text += [f'bad{k}:', f' mov r5,{hex(base_marker + k)}', ' ldb r0,[r5,0]']
    return '\n'.join(text) + '\n'


def probe_abs(word_checks, byte_checks, success, base_marker=0xdeadcd00):
    """Absolute-address word (32-bit ld) and byte checks; distinct faults."""
    text = []
    n = 0
    for addr, val in word_checks:
        text += [f' mov r1,{hex(addr)}', ' ld r4,[r1,0]',
                 f' mov r5,{hex(val)}', ' cmp r4,r5', f' bne bad{n}']
        n += 1
    for addr, val in byte_checks:
        text += [f' mov r1,{hex(addr)}', ' ldb r2,[r1,0]',
                 f' mov r5,{hex(val)}', ' cmp r2,r5', f' bne bad{n}']
        n += 1
    text += [f' mov r5,{hex(success)}', ' ldb r0,[r5,0]']
    for k in range(n):
        text += [f'bad{k}:', f' mov r5,{hex(base_marker + k)}', ' ldb r0,[r5,0]']
    return '\n'.join(text) + '\n'


def stub_ret(addr, section, retval=None, code=''):
    body = code
    if retval is not None:
        body += f' mov r0,{hex(retval)}\n'
    body += ' j_s [blink]\n'
    return (f'.section {section},"ax",@progbits\n'
            f' .org 0\n{body}')


def stub_fault(section, probe_text):
    return (f'.section {section},"ax",@progbits\n'
            f' .org 0\n{probe_text}')


def stub_order(addr, section, stub_id, retval=None, extra=''):
    """Stub that appends (id, r0) to the order log: counter at log[40],
    entries id at log[44+8k], arg r0 at log[48+8k]."""
    body = (f' mov r3,{hex(LOG_BASE)}\n'
            ' ld r4,[r3,40]\n'
            ' add r5,r4,1\n'
            ' st r5,[r3,40]\n'
            ' add r4,r4,r4\n'
            ' add r4,r4,r4\n'
            ' add r4,r4,r4\n'
            f' mov r6,{hex(44)}\n'
            ' add r6,r6,r4\n'
            ' add r6,r6,r3\n'
            f' mov r5,{hex(stub_id)}\n'
            ' st r5,[r6,0]\n'
            ' st r0,[r6,4]\n'
            + extra)
    if retval is not None:
        body += f' mov r0,{hex(retval)}\n'
    body += ' j_s [blink]\n'
    return (f'.section {section},"ax",@progbits\n'
            f' .org 0\n{body}')


def harness(entry, args):
    text = ('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            f' mov sp,{hex(STACK)}\n'
            + ''.join(f' mov r{k},{hex(v)}\n' for k, v in enumerate(args))
            + f' mov r12,{hex(entry)}\n'
            ' jl_s [r12]\n'
            f' mov r5,{hex(0xdeadee00)}\n'
            ' ldb r0,[r5,0]\n'
            '.section .stack,"aw",@nobits\n.align 16\n'
            '.space 16384\n')
    return text


def fixtures(sections):
    """sections: list of (name, bytes) -> asm text"""
    out = ''
    for name, data in sections:
        out += (f'.section {name},"aw",@progbits\n.align 4\n'
                + ''.join(f' .byte {b}\n' for b in data))
    return out


def section_bytes(words=(), size=0, fill=0):
    data = bytearray([fill] * size)
    for off, val in words:
        if isinstance(val, int) and val <= 0xFF and size:
            data[off] = val
        else:
            struct.pack_into('<I', data, off, val)
    return bytes(data)


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'event_router_producers_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, block_dir = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                    action='event-router-producers',
                    firmware_blocks=16,
                    limits=['Static analysis + 8 synthetic CPU cases; no hardware',
                            'Event classification bounded: r1 clobbered by an '
                            'intervening call is not resolved (documented)',
                            '0x4006 has no constant producer in the post APIs; '
                            'its delivery mechanism is OPEN',
                            'CPU windows are cut before the final 32-bit b: the '
                            'sim wraps the 13-bit b displacement mod 8192 '
                            '(it.44 lesson); b targets are NOT proven here',
                            'The WindowManager cycle fragment 0x15AF1C..0x15AF48 '
                            'and 0x16A6E4/0x16A028/0x14505C are static-only in '
                            'this bank (frozen windows + censuses)',
                            'V1.1 sample vs V1.0 machine; NON_INSTALLARE'])
    try:
        # --- 1. event table + trailing ids + node ---------------------------
        idx = 5
        ofs = EVENT_TABLE_BASE - base[idx]
        got = [struct.unpack_from('<II', payloads[idx], ofs + 8 * k)
               for k in range(36)]
        assert got == EVENT_TABLE + [EVENT_TABLE_TERMINATOR], got
        words = [struct.unpack_from('<I', payloads[idx],
                                    ofs + 8 * 36 + 4 * k)[0]
                 for k in range(8)]
        ids = []
        for w in words:
            ids += [w & 0xFFFF, w >> 16]
        assert ids == TRAILING_EVENT_IDS, ids
        node = [struct.unpack_from('<I', payloads[idx],
                                   (NODE - base[idx]) + 4 * k)[0]
                for k in range(8)]
        assert node == NODE_WORDS, node
        results['event_table'] = {
            'base': hex(EVENT_TABLE_BASE), 'entries': len(EVENT_TABLE),
            'terminator_at': hex(EVENT_TABLE_BASE + 8 * 35),
            'node': hex(NODE), 'node_callback_at': hex(NODE + 0xC),
            'trailing_event_ids': [hex(i) for i in TRAILING_EVENT_IDS]}

        # --- 2. pool words --------------------------------------------------
        for (pidx, addr), value in POOLS.items():
            got = struct.unpack_from('<I', payloads[pidx], addr - base[pidx])[0]
            assert got == value, (pidx, hex(addr), hex(got))
        results['pool_words'] = {f'{i}:{hex(a)}': hex(v)
                                 for (i, a), v in POOLS.items()}

        # --- 3. bl censuses --------------------------------------------------
        got_census = census(list(CENSUS_EXPECT))
        for target, expect in CENSUS_EXPECT.items():
            assert got_census[target] == expect, (hex(target), got_census[target])
        results['bl_censuses'] = {hex(t): [hex(x) for x in e]
                                  for t, e in CENSUS_EXPECT.items()}

        # --- 4. LE scans ------------------------------------------------------
        for value, expect in LE_EXPECT.items():
            hits = le_scan(payloads, base, value)
            assert sorted((i, a) for i, a, _ in hits) == sorted(expect), (
                hex(value), hits)
            for _, _, align in hits:
                assert align == 0
        results['le_scans'] = {hex(v): [(i, hex(a)) for i, a in e]
                               for v, e in LE_EXPECT.items()}

        # --- 5. producer classification ---------------------------------------
        found, counts = classify_producers(payloads, base, blocks)
        assert counts == API_CALLER_COUNTS, counts
        for api, events in PRODUCERS.items():
            for ev, expect in events.items():
                got = sorted((s, p, a) for s, p, a in found[api][ev])
                want = sorted(expect)
                assert got == want, (hex(api), hex(ev), got)
            # no bridge event outside the frozen lists
            for ev in BRIDGE_EVENTS:
                if ev not in events:
                    assert found[api][ev] == [], (hex(api), hex(ev))
        for ev in NO_PRODUCER_EVENTS:
            for api in PRODUCERS:
                hits = [s for s, p, a in found[api].get(ev, [])
                        ] if ev in found[api] else []
                assert hits == [], (hex(api), hex(ev))
        # byte-exact pool words at every producer site
        for api, events in PRODUCERS.items():
            for ev, sites in events.items():
                for site, pidx, paddr in sites:
                    got = struct.unpack_from(
                        '<I', payloads[pidx], paddr - base[pidx])[0]
                    assert got == ev, (hex(site), pidx, hex(paddr), hex(got))
        # 0x4006 broadcast hint: word occurrences in payload5 window tables
        p5_4006 = le_scan(payloads, base, 0x4006)
        p5_4006_addrs = sorted(a for i, a, _ in p5_4006 if i == 5)
        assert p5_4006_addrs == P5_4006_TABLE_WORDS, p5_4006_addrs
        results['producers'] = {
            hex(api): {hex(ev): [hex(s) for s, p, a in sites]
                       for ev, sites in events.items()}
            for api, events in PRODUCERS.items()}
        results['api_caller_counts'] = {hex(k): v for k, v in counts.items()}
        results['no_producer_events'] = [hex(e) for e in NO_PRODUCER_EVENTS]
        results['p5_4006_table_words'] = [hex(a) for a in P5_4006_TABLE_WORDS]

        # --- 6. frozen objdump windows ---------------------------------------
        for tag, spec in (('W_169EB4', (0, 0x169EB4, 0x169EFA, 'W_169EB4')),
                          ('W_17BC7C', (0, 0x17BC7C, 0x17BCDE, 'W_17BC7C')),
                          ('W_17BD4C', (0, 0x17BD4C, 0x17BD90, 'W_17BD4C')),
                          ('W_169E1C', (0, 0x169E1C, 0x169E96, 'W_169E1C')),
                          ('W_1453F4', (0, 0x1453F4, 0x1453FA, 'W_1453F4')),
                          ('W_169F60', (0, 0x169F60, 0x169FB0, 'W_169F60')),
                          ('W_16A028', (0, 0x16A028, 0x16A05C, 'W_16A028')),
                          ('W_16A6E4', (0, 0x16A6E4, 0x16A7A2, 'W_16A6E4')),
                          ('W_8101C8', (4, 0x8101C8, 0x8101E0, 'W_8101C8'))):
            pidx, lo, hi, lit = spec
            got = window_lines(payloads[pidx], base[pidx], lo, hi)
            expect = dict(globals()[lit])
            assert got == expect, tag
        results['frozen_windows'] = [t for t, _ in (
            ('W_169EB4', 0), ('W_17BC7C', 0), ('W_17BD4C', 0),
            ('W_169E1C', 0), ('W_1453F4', 0), ('W_169F60', 0),
            ('W_16A028', 0), ('W_16A6E4', 0), ('W_8101C8', 0))]

        # --- 7. raw original bytes of the CPU windows ------------------------
        router = raw_window(payloads, base, ROUTER_BYTES)
        handler = raw_window(payloads, base, HANDLER_B_BYTES)
        table = raw_window(payloads, base, TABLE_DATA)
        nodedata = raw_window(payloads, base, NODE_DATA)
        results['router_window'] = dict(sha256=hashlib.sha256(router).hexdigest(),
                                        size=len(router),
                                        lo=hex(ROUTER_BYTES['lo']),
                                        hi=hex(ROUTER_BYTES['hi']))
        results['handler_window'] = dict(sha256=hashlib.sha256(handler).hexdigest(),
                                         size=len(handler))
        assert len(router) == 0x204 and len(handler) == 0x5A
        assert struct.pack('<I', 0x7F871C) in table[:8 * 33 + 8]
        # handler registered at the 0x3181 table slot
        k3181 = EVENT_TABLE.index((0x3181, 0x7F871C))
        assert struct.unpack_from('<II', table, 8 * k3181) == (0x3181, 0x7F871C)
        assert struct.unpack_from('<I', nodedata, 0xC)[0] == NODE_CALLBACK

        # --- 8. CPU cases ------------------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
                                   output=out, action='event-router-producers'))
        r.prepare()
        r.results.update(static_pass=results)
        cases = []

        def build_case(name, asm_text, orig_windows, ld_extra):
            """orig_windows: (payload_idx, lo, hi, section, patch_words|None)"""
            s = out / f'{name}.s'
            s.write_text(asm_text)
            obj = out / f'{name}.o'
            assert r.command(f'{name}_as', [
                TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL',
                '-o', obj, s]).returncode == 0
            bin_objs = []
            for (pidx, lo, hi, section, patch) in orig_windows:
                data = bytearray(payloads[pidx][lo - base[pidx]: hi - base[pidx]])
                if patch:
                    for off, val in patch:
                        struct.pack_into('<I', data, off, val)
                orig = out / f'{name}_{section}.bin'
                orig.write_bytes(data)
                bo = out / f'{name}_{section}_bin.o'
                assert r.command(f'{name}_{section}_oc', [
                    TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary',
                    '-O', 'elf32-littlearc', '-B', 'arc',
                    '--rename-section',
                    f'.data={section},alloc,load,readonly,code,contents',
                    '--change-section-vma', f'.data={hex(lo)}',
                    '--strip-all', orig, bo]).returncode == 0
                bin_objs.append(bo)
            elf = out / f'{name}.elf'
            ld = out / f'{name}.ld'
            ld.write_text(
                'ENTRY(_start)\n'
                'SECTIONS {\n'
                '  .text 0x1000 : { *(.text .text.*) }\n'
                + ''.join(f'  {section} {hex(lo)} : {{ *({section}) }}\n'
                          for (_, lo, _, section, _) in orig_windows)
                + ld_extra +
                '  .stack 0xC8F000 (NOLOAD) : { *(.stack .stack.*) }\n'
                '}\n')
            cmd = [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-T', ld, '-o', elf,
                   obj] + bin_objs
            assert r.command(f'{name}_ld', cmd).returncode == 0
            ep, segments = elf_loads(elf)
            assert ep == 0x1000, hex(ep)
            for (pidx, lo, hi, section, patch) in orig_windows:
                want = bytearray(payloads[pidx][lo - base[pidx]:
                                               hi - base[pidx]])
                if patch:
                    for off, val in patch:
                        struct.pack_into('<I', want, off, val)
                by = [seg for seg in segments
                      if seg['address'] <= lo
                      and lo + (hi - lo) <= seg['address'] + seg['size']]
                assert len(by) == 1, (hex(lo), segments)
                seg = by[0]
                data = seg['data'][lo - seg['address']:]
                assert data[:hi - lo] == bytes(want), hex(lo)
            case, sim_text = r.run(name, '/result/' + f'{name}.elf')
            return case, sim_text

        LOG128 = bytes(128)
        HOOKS = section_bytes(size=16)                      # 0x367800..0x367810
        CUR_NODE = lambda v: section_bytes(words=[(0, v)], size=4)
        QIDX = lambda rd, wr: bytes([rd & 0xFF, (rd >> 8) & 0xFF,
                                     wr & 0xFF, (wr >> 8) & 0xFF])
        GUARD16 = bytes([0xA5] * 16)

        def ctx_bytes(cell):
            d = bytearray(0xA5 for _ in range(0x40))
            struct.pack_into('<I', d, 0x0C, 0x6005)
            d[0x22] = 0xA5
            d[0x34] = cell
            return bytes(d)

        def saved_bytes(desired=0x2C):
            d = bytearray(0xA5 for _ in range(0x20))
            d[8] = desired
            return bytes(d)

        # ---- case 1/2: post wrappers + ring insert ------------------------
        for cname, qfix, recfix, expect in (
                ('post3181', QIDX(0, 0), bytes(16), 'insert'),
                ('post3181_overflow', QIDX(0, 0x7F), bytes([0xA5] * 16),
                 'overflow')):
            asm = harness(0x169EB4, [0, 0x3181, 0x77])
            if expect == 'insert':
                sig = probe_abs(
                    word_checks=[(RECORDS, 0), (RECORDS + 8, 0x77)],
                    byte_checks=[(RECORDS + 4, 0x81), (RECORDS + 5, 0x31),
                                 (QUEUE, 0), (QUEUE + 1, 0),
                                 (QUEUE_WRITE, 1), (QUEUE_WRITE + 1, 0)],
                    success=0xDEADA201)
                stubs = (stub_ret(0x1593AC, '.stub_1593ac', retval=1) +
                         stub_ret(0x1786E8, '.stub_1786e8', retval=0) +
                         stub_ret(0x179354, '.stub_179354', retval=0) +
                         stub_fault('.stub_158cbc', sig))
                ld_extra = ''
                success = 0xDEADA201
                orig = [(0, 0x169EB4, 0x169EFA, '.origeb4', None),
                        (0, 0x17BC7C, 0x17BCDE, '.origpost', None),
                        (0, 0x334120, 0x33413A, '.origpro', None),
                        (0, 0x16A128, 0x16A138, '.pools16a', None),
                        (0, 0x17BFF4, 0x17C004, '.pools17b', None)]
                fix = [('.log', LOG128), ('.hooks', HOOKS), ('.q', qfix),
                       ('.rec', recfix)]
                ld_fix = ('  .log 0x367000 : { *(.log) }\n'
                          '  .hooks 0x367800 : { *(.hooks) }\n'
                          f'  .q {hex(QUEUE)} : {{ *(.q) }}\n'
                          f'  .rec {hex(RECORDS)} : {{ *(.rec) }}\n'
                          '  .stub_1593ac 0x1593AC : { *(.stub_1593ac) }\n'
                          '  .stub_1786e8 0x1786E8 : { *(.stub_1786e8) }\n'
                          '  .stub_179354 0x179354 : { *(.stub_179354) }\n'
                          '  .stub_158cbc 0x158CBC : { *(.stub_158cbc) }\n')
            else:
                # overflow: the signal stub must NOT run; the flow reaches the
                # tail cut of 0x17BC7C -> probe at 0x17BCE4
                sig = probe_abs(
                    word_checks=[(RECORDS, 0xA5A5A5A5),
                                 (RECORDS + 8, 0xA5A5A5A5)],
                    byte_checks=[(RECORDS + 4, 0xA5), (RECORDS + 5, 0xA5),
                                 (QUEUE, 0), (QUEUE + 1, 0),
                                 (QUEUE_WRITE, 0x7F), (QUEUE_WRITE + 1, 0)],
                    success=0xDEADA202)
                d = 0x17BCE4 - (0x17BCDE & ~3)
                w = d + 1
                tramp = ('.section .landing,"ax",@progbits\n'
                         f' .byte {w & 0xFF}\n .byte {w >> 8}\n'
                         ' .byte 0\n .byte 0\n'
                         ' .byte 0xe0\n .byte 0x78\n'
                         '.section .probe,"ax",@progbits\n' + sig)
                stubs = (stub_ret(0x1593AC, '.stub_1593ac', retval=1) +
                         stub_ret(0x1786E8, '.stub_1786e8', retval=0) +
                         stub_ret(0x179354, '.stub_179354', retval=0) +
                         stub_fault('.stub_158cbc',
                                    f' mov r5,{hex(0xDEADEE01)}\n'
                                    ' ldb r0,[r5,0]\n'))
                ld_extra = ('  .landing 0x17BCDE : { *(.landing) }\n'
                            '  .probe 0x17BCE4 : { *(.probe) }\n')
                success = 0xDEADA202
                orig = [(0, 0x169EB4, 0x169EFA, '.origeb4', None),
                        (0, 0x17BC7C, 0x17BCDE, '.origpost', None),
                        (0, 0x334120, 0x33413A, '.origpro', None),
                        (0, 0x16A128, 0x16A138, '.pools16a', None),
                        (0, 0x17BFF4, 0x17C004, '.pools17b', None)]
                fix = [('.log', LOG128), ('.hooks', HOOKS), ('.q', qfix),
                       ('.rec', recfix)]
                ld_fix = ('  .log 0x367000 : { *(.log) }\n'
                          '  .hooks 0x367800 : { *(.hooks) }\n'
                          f'  .q {hex(QUEUE)} : {{ *(.q) }}\n'
                          f'  .rec {hex(RECORDS)} : {{ *(.rec) }}\n'
                          '  .stub_1593ac 0x1593AC : { *(.stub_1593ac) }\n'
                          '  .stub_1786e8 0x1786E8 : { *(.stub_1786e8) }\n'
                          '  .stub_179354 0x179354 : { *(.stub_179354) }\n'
                          '  .stub_158cbc 0x158CBC : { *(.stub_158cbc) }\n')
            asm = harness(0x169EB4, [0, 0x3181, 0x77]) + stubs
            if expect == 'overflow':
                asm += tramp
            asm += fixtures(fix)
            case, sim_text = build_case(cname, asm, orig, ld_extra + ld_fix)
            assert case['exit_code'] == 11, sim_text
            assert case['fault'] is not None
            assert int(case['fault']['address'], 16) == success, case['fault']
            case.update(expected=hex(success), original_bytes=True)
            cases.append(case)

        # ---- case 3/4: extract ---------------------------------------------
        for cname, qfix, recword, expect in (
                ('extract3181', QIDX(0, 1), (0, 0x3181, 0x77), 'ok'),
                ('extract3181_empty', QIDX(0, 0), None, 'empty')):
            buf = bytes([0xA5] * 24)
            if expect == 'ok':
                rec = bytearray(16)
                struct.pack_into('<H', rec, 4, 0x3181)
                struct.pack_into('<I', rec, 8, 0x77)
                recfix = bytes(rec)
                ptxt = probe_abs(
                    word_checks=[(BUF, 0), (BUF + 8, 0x77)],
                    byte_checks=[(BUF + 4, 0x81), (BUF + 5, 0x31),
                                 (BUF + 6, 0xA5), (BUF + 7, 0xA5),
                                 (QUEUE, 1), (QUEUE + 1, 0),
                                 (QUEUE_WRITE, 1), (QUEUE_WRITE + 1, 0)],
                    success=0xDEADA301)
                success = 0xDEADA301
                stubs = stub_ret(0x1593AC, '.stub_1593ac', retval=1)
            else:
                recfix = bytes(16)
                ptxt = probe(
                    words=[(0, 1)],
                    bytes_=[(BUF, 0xA5), (BUF + 1, 0xA5), (BUF + 2, 0xA5),
                            (BUF + 3, 0xA5), (BUF + 8, 0xA5), (BUF + 9, 0xA5),
                            (BUF + 10, 0xA5), (BUF + 11, 0xA5),
                            (QUEUE, 0), (QUEUE_WRITE, 0)],
                    success=0xDEADA401)
                success = 0xDEADA401
                stubs = (stub_ret(0x1593AC, '.stub_1593ac', retval=0) +
                         stub_ret(0x1594A4, '.stub_1594a4', retval=0,
                                  code=f' mov r3,{hex(LOG_BASE)}\n'
                                       ' ld r4,[r3,0]\n add r4,r4,1\n'
                                       ' st r4,[r3,0]\n'))
            d = 0x17BD98 - (0x17BD90 & ~3)
            w = d + 1
            tramp = ('.section .landing,"ax",@progbits\n'
                     f' .byte {w & 0xFF}\n .byte {w >> 8}\n'
                     ' .byte 0\n .byte 0\n'
                     ' .byte 0xe0\n .byte 0x78\n'
                     '.section .probe,"ax",@progbits\n' + ptxt)
            asm = (harness(0x17BD4C, [BUF]) + stubs + tramp +
                   fixtures([('.log', LOG128), ('.hooks', HOOKS),
                             ('.q', qfix), ('.rec', recfix), ('.buf', buf)]))
            ld_extra = ('  .landing 0x17BD90 : { *(.landing) }\n'
                        '  .probe 0x17BD98 : { *(.probe) }\n'
                        '  .log 0x367000 : { *(.log) }\n'
                        '  .hooks 0x367800 : { *(.hooks) }\n'
                        f'  .q {hex(QUEUE)} : {{ *(.q) }}\n'
                        f'  .rec {hex(RECORDS)} : {{ *(.rec) }}\n'
                        f'  .buf {hex(BUF)} : {{ *(.buf) }}\n'
                        '  .stub_1593ac 0x1593AC : { *(.stub_1593ac) }\n'
                        '  .stub_1594a4 0x1594A4 : { *(.stub_1594a4) }\n')
            case, sim_text = build_case(
                cname, asm,
                [(0, 0x17BD4C, 0x17BD90, '.origext', None),
                 (0, 0x334120, 0x33413A, '.origpro', None),
                 (0, 0x17BFF4, 0x17C004, '.pools17b', None)], ld_extra)
            assert case['exit_code'] == 11, sim_text
            assert int(case['fault']['address'], 16) == success, case['fault']
            case.update(expected=hex(success), original_bytes=True)
            cases.append(case)

        # ---- case 5/6: 0x169E1C resolve current node -----------------------
        for cname, cur, expect in (
                ('resolve3181', NODE, 'ok'),
                ('resolve3181_none', 0, 'none')):
            d = 0x169F00 - (0x169E96 & ~3)
            w = d + 1
            if expect == 'ok':
                ptxt = probe(
                    words=[(0, NODE), (4, 0x3181), (8, 0x77)],
                    bytes_=[(NODE + 0xC, 0x24), (NODE + 0xD, 0x68),
                            (NODE + 0xE, 0x7F), (NODE + 0xF, 0)],
                    success=0xDEADA501)
                stubs = stub_ret(
                    0x169D78, '.stub_169d78', retval=0x5A,
                    code=f' mov r3,{hex(LOG_BASE)}\n st r0,[r3,0]\n'
                         ' st r1,[r3,4]\n st r2,[r3,8]\n')
                success = 0xDEADA501
            else:
                ptxt = probe(words=[(0, 0), (4, 0), (8, 0)],
                             bytes_=[], success=0xDEADA601)
                stubs = stub_fault('.stub_169d78',
                                  f' mov r5,{hex(0xDEADEE02)}\n'
                                  ' ldb r0,[r5,0]\n')
                success = 0xDEADA601
            tramp = ('.section .landing,"ax",@progbits\n'
                     f' .byte {w & 0xFF}\n .byte {w >> 8}\n'
                     ' .byte 0\n .byte 0\n'
                     ' .byte 0xe0\n .byte 0x78\n'
                     '.section .probe,"ax",@progbits\n' + ptxt)
            asm = (harness(0x169E1C, [0, 0x3181, 0x77]) + stubs + tramp +
                   fixtures([('.log', LOG128), ('.hooks', HOOKS),
                             ('.curnode', CUR_NODE(cur))]))
            ld_extra = ('  .landing 0x169E96 : { *(.landing) }\n'
                        '  .probe 0x169F00 : { *(.probe) }\n'
                        '  .log 0x367000 : { *(.log) }\n'
                        '  .hooks 0x367800 : { *(.hooks) }\n'
                        f'  .curnode {hex(CUR_NODE_CELL)} : {{ *(.curnode) }}\n'
                        '  .stub_169d78 0x169D78 : { *(.stub_169d78) }\n')
            orig = [(0, 0x169E1C, 0x169E96, '.orig169e1c', None),
                    (0, 0x1453F4, 0x1453FA, '.origcur', None),
                    (0, 0x334120, 0x33413A, '.origpro', None),
                    (0, 0x16A128, 0x16A138, '.pools16a', None),
                    (0, 0x14579C, 0x1457A0, '.pool14579c', None),
                    (5, NODE, NODE + 0x20, '.nodedata', None)]
            case, sim_text = build_case(cname, asm, orig, ld_extra)
            assert case['exit_code'] == 11, sim_text
            assert int(case['fault']['address'], 16) == success, case['fault']
            case.update(expected=hex(success), original_bytes=True)
            cases.append(case)

        # ---- case 7/8: router -> 0x169F60 -> handler (bridge) --------------
        # 0x135A84 has only 12 bytes before 0x135A90: pure return stub,
        # its (constant 0) argument is not logged
        order_expect = [(0x137774, 0), (0x135A90, 0x10),
                        (0x7F936C, 0), (0xD1644, 1), (0xCA404, 0x2C),
                        (0xCB5E4, 7), (0x20E814, 0x6001)]
        stubs_d = (
            stub_order(0x137774, '.stub_137774', 0x137774, retval=0) +
            stub_ret(0x135A84, '.stub_135a84', retval=0) +
            stub_order(0x135A90, '.stub_135a90', 0x135A90, retval=0) +
            stub_order(0x7F936C, '.stub_7f936c', 0x7F936C, retval=0) +
            stub_order(0xD1644, '.stub_d1644', 0xD1644, retval=0) +
            stub_order(0xCA404, '.stub_ca404', 0xCA404, retval=0) +
            stub_order(0xCB5E4, '.stub_cb5e4', 0xCB5E4, retval=0) +
            stub_order(0x20E814, '.stub_20e814', 0x20E814, retval=0,
                       extra=f' mov r3,{hex(LOG_BASE)}\n st r0,[r3,28]\n'
                             ' st r1,[r3,32]\n st r2,[r3,36]\n'))
        for cname, blocked, success in (
                ('dispatch3181', False, 0xDEADA701),
                ('dispatch3181_blocked', True, 0xDEADA801)):
            words = [(40, len(order_expect))]
            for k, (sid, sarg) in enumerate(order_expect):
                words += [(44 + 8 * k, sid), (48 + 8 * k, sarg)]
            words += [(28, 0x6001), (32, 0x3181), (36, 0x77)]
            if blocked:
                # no stub may run: order counter zero, all slots zero,
                # guard sentinel intact, router store happened
                words = [(40, 0)] + [(44 + 8 * k, 0) for k in range(4)]
                pbytes = [(GUARD_CELL, 0xA5), (BRIDGE_CELL, 7),
                          (0x89A322, 0), (0x89A323, 0xA5)]
            else:
                pbytes = [(GUARD_CELL, 7), (GUARD_CELL - 1, 0xA5),
                          (GUARD_CELL + 1, 0xA5), (SAVED_GUARD_CELL, 0xA5),
                          (BRIDGE_CELL, 7), (0x89A32F, 0xA5),
                          (0x89A331, 0xA5), (0x89A322, 0)]
            ptxt = probe(words=words, bytes_=pbytes, success=success)
            if blocked:
                # probe at the 0x169F60 tail cut: no epilogue emulation, the
                # checks run there and fault (the router tail is never
                # reached, so its cut stays a plain data hole)
                d = 0x169FB4 - (0x169FB0 & ~3)
                w = d + 1
                tramp = ('.section .landing,"ax",@progbits\n'
                         f' .byte {w & 0xFF}\n .byte {w >> 8}\n'
                         ' .byte 0\n .byte 0\n'
                         '.section .probe,"ax",@progbits\n' + ptxt)
                ld_extra = ('  .landing 0x169FB0 : { *(.landing) }\n'
                            '  .probe 0x169FB4 : { *(.probe) }\n')
            else:
                d = 0x7F8780 - (0x7F8776 & ~3)
                w = d + 1
                tramp = ('.section .landing,"ax",@progbits\n'
                         f' .byte {w & 0xFF}\n .byte {w >> 8}\n'
                         ' .byte 0\n .byte 0\n'
                         ' .byte 0xe0\n .byte 0x78\n'
                         '.section .probe,"ax",@progbits\n' + ptxt)
                ld_extra = ('  .landing 0x7F8776 : { *(.landing) }\n'
                            '  .probe 0x7F8780 : { *(.probe) }\n')
            patch = None
            if blocked:
                patch = [(0x99ACAC - 0x99AB8C, 0x04813181)]
            asm = (harness(0x7F6824, [0x6001, 0x3181, 0x77]) + stubs_d +
                   tramp +
                   fixtures([('.log', LOG128), ('.hooks', HOOKS),
                             ('.ctx', ctx_bytes(7)),
                             ('.saved', saved_bytes()),
                             ('.guard', GUARD16)]))
            ld_extra += ('  .log 0x367000 : { *(.log) }\n'
                         '  .hooks 0x367800 : { *(.hooks) }\n'
                         '  .ctx 0x89A2FC : { *(.ctx) }\n'
                         '  .saved 0x3657C0 : { *(.saved) }\n'
                         '  .guard 0x365750 : { *(.guard) }\n'
                         '  .tabledata 0x99AB8C : { *(.tabledata) }\n'
                         '  .stub_137774 0x137774 : { *(.stub_137774) }\n'
                         '  .stub_135a84 0x135A84 : { *(.stub_135a84) }\n'
                         '  .stub_135a90 0x135A90 : { *(.stub_135a90) }\n'
                         '  .stub_7f936c 0x7F936C : { *(.stub_7f936c) }\n'
                         '  .stub_d1644 0xD1644 : { *(.stub_d1644) }\n'
                         '  .stub_ca404 0xCA404 : { *(.stub_ca404) }\n'
                         '  .stub_cb5e4 0xCB5E4 : { *(.stub_cb5e4) }\n'
                         '  .stub_20e814 0x20E814 : { *(.stub_20e814) }\n')
            orig = [(4, 0x7F6824, 0x7F6A28, '.origrouter', None),
                    (4, 0x7F6A2C, 0x7F6A50, '.poolrouter', None),
                    (0, 0x169F60, 0x169FB0, '.orig169f60', None),
                    (4, 0x7F871C, 0x7F8776, '.origb', None),
                    (4, 0x7F86BC, 0x7F86C0, '.poola', None),
                    (0, 0xD04C8, 0xD0534, '.origgetters', None),
                    (0, 0xCA2F4, 0xCA310, '.origsetter', None),
                    (0, 0x334120, 0x33413A, '.origpro', None),
                    (5, 0x99AB8C, 0x99ACCC, '.tabledata', patch)]
            case, sim_text = build_case(cname, asm, orig, ld_extra)
            assert case['exit_code'] == 11, sim_text
            assert int(case['fault']['address'], 16) == success, case['fault']
            case.update(expected=hex(success), original_bytes=True,
                        blocked=blocked)
            cases.append(case)

        results['cpu_cases'] = cases
        assert len(cases) == 8, len(cases)
        results['status'] = 'PASS'
        results['verdict'] = 'PASS_EVENT_ROUTER_PRODUCERS'
        print('PASS_EVENT_ROUTER_PRODUCERS', stamp)
    except AssertionError as exc:
        results['status'] = 'FAIL'
        results['error'] = repr(exc)
        print('FAIL:', exc, flush=True)
        raise
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')
        if results['status'] == 'PASS':
            latest = ROOT / 'Risultati/GUI_S33/event_router_producers_latest.json'
            latest.write_text(json.dumps(results, indent=2, default=str) + '\n')
        print('Evidence:', out / 'verified_evidence.json')


if __name__ == '__main__':
    main()
