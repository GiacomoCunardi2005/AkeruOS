#!/usr/bin/env python3
"""Scanner 0x580 -> controllo classe 9 -> conferma ISO, con RAM sintetica."""
import struct
import sys
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_iso_lifecycle_cpu as life
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer
from s33_trace_state_dispatch import verified_payloads
from s33_run_gnu_arc700 import ROOT


def main():
    assert sys.argv[1:] in ([], ['--all-iso'])
    converted = [0, 50, 64, 80, 100, 120, 125, 140, 160, 200, 250, 280,
                 320, 400, 500, 640, 800, 1000, 1250, 1600, 2000, 2500, 3200]
    selections = ([(0, 6, 555)] + [(i+1, i, value) for i, value in enumerate(converted)]
                  if sys.argv[1:] else [(0, 6, 555), (1, 0, 0), (7, 6, 125), (20, 19, 1600)])
    blocks, payloads, _ = verified_payloads(ROOT)
    block = next(b for b in blocks if b['index'] == 5)
    offset = 0x989F84 - block['load_address_candidate']
    raw = payloads[5]
    assert struct.unpack_from('<I', raw, offset)[0] == 0x37
    assert struct.unpack_from('<I', raw, offset+4)[0] == 0x94801
    assert struct.unpack_from('<I', raw, offset+0x14)[0] == 0x2D0000
    specs = []
    for base in life.build_specs():
        if not base['name'].endswith('_busy0'):
            continue
        for selected, index, value in selections:
            for enabled in ((1,) if sys.argv[1:] else (0, 1)):
                extra = base['extra'] + fan.write_word(0x365787, 88, 'stb')
                extra += fan.write_word(0x37FBF2, 555, 'sth') + dispatch_buffer(1)
                extra += (f' mov r0,{hex(queue.BUF+32)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
                          + dispatch_buffer(2))
                for addr, val, op in [(0x366E94, 0x77F728, 'st'), (0x366E98, 22, 'sth'),
                                      (0x366EA0, 0, 'sth'), (0x366EAC, 0x367700, 'st'),
                                      (0x367814, 1, 'stb'), (0x367700, 0x37, 'st'),
                                      (0x367704, 0x94801, 'st'), (0x367708, 0x989FCC, 'st'),
                                      (0x367714, 0x2D0000 if enabled else 0x0D0000, 'st'),
                                      (0x367726, selected, 'stb'), (0x446836, 1, 'sth')]:
                    extra += fan.write_word(addr, val, op)
                extra += km.scanner_asm(1 << 12, 0) + km.scanner_asm(0, 0)
                for i in (3, 4):
                    extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
                extra += dispatch_buffer(3) + dispatch_buffer(4)
                checks = [(a, w, 5 if a in (queue.QUEUE, queue.QUEUE+2, 0x367368) else v)
                          for a, w, v in base['checks']]
                checks = [(a, w, 2 if a == km.C150_COUNT else v) for a, w, v in checks]
                changed = enabled and selected != 0
                checks += [(0x365787, 1, index if changed else 88),
                           (0x367BC8, 1, index if changed else 6),
                           (0x37FBF2, 2, value if changed else 555),
                           (0x367630, 4, 1), (0x367640, 4, enabled),
                           (queue.BUF+48, 4, 0), (queue.BUF+52, 2, 0x580),
                           (queue.BUF+64, 4, 0), (queue.BUF+68, 2, 0x581)]
                checks += km.c150_entry(1, 2, 1, 0x580, 0x581)
                pcs = base['trace'] + ['0x145020', '0x6406d8', '0x640f60', '0x640fd8']
                if enabled:
                    pcs += ['0x640fa6', '0x7d25b0', '0x6410f4']
                if changed:
                    pcs += ['0x0d03b8', '0x17c320', '0x0de78c']
                absent = [] if changed else ['0x0d03b8', '0x17c320', '0x0de78c']
                if not enabled:
                    absent += ['0x640fa6', '0x7d25b0']
                observed_event = 0x4801 if enabled else 0x5000 + selected
                specs.append(dict(name=f'{base["name"]}_sel{selected}_enabled{enabled}',
                                  extra=extra, checks=checks, trace=pcs, trace_absent=absent,
                                  trace_counts=[('0x1453e4', 2 if enabled else 1)],
                                  trace_values=base['trace_values'] + [
                                      ('0x169e12', 'cr16 <- 0x580'),
                                      ('0x169e12', 'cr16 <- 0x581'),
                                      ('0x169e12', f'cr16 <- {hex(observed_event)}')],
                                  success=0xDEAD6100+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True,
             table=True, shared=True, handler700=True, manager700=True,
             lifecycle_real=True, iso_confirm=True, control_confirm=True)


if __name__ == '__main__':
    main()
