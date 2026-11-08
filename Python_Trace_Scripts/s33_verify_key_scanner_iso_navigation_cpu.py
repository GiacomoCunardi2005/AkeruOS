#!/usr/bin/env python3
"""Navigazione classe 9 originale e conferma ISO dopo scanner emulato."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_iso_lifecycle_cpu as life
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer
from s33_verify_key_scanner_control_confirm_cpu import verified_payloads, ROOT
import struct


def snapshot_byte(addr, destination):
    return f' mov r1,{hex(addr)}\n ldb r0,[r1,0]\n mov r1,{hex(destination)}\n st r0,[r1,0]\n'


def main():
    blocks, payloads, _ = verified_payloads(ROOT)
    block = next(b for b in blocks if b['index'] == 5)
    offset = 0x989F84 - block['load_address_candidate']
    assert struct.unpack_from('<II', payloads[5], offset) == (0x37, 0x94801)
    assert struct.unpack_from('<I', payloads[5], offset + 0x14)[0] == 0x2D0000
    specs = []
    for base in life.build_specs():
        if not base['name'].endswith('_busy0'):
            continue
        for bit, key, target, index, iso in [(20, 7, 6, 5, 120), (16, 8, 8, 7, 140)]:
            for enabled in (0, 1):
                chosen = target if enabled else 7
                idx, value = (index, iso) if enabled else (6, 125)
                extra = base['extra'] + fan.write_word(0x365787, 88, 'stb')
                extra += fan.write_word(0x37FBF2, 555, 'sth') + dispatch_buffer(1)
                extra += (f' mov r0,{hex(queue.BUF+32)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
                          + dispatch_buffer(2))
                for addr, val, op in [(0x366E94, 0x77F728, 'st'), (0x366E98, 22, 'sth'),
                                      (0x366EA0, 0, 'sth'), (0x366EAC, 0x367700, 'st'),
                                      (0x367814, 1, 'stb'), (0x367700, 0x37, 'st'),
                                      (0x367704, 0x94801, 'st'), (0x367708, 0x989FCC, 'st'),
                                      (0x367714, 0x2D0000 if enabled else 0x290000, 'st'),
                                      (0x446808+4*key+2, 1, 'sth'), (0x446836, 1, 'sth')]:
                    extra += fan.write_word(addr, val, op)
                extra += snapshot_byte(0x367726, 0x367680)
                extra += km.scanner_asm(1 << bit, 0) + km.scanner_asm(0, 0)
                for i in (3, 4):
                    extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
                extra += dispatch_buffer(3) + dispatch_buffer(4)
                extra += snapshot_byte(0x367726, 0x367684)
                extra += km.scanner_asm(1 << 12, 0) + km.scanner_asm(0, 0)
                for i in (5, 6):
                    extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
                extra += dispatch_buffer(5) + dispatch_buffer(6)
                checks = [(a, w, 7 if a in (queue.QUEUE, queue.QUEUE+2, 0x367368) else 3 if a == km.C150_COUNT else v)
                          for a, w, v in base['checks'] if a not in (0x36760C, 0x367610, 0x367614)]
                checks += [(0x367680, 4, 7), (0x367684, 4, chosen),
                           (0x367726, 1, chosen), (0x365787, 1, idx),
                           (0x367BC8, 1, idx), (0x37FBF2, 2, value),
                           (0x367648, 4, 2 if enabled else 1),
                           (queue.BUF+52, 2, key << 7),
                           (queue.BUF+68, 2, (key << 7) | 1),
                           (queue.BUF+84, 2, 0x580), (queue.BUF+100, 2, 0x581)]
                checks += km.c150_entry(1, 2, 1, key << 7, (key << 7) | 1)
                checks += km.c150_entry(2, 2, 1, 0x580, 0x581)
                helper = '0x6413a0' if key == 7 else '0x641314'
                pcs = base['trace'] + ['0x641064', '0x640e64', '0x641174',
                                      '0x640ee4', '0x640f60', '0x7d25b0',
                                      '0x0d03b8', '0x17c320', '0x0de78c']
                if enabled:
                    pcs.append(helper)
                specs.append(dict(name=f'{base["name"]}_key{key}_enabled{enabled}',
                                  extra=extra, checks=checks, trace=pcs,
                                  trace_absent=[] if enabled else ['0x641314', '0x6413a0'],
                                  trace_counts=[('0x641064', 2 if enabled else 1)],
                                  trace_values=base['trace_values'] + [
                                      ('0x169e12', f'cr16 <- {hex(key << 7)}'),
                                      ('0x169e12', f'cr16 <- {hex((key << 7) | 1)}'),
                                      ('0x169e12', 'cr16 <- 0x4801')],
                                  success=0xDEAD7100+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True,
             table=True, shared=True, handler700=True, manager700=True,
             lifecycle_real=True, iso_confirm=True, control_confirm=True, navigation=True)


if __name__ == '__main__':
    main()
