#!/usr/bin/env python3
"""Snapshot MMIO sintetico -> input originale -> dispatcher -> menu C."""
import struct
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer
from s33_verify_key_scanner_menu_model_cpu import EXPECTED


def snapshot(a, b, save):
    return (fan.write_word(0xFE70224, a, 'sth') + fan.write_word(0xFE70228, b, 'sth')
            + ' mov r12,0x2d62d8\n jl_s [r12]\n'
            + f' mov r1,{hex(save)}\n st r0,[r1,0]\n'
            + ' mov r12,0x1406d0\n jl_s [r12]\n')


def build_specs():
    blocks, payloads, _ = fan.verified_payloads(fan.ROOT)
    b = next(b for b in blocks if b['index'] == 5)
    off = 0x9802AC-b['load_address_candidate']
    desc = bytearray(payloads[5][off:off+28])
    assert len(desc) == 28 and struct.unpack_from('<I', desc, 12)[0] == 0x7CAFE8
    struct.pack_into('<H', desc, 6, 0)
    for pos, value in ((8, 0), (12, 0x300800), (20, 0)):
        struct.pack_into('<I', desc, pos, value)
    descriptor = ''.join(fan.write_word(0x367700+4*i, value)
                         for i, value in enumerate(struct.unpack('<7I', desc)))
    specs = []
    for order in (0x16E588, 0x323A00):
        for slot, (key, bit) in enumerate(((11, 12), (14, 7), (67, 8), (78, 13))):
            base = next(s for s in queue.build_specs() if s['name'] == f'c{key}_o{order:x}_g0')
            a = 0xffff & ~(1 << (bit-10)) if bit in (12, 13) else 0xffff
            b = 0xffff & ~(1 << bit)
            start = km.scanner_asm(1 << bit, 0)
            end = km.scanner_asm(0, 0)
            assert base['extra'].count(start) == base['extra'].count(end) == 1
            setup = (fan.write_word(0x366DE8, 0x16EC38) + fan.write_word(0x3678F0, 0xFC000000)
                     + fan.write_word(0x3678F4, 0) + fan.write_word(0x3678A2, 0, 'stb'))
            events = base['extra'].replace(start, setup + snapshot(a, b, 0x367670))
            events = events.replace(end, snapshot(0xffff, 0xffff, 0x367674))
            for screen in (0, 1):
                chosen, action = EXPECTED[screen][slot]
                extra = events + descriptor + fan.write_word(0x366EA4, 0x367700)
                extra += fan.write_word(0x366EAC, 0) + fan.write_word(0x367600, screen)
                extra += dispatch_buffer(0) + dispatch_buffer(1)
                checks = base['checks'] + [(0x367670, 4, 0x3ffffff ^ (1 << bit)),
                                           (0x367674, 4, 0x3ffffff), (0x367600, 4, chosen),
                                           (0x367604, 4, action), (0x367608, 4, 2),
                                           (0x367610, 4, key << 7), (0x367614, 4, (key << 7) | 1)]
                specs.append(dict(name=f'o{order:x}_slot{slot+1}_screen{screen}', extra=extra,
                                  checks=checks, trace=['0x2d62d8', '0x1406d0', '0x16ec38',
                                                        '0x16e6e0', '0x16f86c', '0x169e1c', '0x300800'],
                                  success=0xDEADFD00+len(specs)))
    return specs


def main():
    fan.main(build_specs(), scanner=True, queue=True, dispatch=True, window=True,
             menu_model=True, menu_bridge=True, snapshot_input=True)


if __name__ == '__main__':
    main()
