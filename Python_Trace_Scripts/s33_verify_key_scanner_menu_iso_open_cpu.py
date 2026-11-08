#!/usr/bin/env python3
"""Scanner -> menu C -> richiesta ISO al manager V1.1, con fixture."""
import struct
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def build_specs():
    blocks, payloads, _ = fan.verified_payloads(fan.ROOT)
    b = next(b for b in blocks if b['index'] == 5)
    off = 0x9802AC - b['load_address_candidate']
    desc = bytearray(payloads[5][off:off+28])
    assert len(desc) == 28 and struct.unpack_from('<I', desc, 12)[0] == 0x7CAFE8
    struct.pack_into('<H', desc, 6, 0)
    for offset, value in ((8, 0), (12, 0x300800), (20, 0)):
        struct.pack_into('<I', desc, offset, value)
    descriptor = ''.join(fan.write_word(0x367780 + 4*i, value)
                         for i, value in enumerate(struct.unpack('<7I', desc)))
    specs = []
    for order in (0x16E588, 0x323A00):
        base = next(s for s in queue.build_specs() if s['name'] == f'c11_o{order:x}_g0')
        for busy in (0, 1):
            extra = base['extra'] + descriptor
            for addr, value, op in ((0x366EA4, 0x367780, 'st'), (0x366E9C, 0x3F5900, 'st'),
                                    (0x366EA0, 197, 'sth'), (0x366EBB, busy, 'stb'),
                                    (0x366EAC, 0, 'st'), (0x367BC8, 6, 'stb'),
                                    (0x367608, 0x367700, 'st'), (0x367725, 24, 'stb'),
                                    (0x367726, 99, 'stb'), (0x367740, 0x989DA4, 'st')):
                extra += fan.write_word(addr, value, op)
            extra += dispatch_buffer(0) + dispatch_buffer(1)
            extra += (' mov r0,0x3676a4\n bl akeru_menu_take_action\n'
                      ' mov r1,0x367670\n st r0,[r1,0]\n')
            extra += fan.write_word(0x446842, 1, 'sth')
            extra += km.scanner_asm(1 << 7, 0) + km.scanner_asm(0, 0)
            for i in (2, 3):
                extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
            extra += dispatch_buffer(2) + dispatch_buffer(3)
            extra += (' mov r0,0x3676a4\n bl akeru_menu_take_action\n'
                      ' mov r1,0x367674\n st r0,[r1,0]\n'
                      ' cmp r0,2\n bne no_open\n'
                      ' mov r0,0x3f\n mov r1,0\n mov r12,0x1453e4\n jl_s [r12]\n'
                      ' mov r1,0x367678\n st r0,[r1,0]\nno_open:\n')
            checks = [(a, w, 4 if a == queue.QUEUE else (4 if busy else 5)
                       if a in (queue.QUEUE+2, 0x367368) else 2 if a == km.C150_COUNT else v)
                      for a, w, v in base['checks']]
            checks += [(0x367670, 4, 1), (0x367674, 4, 2), (0x3676A0, 4, 1),
                       (0x3676A4, 4, 0), (0x367678, 4, 0 if busy else 1),
                       (0x366EA4, 4, 0x367780 if busy else 0x989FCC),
                       (0x36760C, 4, 0 if busy else 1)]
            if not busy:
                checks += [(0x367610, 4, 0x367700), (0x367614, 4, 7),
                           (queue.RECORDS+48, 4, 0x989FCC),
                           (queue.RECORDS+52, 2, 0x4409)]
            checks += km.c150_entry(1, 2, 1, 0x700, 0x701)
            pcs = ['0x300800', '0x169e1c', '0x16a6e4', '0x1453e4', '0x145180']
            if not busy:
                pcs += ['0x7d252c', '0x16a05c', '0x16a188', '0x7d2564', '0x641128']
            specs.append(dict(name=f'o{order:x}_busy{busy}', extra=extra, checks=checks,
                              trace=pcs, trace_absent=['0x7d252c'] if busy else [],
                              success=0xDEADE100+len(specs)))
    return specs


def main():
    fan.main(build_specs(), scanner=True, queue=True, dispatch=True, window=True, table=True,
             shared=True, handler700=True, manager700=True, lifecycle_real=True,
             menu_model=True, menu_bridge=True)


if __name__ == '__main__':
    main()
