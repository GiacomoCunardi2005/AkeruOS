#!/usr/bin/env python3
"""Scanner, callback menu e selezione colore/mono su frame sintetico."""
import struct
import sys
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def main():
    rows = '--rows' in sys.argv
    blocks, payloads, _ = fan.verified_payloads(fan.ROOT)
    block = next(b for b in blocks if b['index'] == 5)
    off = 0x9802AC - block['load_address_candidate']
    desc = bytearray(payloads[5][off:off+28])
    assert len(desc) == 28 and struct.unpack_from('<I', desc, 12)[0] == 0x7CAFE8
    struct.pack_into('<H', desc, 6, 0)
    for offset, value in ((8, 0), (12, 0x301000), (20, 0)):
        struct.pack_into('<I', desc, offset, value)
    descriptor = ''.join(fan.write_word(0x367700+4*i, value)
                         for i, value in enumerate(struct.unpack('<7I', desc)))
    specs = []
    for order in (0x16E588, 0x323A00):
        base = next(s for s in queue.build_specs() if s['name'] == f'c14_o{order:x}_g0')
        for initial in (0, 1):
            for selections in ((0, 1), (1, 0)):
                extra = base['extra'] + descriptor + fan.write_word(0x366EA4, 0x367700)
                extra += fan.write_word(0x366EAC, 0) + fan.write_word(0x367660, initial)
                extra += fan.write_word(0x446916, 1, 'sth')
                for i in range(4):
                    extra += fan.write_word(0x367680+2*i, 1024, 'sth')
                    extra += fan.write_word(0x367690+2*i, 777, 'sth')
                    extra += fan.write_word(0x3676A0+2*i, 777, 'sth')
                extra += dispatch_buffer(0) + dispatch_buffer(1)
                for j, mode in enumerate(selections):
                    bit = 8 if mode else 7
                    extra += km.scanner_asm(1 << bit, 0) + km.scanner_asm(0, 0)
                    for i in (2+2*j, 3+2*j):
                        extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
                    extra += dispatch_buffer(2+2*j) + dispatch_buffer(3+2*j)
                    extra += (f' mov r1,0x367660\n ld r0,[r1,0]\n mov r1,{hex(0x367664+8*j)}\n st r0,[r1,0]\n'
                              f' mov r1,0x367680\n mov r2,{hex(0x367690+16*j)}\n mov r3,2\n mov r4,2\n')
                    if rows:
                        extra += (f' mov r5,0\n mov r6,1\n bl akeru_color_process_rows\n'
                                  f' mov r1,{hex(0x3676c0+4*j)}\n st r0,[r1,0]\n'
                                  f' mov r1,{hex(0x367690+16*j)}\n ld r2,[r1,0]\n ld r3,[r1,4]\n'
                                  f' mov r1,{hex(0x3676c8+8*j)}\n st r2,[r1,0]\n st r3,[r1,4]\n')
                        if j == 0:
                            extra += (f' mov r0,0x367660\n mov r1,{5 if mode else 6}\n bl akeru_color_select\n'
                                      ' mov r1,0x3676dc\n st r0,[r1,0]\n'
                                      ' mov r1,0x367660\n ld r0,[r1,0]\n mov r1,0x3676d8\n st r0,[r1,0]\n')
                        extra += (f' mov r1,{hex(0x367664+8*j)}\n ld r0,[r1,0]\n'
                                  f' mov r1,0x367680\n mov r2,{hex(0x367694+16*j)}\n'
                                  ' mov r3,2\n mov r4,2\n mov r5,1\n mov r6,1\n bl akeru_color_process_rows\n')
                    else:
                        extra += ' bl akeru_color_process\n'
                    extra += f' mov r1,{hex(0x367668+8*j)}\n st r0,[r1,0]\n'
                checks = [(a, w, 6 if a in (queue.QUEUE, queue.QUEUE+2, 0x367368)
                           else 3 if a == km.C150_COUNT else v) for a, w, v in base['checks']]
                checks += [(0x367600, 4, 2), (0x367604, 4, 0), (0x367608, 4, 6),
                           (0x367660, 4, selections[1])]
                events = [0x700, 0x701]
                for j, mode in enumerate(selections):
                    event = 0x2180 if mode else 0x700
                    events += [event, event+1]
                    checks += [(0x367664+8*j, 4, mode), (0x367668+8*j, 4, mode)]
                    checks += [(0x367690+16*j+2*i, 2, 1219 if mode else 777) for i in range(4)]
                    if rows:
                        checks += [(0x3676c0+4*j, 4, mode),
                                   (0x3676c8+8*j, 4, (1219 if mode else 777)*0x10001),
                                   (0x3676cc+8*j, 4, 777*0x10001)]
                    checks += km.c150_entry(j+1, 2, 1, event, event+1)
                checks += [(0x367610+4*i, 4, event) for i, event in enumerate(events)]
                if rows: checks += [(0x3676d8, 4, 1-selections[0]), (0x3676dc, 4, 1)]
                checks += [(0x367680+2*i, 2, 1024) for i in range(4)]
                specs.append(dict(name=f'o{order:x}_initial{initial}_select{selections[0]}{selections[1]}',
                                  extra=extra, checks=checks, trace=['0x16f86c', '0x169e1c', '0x16a6e4', '0x301000'],
                                  success=0xDEADF900+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True,
             menu_model=True, menu_bridge=True, color_model=True)


if __name__ == '__main__':
    main()
