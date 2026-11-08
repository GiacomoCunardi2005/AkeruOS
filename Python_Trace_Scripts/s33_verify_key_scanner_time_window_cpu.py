#!/usr/bin/env python3
"""Scanner e dispatcher originali verso schermata tempo diagnostica V1.1."""
import struct
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def main():
    blocks, payloads, _ = fan.verified_payloads(fan.ROOT)
    b = next(b for b in blocks if b['index'] == 5)
    off = 0x989CF8-b['load_address_candidate']
    table = dict(struct.iter_unpack('<II', payloads[5][off:off+72]))
    assert all(table[e] == h for e, h in ((0x380, 0x7D23C8), (0x400, 0x7D241C), (0x580, 0x7D2394)))
    specs = []
    for order in (0x16E588, 0x323A00):
        base = next(s for s in queue.build_specs() if s['name'] == f'c11_o{order:x}_g0')
        for initial, key, bit, edited in ((0, 7, 20, 120), (120, 7, 20, 121),
                                          (3999, 7, 20, 0), (0, 8, 16, 119),
                                          (1, 8, 16, 0), (2, 8, 16, 1)):
            scan = km.scanner_asm(1 << 12, 0)
            assert base['extra'].count(scan) == 1
            extra = base['extra'].replace(scan, fan.write_word(0x446808+4*key+2, 1, 'sth') + km.scanner_asm(1 << bit, 0))
            for a, v, op in ((0x366EA4, 0x989CD8, 'st'), (0x366EAC, 0, 'st'),
                             (0x899AD0, initial, 'st'), (0x899AC0, 0x367700, 'st'),
                             (0x367614, 0x367700, 'st'), (0x365788, 0x12345678, 'st'),
                             (0x37FBF4, 0x12345678, 'st')):
                extra += fan.write_word(a, v, op)
            extra += dispatch_buffer(0) + dispatch_buffer(1)
            for src, dst in ((0x899AD0, 0x367680), (0x365788, 0x367684), (0x37FBF4, 0x367688),
                             (0x367620, 0x36768C)):
                extra += f' mov r1,{hex(src)}\n ld r0,[r1,0]\n mov r1,{hex(dst)}\n st r0,[r1,0]\n'
            extra += km.scanner_asm(1 << 12, 0) + km.scanner_asm(0, 0)
            for i in (2, 3):
                extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
            extra += dispatch_buffer(2) + dispatch_buffer(3)
            checks = [(queue.QUEUE, 2, 4), (queue.QUEUE+2, 2, 4), (0x367368, 4, 4),
                      (km.C150_COUNT, 4, 2), (0x367680, 4, edited),
                      (0x367684, 4, 0x12345678), (0x367688, 4, 0x12345678), (0x36768C, 4, 0),
                      (0x365788, 4, edited*1000), (0x37FBF4, 4, edited*1000),
                      (0x367620, 4, 1), (0x367624, 4, 0x36), (0x367628, 4, 0),
                      (queue.BUF+4, 2, key << 7), (queue.BUF+20, 2, (key << 7)|1),
                      (queue.BUF+36, 2, 0x580), (queue.BUF+52, 2, 0x581)]
            checks += [(0x367750, 4, 1), (0x367754, 4, 0x899AC4),
                       (0x367758, 4, 0x899AD9 if edited else 0x899AD4),
                       (0x367764, 4, 1), (0x367768, 4, 1)]
            if edited: checks.append((0x36775C, 4, edited))
            checks += km.c150_entry(0, 2, 1, key << 7, (key << 7)|1)
            checks += km.c150_entry(1, 2, 1, 0x580, 0x581)
            handler = '0x7d23c8' if key == 7 else '0x7d241c'
            specs.append(dict(name=f'o{order:x}_v{initial}_key{key}', extra=extra, checks=checks,
                              trace=['0x16f86c', '0x169e1c', '0x16a6e4', '0x7d22f0', handler,
                                     '0x7d2394', '0x0d03e0', '0x0de7b4', '0x1453e4'],
                              success=0xDEADFA00+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True, table=True, time_window=True)


if __name__ == '__main__':
    main()
