#!/usr/bin/env python3
"""Scanner -> menu -> manager tempo -> modifica e conferma originali."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_menu_time_open_cpu as opening
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def main():
    specs = []
    for base in opening.build_specs():
        if not base['name'].endswith('busy0'):
            continue
        for key, bit, edited in ((7, 20, 121), (8, 16, 119)):
            extra = base['extra']
            extra += f' mov r0,{hex(queue.BUF+96)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
            extra += dispatch_buffer(6)
            for a, v, op in ((0x366EA0, 0, 'sth'), (0x366EAC, 0, 'st'),
                             (0x899AD0, 120, 'st'), (0x899AC0, 0x367700, 'st'),
                             (0x365788, 0x12345678, 'st'), (0x37FBF4, 0x12345678, 'st'),
                             (0x446808+4*key+2, 1, 'sth')):
                extra += fan.write_word(a, v, op)
            extra += km.scanner_asm(1 << bit, 0) + km.scanner_asm(0, 0)
            for i in (7, 8):
                extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
            extra += dispatch_buffer(7) + dispatch_buffer(8)
            for src, dst in ((0x899AD0, 0x367680), (0x365788, 0x367684), (0x37FBF4, 0x367688)):
                extra += f' mov r1,{hex(src)}\n ld r0,[r1,0]\n mov r1,{hex(dst)}\n st r0,[r1,0]\n'
            extra += km.scanner_asm(1 << 12, 0) + km.scanner_asm(0, 0)
            for i in (9, 10):
                extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
            extra += dispatch_buffer(9) + dispatch_buffer(10)
            checks = [(a, w, 11 if a in (queue.QUEUE, queue.QUEUE+2, 0x367368)
                       else 5 if a == km.C150_COUNT else v) for a, w, v in base['checks']]
            checks += [(0x367680, 4, edited), (0x367684, 4, 0x12345678),
                       (0x367688, 4, 0x12345678), (0x365788, 4, edited*1000),
                       (0x37FBF4, 4, edited*1000), (queue.BUF+116, 2, key << 7),
                       (queue.BUF+132, 2, (key << 7)|1),
                       (queue.BUF+148, 2, 0x580), (queue.BUF+164, 2, 0x581)]
            checks += km.c150_entry(3, 2, 1, key << 7, (key << 7)|1)
            checks += km.c150_entry(4, 2, 1, 0x580, 0x581)
            specs.append(dict(name=base['name']+f'_key{key}', extra=extra, checks=checks,
                              trace=base['trace'] + ['0x7d2394', '0x0d03e0', '0x0de7b4',
                                                     '0x7d23c8' if key == 7 else '0x7d241c'],
                              trace_counts=[('0x1453e4', 2)], success=0xDEADFC00+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True, table=True,
             shared=True, handler700=True, manager700=True, lifecycle_real=True,
             menu_model=True, menu_bridge=True, time_window=True)


if __name__ == '__main__':
    main()
