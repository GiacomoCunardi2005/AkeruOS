#!/usr/bin/env python3
"""Dal menu C al manager ISO, navigazione e conferma originali, CPU emulata."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_menu_iso_open_cpu as opening
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer
from s33_verify_key_scanner_iso_navigation_cpu import snapshot_byte


def build_specs():
    specs = []
    for base in opening.build_specs():
        if not base['name'].endswith('busy0'):
            continue
        for bit, key, chosen, idx, iso in ((20, 7, 6, 5, 120), (16, 8, 8, 7, 140)):
            extra = base['extra'] + fan.write_word(0x365787, 88, 'stb')
            extra += fan.write_word(0x37FBF2, 555, 'sth')
            extra += f' mov r0,{hex(queue.BUF+64)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
            extra += dispatch_buffer(4)
            for addr, value, op in ((0x366E94, 0x77F728, 'st'), (0x366E98, 22, 'sth'),
                                    (0x366EA0, 0, 'sth'), (0x366EAC, 0x367700, 'st'),
                                    (0x367814, 1, 'stb'), (0x367700, 0x37, 'st'),
                                    (0x367704, 0x94801, 'st'), (0x367708, 0x989FCC, 'st'),
                                    (0x367714, 0x2D0000, 'st'),
                                    (0x446808+4*key+2, 1, 'sth')):
                extra += fan.write_word(addr, value, op)
            extra += snapshot_byte(0x367726, 0x367680)
            extra += km.scanner_asm(1 << bit, 0) + km.scanner_asm(0, 0)
            for i in (5, 6):
                extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
            extra += dispatch_buffer(5) + dispatch_buffer(6)
            extra += snapshot_byte(0x367726, 0x367684)
            extra += km.scanner_asm(1 << 12, 0) + km.scanner_asm(0, 0)
            for i in (7, 8):
                extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
            extra += dispatch_buffer(7) + dispatch_buffer(8)
            checks = [(a, w, 9 if a in (queue.QUEUE, queue.QUEUE+2, 0x367368)
                       else 4 if a == km.C150_COUNT else v)
                      for a, w, v in base['checks']
                      if a not in (0x36760C, 0x367610, 0x367614)]
            checks += [(0x367680, 4, 7), (0x367684, 4, chosen),
                       (0x367726, 1, chosen), (0x365787, 1, idx),
                       (0x367BC8, 1, idx), (0x37FBF2, 2, iso),
                       (0x367648, 4, 2), (queue.BUF+84, 2, key << 7),
                       (queue.BUF+100, 2, (key << 7) | 1),
                       (queue.BUF+116, 2, 0x580), (queue.BUF+132, 2, 0x581)]
            checks += km.c150_entry(2, 2, 1, key << 7, (key << 7) | 1)
            checks += km.c150_entry(3, 2, 1, 0x580, 0x581)
            specs.append(dict(name=f'{base["name"]}_nav{key}', extra=extra, checks=checks,
                              trace=base['trace'] + ['0x641064', '0x641174', '0x640f60',
                                                     '0x7d25b0', '0x0d03b8', '0x17c320', '0x0de78c'],
                              trace_values=[('0x169e12', 'cr16 <- 0x4801')],
                              success=0xDEADF200+len(specs)))
    return specs


def main():
    fan.main(build_specs(), scanner=True, queue=True, dispatch=True, window=True, table=True,
             shared=True, handler700=True, manager700=True, lifecycle_real=True,
             iso_confirm=True, control_confirm=True, navigation=True,
             menu_model=True, menu_bridge=True)


if __name__ == '__main__':
    main()
