#!/usr/bin/env python3
"""Scanner -> pagine menu -> richiesta al manager V1.1 per il tempo."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_menu_iso_open_cpu as opening
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def build_specs():
    specs = []
    for base in opening.build_specs():
        busy = int(base['name'].endswith('busy1'))
        extra = base['extra']
        arm = fan.write_word(0x446842, 1, 'sth')
        scan = km.scanner_asm(1 << 7, 0)
        assert extra.count(arm) == extra.count(scan) == 1
        extra = extra.replace(arm, arm + fan.write_word(0x446942, 1, 'sth'))
        extra = extra.replace(scan, km.scanner_asm(1 << 13, 0))
        take = ' mov r0,0x3676a4\n bl akeru_menu_take_action\n'
        at = extra.rfind(take)
        assert at >= 0
        extra = extra[:at] + take + ' mov r1,0x367674\n st r0,[r1,0]\n'
        extra += km.scanner_asm(1 << 7, 0) + km.scanner_asm(0, 0)
        for i in (4, 5):
            extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
        extra += dispatch_buffer(4) + dispatch_buffer(5)
        extra += (take + ' mov r1,0x36767c\n st r0,[r1,0]\n'
                  ' cmp r0,4\n bne no_time_open\n'
                  ' mov r0,0x3e\n mov r1,0\n mov r12,0x1453e4\n jl_s [r12]\n'
                  ' mov r1,0x367678\n st r0,[r1,0]\nno_time_open:\n')
        checks = [(queue.QUEUE, 2, 6), (queue.QUEUE+2, 2, 6 if busy else 7),
                  (0x367368, 4, 6 if busy else 7), (km.C150_COUNT, 4, 3),
                  (0x367670, 4, 1), (0x367674, 4, 1), (0x36767C, 4, 4),
                  (0x367678, 4, 0 if busy else 1), (0x3676A0, 4, 3), (0x3676A4, 4, 0),
                  (0x366EA4, 4, 0x367780 if busy else 0x989CD8)]
        checks += km.c150_entry(0, 2, 1, 0x580, 0x581)
        checks += km.c150_entry(1, 2, 1, 0x2700, 0x2701)
        checks += km.c150_entry(2, 2, 1, 0x700, 0x701)
        if not busy:
            checks += [(queue.RECORDS+72, 4, 0x989CD8), (queue.RECORDS+76, 2, 0x4409)]
        specs.append(dict(name=base['name'], extra=extra, checks=checks,
                          trace=['0x300800', '0x169e1c', '0x1453e4', '0x145180']
                                + ([] if busy else ['0x7d22f0', '0x16a05c', '0x16a188']),
                          trace_absent=['0x7d22f0'] if busy else [],
                          success=0xDEADFB00+len(specs)))
    return specs


def main():
    fan.main(build_specs(), scanner=True, queue=True, dispatch=True, window=True, table=True,
             shared=True, handler700=True, manager700=True, lifecycle_real=True,
             menu_model=True, menu_bridge=True, time_window=True)


if __name__ == '__main__':
    main()
