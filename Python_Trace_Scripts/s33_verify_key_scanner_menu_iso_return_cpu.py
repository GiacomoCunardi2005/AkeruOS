#!/usr/bin/env python3
"""Ritorno ISO del manager originale verso descrittore menu sintetico."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_menu_iso_navigation_cpu as nav
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def main():
    specs = []
    marker = fan.write_word(0x366EA0, 0, 'sth')
    for base in nav.build_specs():
      for busy in (0, 1):
        extra = base['extra']
        bridge = fan.write_word(0x36778C, 0x300800)
        assert extra.count(bridge) == 1
        extra = extra.replace(bridge, fan.write_word(0x36778C, 0x301000))
        assert extra.count(marker) == 1
        setup = (fan.write_word(0x370000+0x36*4, 0x367780)
                 + fan.write_word(0x370000+0x3f*4, 0x989FCC)
                 + fan.write_word(0x366E9C, 0x370000)
                 + fan.write_word(0x366EA0, 197, 'sth'))
        extra = extra.replace(marker, setup)
        confirm = km.scanner_asm(1 << 12, 0)
        position = extra.rfind(confirm)
        assert position >= 0
        extra = extra[:position] + fan.write_word(0x366EBB, busy, 'stb') + extra[position:]
        if not busy:
            extra += f' mov r0,{hex(queue.BUF+144)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
            extra += dispatch_buffer(9) + fan.write_word(0x366EAC, 0)
            extra += fan.write_word(0x446916, 1, 'sth')
            extra += km.scanner_asm(1 << 8, 0) + km.scanner_asm(0, 0)
            for i in (10, 11):
                extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
            extra += dispatch_buffer(10) + dispatch_buffer(11)
        checks = [(a, w, (0x989FCC if busy else 0x367780) if a == 0x366EA4
                   else (9 if busy else 12) if a in (queue.QUEUE, queue.QUEUE+2, 0x367368)
                   else (4 if busy else 5) if a == km.C150_COUNT
                   else (0 if busy else 1) if a == 0x3676A4
                   else 5 if not busy and a == 0x3676A0 else v)
                  for a, w, v in base['checks']]
        checks += [(0x366EBB, 1, busy), (0x367658, 4, 0 if busy else 1),
                   (0x36764C, 4, 0 if busy else 1)]
        if not busy:
            checks += km.c150_entry(4, 2, 1, 0x2180, 0x2181)
        specs.append(dict(name=base['name']+f'_return_busy{busy}', extra=extra, checks=checks,
                          trace=['0x301000' if pc == '0x300800' else pc for pc in base['trace']], trace_values=base['trace_values'],
                          success=0xDEADE800+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True, table=True,
             shared=True, handler700=True, manager700=True, lifecycle_real=True,
             iso_confirm=True, control_confirm=True, navigation=True,
             menu_model=True, menu_bridge=True, menu_return_table=True)


if __name__ == '__main__':
    main()
