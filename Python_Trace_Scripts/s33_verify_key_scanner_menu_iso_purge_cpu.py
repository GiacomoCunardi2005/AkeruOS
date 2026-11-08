#!/usr/bin/env python3
"""Chiusura ISO con purge originale e tre eventi pendenti sintetici."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_menu_iso_navigation_cpu as nav
import s33_verify_key_machine_static_map_cpu as km
import s33_verify_key_scanner_queue_cpu as queue
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def post(node, event, arg):
    return (f' mov r0,{hex(node)}\n mov r1,{hex(event)}\n mov r2,{hex(arg)}\n'
            ' mov r12,0x169eb4\n jl_s [r12]\n')


def main():
    specs = []
    for base in nav.build_specs():
        for busy in (0, 1):
            extra = base['extra']
            for before, after in (
                (fan.write_word(0x36778C, 0x300800), fan.write_word(0x36778C, 0x301000)),
                (fan.write_word(0x366EA0, 0, 'sth'),
                 fan.write_word(0x370000+0x36*4, 0x367780)
                 + fan.write_word(0x370000+0x3f*4, 0x989FCC)
                 + fan.write_word(0x366E9C, 0x370000)
                 + fan.write_word(0x366EA0, 197, 'sth')),
                (dispatch_buffer(7),
                 fan.write_word(0x366EBB, busy, 'stb')
                 + post(0x989FCC, 0x580, 0x111)
                 + post(0x367780, 0x580, 0x222)
                 + post(0x989FCC, 0x8000, 0x333)
                 + dispatch_buffer(7))):
                assert extra.count(before) == 1
                extra = extra.replace(before, after)
            checks = [(a, w, (0x989FCC if busy else 0x367780) if a == 0x366EA4
                       else 12 if a == queue.QUEUE+2 else 12 if a == 0x367368 and busy
                       else 13 if a == 0x367368 else v) for a, w, v in base['checks']]
            records = [(0x989FCC, 0x580, 0x111), (0x367780, 0x580, 0x222),
                       (0x989FCC, 0x8000, 0x333)] if busy else [
                       (0x367780, 0x580, 0x222), (0x989FCC, 0x8000, 0x333),
                       (0x367780, 0x4409, 0)]
            for i, (node, event, arg) in enumerate(records, start=9):
                checks += [(queue.RECORDS+12*i, 4, node),
                           (queue.RECORDS+12*i+4, 2, event),
                           (queue.RECORDS+12*i+8, 4, arg)]
            pcs = ['0x301000' if pc == '0x300800' else pc for pc in base['trace']]
            if not busy:
                pcs += ['0x17bf60', '0x17bee8', '0x16a0bc']
            specs.append(dict(name=base['name']+f'_purge_busy{busy}', extra=extra, checks=checks,
                              trace=pcs, trace_absent=['0x17bf60'] if busy else [],
                              trace_values=base['trace_values'], success=0xDEADF600+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True, table=True,
             shared=True, handler700=True, manager700=True, lifecycle_real=True,
             iso_confirm=True, control_confirm=True, navigation=True,
             menu_model=True, menu_bridge=True, menu_return_table=True, return_purge_real=True)


if __name__ == '__main__':
    main()
