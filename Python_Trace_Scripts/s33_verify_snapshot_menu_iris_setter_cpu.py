#!/usr/bin/env python3
"""Snapshot sintetico -> menu -> setter iride originale con servizi fixture."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_snapshot_menu_bridge_cpu as snapshot
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def main():
    specs = []
    tests = ((3, 9, 1, 0, 0, 1), (3, 9, 1, 1, 0, 1),
             (3, 9, 1, 0, 1, 1), (3, 9, 1, 0, 0, 0),
             (3, 9, 9, 0, 0, 1), (3, 1, 9, 0, 0, 1),
             (2, 9, 1, 0, 0, 1))
    for order in (0x16E588, 0x323A00):
        for slot, initial, requested, acquire, guard, request in tests:
            base = next(s for s in snapshot.build_specs()
                        if s['name'] == f'o{order:x}_slot{slot}_screen1')
            extra = base['extra']
            for a, value, op in ((0x367FEA, initial, 'stb'), (0x367720, acquire, 'st'),
                                 (0x367724, guard, 'st'), (0x367728, request, 'st'),
                                 (0x367764, 0xAB, 'st')):
                extra += fan.write_word(a, value, op)
            if slot == 3:
                extra += (' mov r0,0x367604\n bl akeru_menu_take_action\n'
                          ' mov r1,0x367768\n st r0,[r1,0]\n')
                key, bit = (14, 7) if requested == 1 else (67, 8)
                extra += fan.write_word(0x446808+4*key+2, 1, 'sth')
                extra += snapshot.snapshot(0xffff, 0xffff & ~(1 << bit), 0x367678)
                extra += snapshot.snapshot(0xffff, 0xffff, 0x36767C)
                for i in (2, 3):
                    extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
                extra += dispatch_buffer(2) + dispatch_buffer(3)
            extra += (' mov r0,0x367604\n bl akeru_menu_take_action\n'
                      ' mov r1,0x367760\n st r0,[r1,0]\n'
                      ' mov r1,0x18b85c\n mov r2,0x367764\n bl akeru_iris_apply\n'
                      ' mov r1,0x36776c\n st r0,[r1,0]\n')
            selected = slot == 3
            changed = selected and initial != requested and not acquire and not guard and request == 1
            final = requested if changed else initial
            ac = int(selected and initial != requested)
            gc = int(ac and acquire == 0)
            rc = int(gc and guard == 0)
            rel = int(gc and guard != 0)
            clean = int(rc and request != 1)
            checks = [(a, w, 4 if selected and a in (queue.QUEUE, queue.QUEUE+2, 0x367368, 0x367608)
                       else 2 if selected and a == km.C150_COUNT else v)
                      for a,w,v in base['checks'] if a != 0x367604]
            checks += [(0x367604, 4, 0), (0x367760, 4, (12 if requested == 1 else 13) if selected else 2),
                       (0x367764, 4, final if selected else 0xAB), (0x367FEA, 1, final),
                       (0x36776C, 4, (int(final == requested) if selected else 0xFFFFFFFF)),
                       (0x36772C, 4, ac), (0x367730, 4, gc), (0x367734, 4, rc),
                       (0x367738, 4, rel), (0x36773C, 4, clean)]
            if rc:
                checks += [(0x367744, 4, 0x1234), (0x367748, 4, requested),
                           (0x36774C, 4, 1), (0x367750, 4, 0x3A98)]
            if selected:
                event = 0x700 if requested == 1 else 0x2180
                checks += [(0x367768, 4, 1)]
                checks += km.c150_entry(1, 2, 1, event, event+1)
                checks += [(0x367618, 4, event), (0x36761C, 4, event+1)]
            specs.append(dict(name=f'o{order:x}_slot{slot}_{initial}to{requested}_a{acquire}g{guard}r{request}',
                              extra=extra, checks=checks,
                              trace=base['trace'] + (['0x18b85c'] if selected else []),
                              trace_absent=[] if selected else ['0x18b85c'],
                              success=0xDEADFE00+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True,
             menu_model=True, menu_bridge=True, snapshot_input=True, iris_backend=True)


if __name__ == '__main__':
    main()
