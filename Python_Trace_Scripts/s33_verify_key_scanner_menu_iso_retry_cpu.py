#!/usr/bin/env python3
"""Manager busy rifiuta ISO: sblocco e ripetizione pressione, CPU V1.1."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_menu_iso_open_cpu as opening
import s33_verify_key_scanner_queue_cpu as queue
import s33_verify_key_machine_static_map_cpu as km
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def main():
    specs = []
    for base in opening.build_specs():
        if not base['name'].endswith('busy1'):
            continue
        for retry in (0, 1):
            extra = base['extra']
            extra += (' mov r1,0x366ea4\n ld r0,[r1,0]\n mov r1,0x367690\n st r0,[r1,0]\n'
                      ' mov r1,0x3676a4\n ld r0,[r1,0]\n mov r1,0x367694\n st r0,[r1,0]\n')
            extra += fan.write_word(0x366EBB, 0, 'stb')
            if retry:
                extra += km.scanner_asm(1 << 7, 0) + km.scanner_asm(0, 0)
                for i in (4, 5):
                    extra += f' mov r0,{hex(queue.BUF+16*i)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
                extra += dispatch_buffer(4) + dispatch_buffer(5)
                extra += (' mov r0,0x3676a4\n bl akeru_menu_take_action\n'
                          ' mov r1,0x367698\n st r0,[r1,0]\n'
                          ' cmp r0,2\n bne retry_done\n'
                          ' mov r0,0x3f\n mov r1,0\n mov r12,0x1453e4\n jl_s [r12]\n'
                          ' mov r1,0x36769c\n st r0,[r1,0]\nretry_done:\n')
            checks = [(a, w, 6 if retry and a == queue.QUEUE else 7 if retry and a in (queue.QUEUE+2, 0x367368)
                       else 3 if retry and a == km.C150_COUNT else v)
                      for a, w, v in base['checks']
                      if a not in (0x366EA4, 0x36760C)]
            checks += [(0x367690, 4, 0x367780), (0x367694, 4, 0),
                       (0x366EBB, 1, 0), (0x366EA4, 4, 0x989FCC if retry else 0x367780),
                       (0x36760C, 4, retry), (0x367698, 4, 2 if retry else 0),
                       (0x36769C, 4, 1 if retry else 0)]
            if retry:
                checks += km.c150_entry(2, 2, 1, 0x700, 0x701)
                checks += [(0x367610, 4, 0x367700), (0x367614, 4, 7),
                           (queue.RECORDS+72, 4, 0x989FCC), (queue.RECORDS+76, 2, 0x4409)]
            specs.append(dict(name=f'{base["name"]}_retry{retry}', extra=extra, checks=checks,
                              trace=base['trace'] + (['0x7d252c', '0x7d2564', '0x641128'] if retry else []),
                              trace_counts=[('0x1453e4', 2 if retry else 1)],
                              trace_absent=[] if retry else ['0x7d252c'],
                              success=0xDEADE500+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True, table=True,
             shared=True, handler700=True, manager700=True, lifecycle_real=True,
             menu_model=True, menu_bridge=True)


if __name__ == '__main__':
    main()
