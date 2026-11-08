#!/usr/bin/env python3
"""Apertura ISO e conferma 0x4801 iniettata; servizi GUI fixture."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_iso_lifecycle_cpu as life
import s33_verify_key_scanner_queue_cpu as queue
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def main():
    specs = []
    for base in life.build_specs():
        if not base['name'].endswith('_busy0'):
            continue
        for selected, index, converted in [(0, 6, 555), (1, 0, 0), (7, 6, 125), (20, 19, 1600), (24, 0, 0)]:
            extra = base['extra']
            extra += fan.write_word(0x365787, 88, 'stb') + fan.write_word(0x37FBF2, 555, 'sth')
            extra += dispatch_buffer(1)
            extra += (f' mov r0,{hex(queue.BUF+32)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
                      + dispatch_buffer(2))
            extra += fan.write_word(0x366EAC, 0x367700) + fan.write_word(0x367726, selected, 'stb')
            extra += fan.write_word(0x366EA0, 0, 'sth')
            extra += (' mov r0,0\n mov r1,0x4801\n mov r2,0\n mov r12,0x169eb4\n jl_s [r12]\n'
                      f' mov r0,{hex(queue.BUF+48)}\n mov r12,0x17bd4c\n jl_s [r12]\n'
                      + dispatch_buffer(3))
            checks = [(a, w, 4 if a in (queue.QUEUE, queue.QUEUE+2, 0x367368) else v)
                      for a, w, v in base['checks']]
            checks += [(0x365787, 1, 88 if selected == 0 else index),
                       (0x367BC8, 1, index), (0x37FBF2, 2, converted),
                       (0x367630, 4, 1), (0x367634, 4, 0x989FCC),
                       (0x367638, 4, 0x4409), (0x36763C, 4, 0),
                       (queue.BUF+32, 4, 0x989FCC), (queue.BUF+36, 2, 0x4409),
                       (queue.BUF+48, 4, 0), (queue.BUF+52, 2, 0x4801)]
            specs.append(dict(name=f'{base["name"]}_selected{selected}', extra=extra,
                              checks=checks,
                              trace=base['trace'] + ['0x7d25b0', '0x6410f4', '0x16a29c']
                              + ([] if selected == 0 else ['0x0d03b8', '0x17c320', '0x0de78c']),
                              trace_absent=['0x0d03b8', '0x17c320', '0x0de78c'] if selected == 0 else [],
                              trace_counts=[('0x1453e4', 2)],
                              trace_values=base['trace_values'] + [
                                  ('0x169e12', 'cr16 <- 0x701'),
                                  ('0x169e12', 'cr16 <- 0x4409'),
                                  ('0x169e12', 'cr16 <- 0x4801'),
                                  ('0x7d25e6', 'cr16 <- 0x36'),
                                  ('0x145096', 'cr16 <- 0x0')],
                              success=0xDEAD5100+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True,
             table=True, shared=True, handler700=True, manager700=True,
             lifecycle_real=True, iso_confirm=True)


if __name__ == '__main__':
    main()
