#!/usr/bin/env python3
"""Scanner 0x700 a manager e lifecycle ISO originali, con servizi fixture."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def build_specs():
    specs = []
    for order in (0x16E588, 0x323A00):
        for busy in (0, 1):
            base = next(s for s in queue.build_specs() if s['name'] == f'c14_o{order:x}_g0')
            extra = base['extra'] + fan.write_word(0x366EA4, 0x9802AC)
            extra += fan.write_word(0x366E9C, 0x3F5900) + fan.write_word(0x366EA0, 197, 'sth')
            extra += fan.write_word(0x366EBB, busy, 'stb') + fan.write_word(0x3675C4, 2)
            extra += fan.write_word(0x3675CC, 0x3F) + fan.write_word(0x367BC8, 6, 'stb')
            extra += fan.write_word(0x367608, 0x367700)
            extra += fan.write_word(0x367725, 24, 'stb') + fan.write_word(0x367726, 99, 'stb')
            extra += fan.write_word(0x367740, 0x989DA4) + dispatch_buffer(0)
            checks = [(a, w, 3 if not busy and a in (queue.QUEUE+2, 0x367368) else v)
                      for a, w, v in base['checks']]
            checks += [(0x366EA4, 4, 0x9802AC if busy else 0x989FCC),
                                       (0x366EBB, 1, busy),
                                       (0x36760C, 4, 0 if busy else 1)]
            if not busy:
                checks += [(0x367610, 4, 0x367700), (0x367614, 4, 7),
                           (queue.RECORDS+24, 4, 0x989FCC),
                           (queue.RECORDS+28, 2, 0x4409), (queue.RECORDS+32, 4, 0)]
            pcs = ['0x1453e4', '0x145180']
            if not busy:
                pcs += ['0x7d252c', '0x16a05c', '0x16a188', '0x7d2564', '0x641128']
            specs.append(dict(name=f'o{order:x}_busy{busy}', extra=extra, checks=checks,
                              trace=pcs, trace_values=[] if busy else [
                                  ('0x169e12', 'cr16 <- 0x4403'),
                                  ('0x169e12', 'cr16 <- 0x4401'),
                                  ('0x169e12', 'cr16 <- 0x4405')],
                              success=0xDEAD4100+len(specs)))
    return specs


def main():
    fan.main(build_specs(), scanner=True, queue=True, dispatch=True, window=True,
             table=True, shared=True, handler700=True, manager700=True, lifecycle_real=True)


if __name__ == '__main__':
    main()
