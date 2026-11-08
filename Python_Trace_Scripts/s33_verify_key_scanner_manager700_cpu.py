#!/usr/bin/env python3
"""Scanner 0x700 fino ai gate del manager originale, con stato sintetico."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def main():
    specs = []
    for order in (0x16E588, 0x323A00):
        base = next(s for s in queue.build_specs() if s['name'] == f'c14_o{order:x}_g0')
        for mode in (1, 2):
            for busy, count in ((1, 197), (0, 0)):
                extra = base['extra'] + fan.write_word(0x366EA4, 0x9802AC)
                extra += fan.write_word(0x366E9C, 0x3F5900)
                extra += fan.write_word(0x366EA0, count, 'sth')
                extra += fan.write_word(0x366EBB, busy, 'stb')
                extra += fan.write_word(0x3675C4, mode) + fan.write_word(0x3675CC, 0x3F)
                extra += dispatch_buffer(0) + dispatch_buffer(1)
                checks = base['checks'] + [(0x366EA4, 4, 0x9802AC), (0x366EA8, 4, 0),
                                           (0x366EBB, 1, busy),
                                           (0x3675C0, 4, 1 if mode == 2 else 2),
                                           (0x3675C8, 4, int(mode == 2))]
                pcs = ['0x1453e4', '0x14507c', '0x145180', '0x14539a']
                if busy:
                    pcs.append('0x14519c')
                specs.append(dict(name=f'o{order:x}_mode{mode}_busy{busy}_count{count}',
                                  extra=extra, checks=checks, trace=pcs,
                                  trace_values=[('0x145092', 'cr16 <- '+('0x9802ac' if mode == 1 else '0x989fcc'))] if busy else [('0x145096', 'cr16 <- 0x0')],
                                  success=0xDEAD3100+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True,
             table=True, shared=True, handler700=True, manager700=True)


if __name__ == '__main__':
    main()
