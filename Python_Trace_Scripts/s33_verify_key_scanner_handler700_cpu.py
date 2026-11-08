#!/usr/bin/env python3
"""Pressione 0x700 fino all'handler originale e richiesta menu intercettata."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def main():
    specs = []
    for order in (0x16E588, 0x323A00):
        base = next(s for s in queue.build_specs() if s['name'] == f'c14_o{order:x}_g0')
        for mode in (0, 1, 2):
            extra = base['extra'] + fan.write_word(0x366EA4, 0x9802AC)
            extra += fan.write_word(0x3675C4, mode) + fan.write_word(0x3675CC, 0x3F)
            extra += dispatch_buffer(0) + dispatch_buffer(1)
            checks = base['checks'] + [(0x3675C0, 4, 1 if mode == 2 else 2),
                                       (0x3675C8, 4, int(mode == 2)),
                                       (0x3675D0, 4, int(mode != 0))]
            if mode:
                checks += [(0x3675D4, 4, 2 if mode == 1 else 0x3F), (0x3675D8, 4, 0)]
            specs.append(dict(name=f'o{order:x}_mode{mode}', extra=extra,
                              checks=checks, success=0xDEAD2100+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True,
             table=True, shared=True, handler700=True)


if __name__ == '__main__':
    main()
