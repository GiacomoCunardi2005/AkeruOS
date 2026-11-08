#!/usr/bin/env python3
"""Scanner V1.1 fino all'handler originale 0x2180, servizi profondi modellati."""
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue
from s33_verify_key_scanner_shared_cpu import dispatch_buffer


def main():
    specs = []
    for order in (0x16E588, 0x323A00):
        base = next(s for s in queue.build_specs() if s['name'] == f'c67_o{order:x}_g0')
        for scenario in ('state6', 'state3', 'queued', 'cfg42', 'pass'):
            extra = base['extra'] + fan.write_word(0x366EA4, 0x9802AC)
            for addr, value in ((0x365756, 2 if scenario == 'state6' else 0),
                                (0x365753, 3 if scenario == 'state3' else 5),
                                (0x446808 + 4*0x61, 42 if scenario == 'cfg42' else 41)):
                extra += fan.write_word(addr, value, 'stb')
            extra += fan.write_word(0x367610, int(scenario == 'queued'))
            extra += dispatch_buffer(0) + dispatch_buffer(1)
            query = scenario not in ('state6', 'state3')
            passed = scenario == 'pass'
            checks = base['checks'] + [(0x367600, 4, int(query)),
                                      (0x367618, 4, int(passed)),
                                      (0x367620, 4, int(passed)),
                                      (0x367640, 4, 4 if passed else 0)]
            if query:
                checks += [(0x367604, 4, 0), (0x367608, 4, 0x3101), (0x36760C, 4, 0x3101)]
            if passed:
                checks += [(0x36761C, 4, 1), (0x367624, 4, 0x87), (0x367628, 4, 0)]
                for i, event in enumerate((0x81, 0x80, 0x101, 0x100)):
                    checks += [(0x367650 + 16*i, 4, 0), (0x367654 + 16*i, 4, event),
                               (0x367658 + 16*i, 4, 0)]
            trace = ['0x20e940', '0x169e1c', '0x16a6e4', '0x7cafe8', '0x20e814']
            if passed:
                trace += ['0x16f920', '0x16e41c', '0x1453fc', '0x1453e4']
            specs.append(dict(name=f'o{order:x}_{scenario}', extra=extra, checks=checks,
                              trace=trace, trace_absent=[] if passed else ['0x1453e4'],
                              success=0xDEAD8100+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True,
             table=True, shared=True, handler2180=True)


if __name__ == '__main__':
    main()
