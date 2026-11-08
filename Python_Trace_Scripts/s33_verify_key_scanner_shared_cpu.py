#!/usr/bin/env python3
"""Scanner fino alla tabella condivisa originale; handler intercettati."""
import s33_verify_key_callback_16e588_cpu as cb
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue


def dispatch_buffer(i):
    return (f' mov r3,{hex(queue.BUF+16*i)}\n ld r0,[r3,0]\n'
            ' ldh.x r1,[r3,4]\n ld r2,[r3,8]\n'
            ' mov r12,0x169e1c\n jl_s [r12]\n')


def main():
    specs = []
    handlers = {0x700: 0x3675B0, 0x2180: 0x3675B4, 0x4006: 0x3675B8}
    for base in queue.build_specs():
        expected = {addr: value for addr, _, value in base['checks']}
        count = expected[queue.QUEUE]
        for node in (0x9802AC, 0):
            extra = base['extra'] + fan.write_word(0x366EA4, node)
            extra += ''.join(dispatch_buffer(i) for i in range(count))
            hits = [(expected[queue.BUF+16*i+4], expected[queue.BUF+16*i+8])
                    for i in range(count) if node and expected[queue.BUF+16*i+4] in handlers]
            checks = base['checks'] + [(cb.POST_COUNT, 4, len(hits)), (0x367504, 4, 0)]
            checks += [(addr, 4, sum(event == key for event, _ in hits))
                       for key, addr in handlers.items()]
            for i, (event, arg) in enumerate(hits):
                checks += cb.post_entry(i, node, event, arg)
            specs.append(dict(name=base['name'] + ('_node' if node else '_null'),
                              extra=extra, checks=checks, success=0xDEAD1100+len(specs)))
    base = next(s for s in queue.build_specs() if s['name'] == 'c14_o16e588_g0')
    extra = (base['extra'] + fan.write_word(0x366EA4, 0x9802AC)
             + fan.write_word(0x899858, 0x700, 'sth')
             + dispatch_buffer(0) + dispatch_buffer(1))
    specs.append(dict(name='control_exclusion_700', extra=extra,
                      checks=base['checks'] + [(cb.POST_COUNT, 4, 0),
                                               (0x3675B0, 4, 0)],
                      success=0xDEAD1100+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True, table=True, shared=True)


if __name__ == '__main__':
    main()
