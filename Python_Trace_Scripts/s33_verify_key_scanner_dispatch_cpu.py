#!/usr/bin/env python3
"""Scanner e coda fino al dispatcher originale; destinazione intercettata."""
import s33_verify_key_callback_16e588_cpu as cb
import s33_verify_key_fanout_callbacks_cpu as fan
import s33_verify_key_scanner_queue_cpu as queue


def main():
    specs = []
    for base in queue.build_specs():
        expected = {addr: value for addr, _, value in base['checks']}
        count = expected[queue.QUEUE]
        for node in (0x9802AC, 0):
            extra = base['extra'] + fan.write_word(0x366EA4, node)
            for i in range(count):
                addr = queue.BUF + 16*i
                extra += (f' mov r3,{hex(addr)}\n ld r0,[r3,0]\n'
                          ' ldh.x r1,[r3,4]\n ld r2,[r3,8]\n'
                          ' mov r12,0x169e1c\n jl_s [r12]\n')
            checks = base['checks'] + [(cb.POST_COUNT, 4, count if node else 0)]
            if node:
                for i in range(count):
                    addr = queue.BUF + 16*i
                    checks += cb.post_entry(i, node, expected[addr+4], expected[addr+8])
            specs.append(dict(name=base['name'] + ('_node' if node else '_null'),
                              extra=extra, checks=checks,
                              success=0xDEADE100+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True)


if __name__ == '__main__':
    main()
