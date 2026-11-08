#!/usr/bin/env python3
"""Scanner fino alla callback CaptureMenu originale; lookup tabella simulato."""
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
            checks = base['checks'] + [(0x367500, 4, count if node else 0)]
            if node:
                for i in range(count):
                    addr = queue.BUF + 16*i
                    entry = 0x367510 + 32*i
                    checks += [(entry, 4, 0x899858), (entry+4, 4, 0x982384),
                               (entry+8, 4, node), (entry+12, 4, expected[addr+4]),
                               (entry+16, 4, expected[addr+8])]
            specs.append(dict(name=base['name'] + ('_node' if node else '_null'),
                              extra=extra, checks=checks,
                              success=0xDEADF100+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True)


if __name__ == '__main__':
    main()
