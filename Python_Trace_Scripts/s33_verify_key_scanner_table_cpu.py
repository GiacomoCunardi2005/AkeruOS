#!/usr/bin/env python3
"""Scanner fino alla tabella CaptureMenu originale; handler finali intercettati."""
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
            checks = base['checks'] + [(cb.POST_COUNT, 4, count if node else 0),
                                       (0x367504, 4, 0)]
            if node:
                for i in range(count):
                    addr = queue.BUF + 16*i
                    checks += cb.post_entry(i, node, expected[addr+4], expected[addr+8])
            specs.append(dict(name=base['name'] + ('_node' if node else '_null'),
                              extra=extra, checks=checks, success=0xDEAD0100+len(specs)))
    # 0x180 is present in the original table and must not hit its default.
    base = queue.build_specs()[0]
    extra = base['extra'] + fan.write_word(0x366EA4, 0x9802AC)
    extra += ' mov r0,0\n mov r1,0x180\n mov r2,0x77\n mov r12,0x169e1c\n jl_s [r12]\n'
    specs.append(dict(name='control_table_match_180', extra=extra,
                      checks=base['checks'] + [(cb.POST_COUNT, 4, 0), (0x367504, 4, 1),
                                               (0x367510, 4, 0x9802AC), (0x367514, 4, 0x180),
                                               (0x367518, 4, 0x77)],
                      success=0xDEAD0100+len(specs)))
    base = next(s for s in queue.build_specs() if s['name'] == 'c14_o16e588_g0')
    extra = base['extra'] + fan.write_word(0x366EA4, 0x9802AC)
    extra += fan.write_word(0x899858, 0x700, 'sth')
    for i in range(2):
        extra += (f' mov r3,{hex(queue.BUF+16*i)}\n ld r0,[r3,0]\n'
                  ' ldh.x r1,[r3,4]\n ld r2,[r3,8]\n'
                  ' mov r12,0x169e1c\n jl_s [r12]\n')
    specs.append(dict(name='control_exclusion_700', extra=extra,
                      checks=base['checks'] + [(cb.POST_COUNT, 4, 1), (0x367504, 4, 0)]
                      + cb.post_entry(0, 0x9802AC, 0x701, 0),
                      success=0xDEAD0100+len(specs)))
    fan.main(specs, scanner=True, queue=True, dispatch=True, window=True, table=True)


if __name__ == '__main__':
    main()
