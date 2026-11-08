#!/usr/bin/env python3
"""Setter ISO e consumatore V1.1: confronto e scrittura in RAM sintetica."""
import s33_verify_key_fanout_callbacks_cpu as fan


def main():
    specs = []
    cases = [(6, 125, 1, 0, 21, 2, 8), (7, 140, 1, 0, 21, 2, 42),
             (19, 1600, 1, 0, 21, 2, 42), (19, 1600, 0, 0, 21, 2, 8),
             (19, 1600, 1, 1, 21, 2, 8), (19, 1600, 1, 0, 1, 2, 8),
             (19, 1600, 1, 0, 21, 1, 19), (19, 1600, 1, 0, 21, 4, 42),
             (19, 1600, 1, 0, 21, 0, 8)]
    for index, value, enabled, guard, field, flags, expected in cases:
        correction = -7 if enabled and not guard and value > 125 else 0
        extra = ''.join(fan.write_word(a, v, op) for a, v, op in (
            (0x367604, 0x367720, 'st'), (0x36760c, 0x367730, 'st'),
            (0x367720, enabled, 'stb'), (0x367722, 125, 'sth'),
            (0x367724, 0xfff9, 'sth'), (0x367734, guard, 'stb'),
            (0x367614, 40, 'st'), (0x367704, 12, 'sth'),
            (0x367706, field, 'stb'), (0xc8feb8, 0xabcdef01, 'st'),
            (0xc8fffc, 8, 'sth')))
        extra += (f' mov r0,{index}\n mov r12,0xd03b8\n jl_s [r12]\n'
                  ' mov fp,0xc90000\n mov r0,10\n st r0,[fp,-176]\n'
                  ' mov r0,20\n st r0,[fp,-180]\n mov r0,5\n st r0,[fp,-184]\n'
                  ' mov r13,0x367800\n mov r17,4075\n mov r24,3\n'
                  f' mov r19,{flags}\n mov r16,0\n mov r21,0\n mov r15,0\n'
                  ' mov r26,threshold_return\n mov r12,0xd8d0a\n j_s [r12]\n'
                  'threshold_return:\n')
        total = 78 + correction
        result = 4075 - total
        trace = ['0x0d03b8', '0x17c320', '0x0de78c', '0x0d8d0a', '0x0d8d76',
                 '0x0d8dd0', '0x0d8de2', '0x18c90c']
        if field != 1:
            trace.append('0x18c92e')
        specs.append(dict(name=f'iso{value}_enabled{enabled}_guard{guard}_field{field}_flags{flags}',
                          extra=extra, checks=[(0x367700, 4, correction & 0xffffffff),
                                               (0x367708, 4, result), (0xc8feb8, 4, total),
                                               (0xc8fffc, 2, expected), (0x367610, 4, 1),
                                               (0x37fbf2, 2, value)],
                          trace=trace, trace_counts=[('0x18c90c', 1)],
                          success=0xdead9400+len(specs)))
    fan.main(specs, iso_threshold=True, iso_threshold_math=True,
             iso_threshold_call=True, iso_threshold_apply=True)


if __name__ == '__main__':
    main()
